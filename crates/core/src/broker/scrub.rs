//! Secret detection and redaction over bytes and byte streams.
//!
//! Used for both directions: the egress guard asks "does this outgoing request
//! contain any *other* stored secret?", and the response scrubber replaces any
//! stored value that an upstream echoes back. Values shorter than
//! [`MIN_LEN`] are not guarded (too many false positives); the UI flags them.

use crate::crypto::SecretBytes;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::Engine;

/// Shortest value we will search for.
pub const MIN_LEN: usize = 12;

/// A multi-line value longer than this (a PEM key) is guarded line by line. A
/// stream can only pass on what cannot be the start of a match, so one long
/// pattern would hold back the start of every streamed reply, for every secret.
const LONG_VALUE: usize = 256;

/// Shortest line of such a value worth guarding. A PEM key's lines are 64 long,
/// and a shorter line (`apiVersion: v1` in a kubeconfig) may be anywhere.
const LONG_VALUE_LINE: usize = 32;

/// Redaction marker; the name is appended so owners can tell what leaked.
pub const MARKER_PREFIX: &str = "[REDACTED:usk:";

/// A compiled set of secret values and their common encodings.
#[derive(Debug, Clone)]
pub struct Scrubber {
    ac: Option<AhoCorasick>,
    /// Pattern index → owning secret name.
    names: Vec<String>,
    /// Longest pattern, for stream overlap.
    max_len: usize,
    /// Long values whole, in all their encodings, for data held in one piece: an
    /// outgoing request, and the held-back end of a reply. Not for streams,
    /// which is why they are apart. Base64 of a whole PEM key shares no text
    /// with base64 of its lines.
    whole: Option<AhoCorasick>,
    /// Pattern index in `whole` → owning secret name.
    whole_names: Vec<String>,
}

/// One secret to guard.
#[derive(Debug)]
pub struct Guarded<'a> {
    /// Secret name, shown in the redaction marker.
    pub name: &'a str,
    /// The value.
    pub value: &'a SecretBytes,
}

fn variants(value: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![value.to_vec()];
    let std = base64::engine::general_purpose::STANDARD.encode(value);
    let nopad = base64::engine::general_purpose::STANDARD_NO_PAD.encode(value);
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    for v in [std, nopad, url] {
        if v.len() >= MIN_LEN && !out.iter().any(|o| o == v.as_bytes()) {
            out.push(v.into_bytes());
        }
    }
    if let Ok(s) = core::str::from_utf8(value) {
        let enc = percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
        if enc.as_bytes() != value && enc.len() >= MIN_LEN {
            out.push(enc.into_bytes());
        }
        // A PEM key inside a JSON string has its line breaks escaped, and its
        // slashes perhaps.
        if s.contains('\n') {
            let lines = s
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\r', "\\r")
                .replace('\n', "\\n");
            for v in [lines.replace('/', "\\/"), lines] {
                if !out.iter().any(|o| *o == v.as_bytes()) {
                    out.push(v.into_bytes());
                }
            }
        }
        // JSON string escaping of the characters that commonly appear in keys.
        let json = s
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('/', "\\/");
        if json.as_bytes() != value && !out.iter().any(|o| *o == json.as_bytes()) {
            out.push(json.into_bytes());
        }
    }
    out
}

/// A line of a long value worth guarding on its own: 32 bytes or more, or a
/// shorter one that reads like a code (`a8f3-k29d-77qx-p0m1`: letters and digits,
/// no space, no `name=`). Lines like `apiVersion: v1` or `region=us-east-1`
/// turn up in ordinary traffic and would block it.
fn worth_guarding(line: &str) -> bool {
    if line.starts_with("-----") {
        return false;
    }
    line.len() >= LONG_VALUE_LINE
        || (line.len() >= MIN_LEN
            && !line.contains(|c: char| c.is_whitespace() || c == '=' || c == ':')
            && line.bytes().any(|b| b.is_ascii_digit())
            && line.bytes().any(|b| b.is_ascii_alphabetic()))
}

/// In `token: abc…` or `API_KEY=abc…` the secret is what follows the name, and
/// a reply may hold it alone. Only when the name says it is a secret: the URL
/// after `server: ` in a kubeconfig is not, and traffic names it.
fn secret_tail(line: &str) -> Option<&str> {
    let (name, tail) = line.rsplit_once(": ").or_else(|| line.split_once('='))?;
    let name = name.to_ascii_lowercase();
    let secret = !name.contains("public")
        && [
            "token",
            "secret",
            "key",
            "password",
            "passwd",
            "pwd",
            "credential",
            "authorization",
            "bearer",
            "private",
        ]
        .iter()
        .any(|w| name.contains(w));
    let tail = tail.trim().trim_matches(['"', '\'']);
    (secret && tail.len() >= MIN_LEN).then_some(tail)
}

/// What of one line of a long value to guard: the line, if worth it, and the
/// secret after its name, if it has one.
fn guarded_parts(line: &str) -> impl Iterator<Item = &str> {
    worth_guarding(line)
        .then_some(line)
        .into_iter()
        .chain(secret_tail(line))
}

/// Longest piece of a line guarded as one pattern, a multiple of 3 so base64
/// of the line is base64 of its pieces. A longer line (a kubeconfig's 3 KB
/// `client-key-data`) is cut, or its length would be held back in every stream.
const PIECE: usize = 48;

/// `part` whole if short, else in pieces of [`PIECE`] bytes, the last one
/// ending where the line ends. Any leak of the line holds every piece. A
/// piece of base64 that starts with `-----` (`LS0tLS1…`, a base64 PEM's
/// `-----BEGIN … KEY-----` opening) is the same in every such key, so it is
/// left out; the pieces after it are the key's own.
fn pieces(part: &str) -> Vec<&[u8]> {
    let b = part.as_bytes();
    if b.len() <= 2 * PIECE {
        return vec![b];
    }
    let mut out: Vec<&[u8]> = b.chunks(PIECE).filter(|c| c.len() == PIECE).collect();
    if b.len() % PIECE != 0 {
        out.push(&b[b.len() - PIECE..]);
    }
    out.retain(|p| !p.starts_with(b"LS0tLS1"));
    out
}

impl Scrubber {
    /// Build from the given secrets. Values shorter than [`MIN_LEN`] are skipped.
    pub fn new(secrets: &[Guarded<'_>]) -> Self {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut names = Vec::new();
        let mut whole_patterns: Vec<Vec<u8>> = Vec::new();
        let mut whole_names = Vec::new();
        for g in secrets {
            let v = g.value.expose();
            if v.len() < MIN_LEN {
                continue;
            }
            let parts = core::str::from_utf8(v)
                .ok()
                .filter(|s| s.len() > LONG_VALUE && s.contains('\n'))
                .map(|text| {
                    text.lines()
                        .map(str::trim)
                        .flat_map(guarded_parts)
                        .collect::<Vec<_>>()
                })
                .filter(|parts| !parts.is_empty());
            if let Some(parts) = parts {
                for piece in parts.into_iter().flat_map(pieces) {
                    for variant in variants(piece) {
                        patterns.push(variant);
                        names.push(g.name.to_string());
                    }
                }
                for variant in variants(v) {
                    whole_patterns.push(variant);
                    whole_names.push(g.name.to_string());
                }
                continue;
            }
            for variant in variants(v) {
                patterns.push(variant);
                names.push(g.name.to_string());
            }
        }
        let max_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let build = |patterns: &[Vec<u8>]| {
            (!patterns.is_empty()).then(|| {
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(patterns)
                    .expect("patterns are bounded and non-empty")
            })
        };
        Self {
            ac: build(&patterns),
            names,
            max_len,
            whole: build(&whole_patterns),
            whole_names,
        }
    }

    /// An empty scrubber that matches nothing.
    pub fn empty() -> Self {
        Self::new(&[])
    }

    /// Length of the longest pattern.
    pub fn max_len(&self) -> usize {
        self.max_len
    }

    /// Names of secrets found in `data`, deduplicated, in order of first hit.
    pub fn find(&self, data: &[u8]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut note = |n: &String| {
            if !out.iter().any(|o| o == n) {
                out.push(n.clone());
            }
        };
        if let Some(ac) = &self.ac {
            for m in ac.find_iter(data) {
                note(&self.names[m.pattern().as_usize()]);
            }
        }
        if let Some(whole) = &self.whole {
            for m in whole.find_iter(data) {
                note(&self.whole_names[m.pattern().as_usize()]);
            }
        }
        out
    }

    /// True if any guarded value (or encoding) appears in `data`.
    pub fn contains(&self, data: &[u8]) -> bool {
        self.ac.as_ref().is_some_and(|ac| ac.is_match(data))
            || self.whole.as_ref().is_some_and(|ac| ac.is_match(data))
    }

    fn marker(&self, pattern: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(MARKER_PREFIX.as_bytes());
        out.extend_from_slice(self.names[pattern].as_bytes());
        out.push(b']');
    }

    /// Replace every occurrence with `[REDACTED:usk:<name>]`. Returns the new
    /// bytes and the number of replacements.
    pub fn scrub(&self, data: &[u8]) -> (Vec<u8>, usize) {
        let (first, mut count) = match &self.whole {
            Some(whole) => Self::replace(whole, &self.whole_names, data),
            None => (data.to_vec(), 0),
        };
        let Some(ac) = &self.ac else {
            return (first, count);
        };
        let (out, more) = Self::replace(ac, &self.names, &first);
        count += more;
        (out, count)
    }

    fn replace(ac: &AhoCorasick, names: &[String], data: &[u8]) -> (Vec<u8>, usize) {
        let mut out = Vec::with_capacity(data.len());
        let mut last = 0;
        let mut count = 0;
        for m in ac.find_iter(data) {
            out.extend_from_slice(&data[last..m.start()]);
            out.extend_from_slice(MARKER_PREFIX.as_bytes());
            out.extend_from_slice(names[m.pattern().as_usize()].as_bytes());
            out.push(b']');
            last = m.end();
            count += 1;
        }
        out.extend_from_slice(&data[last..]);
        (out, count)
    }
}

/// Scrubs a byte stream chunk by chunk. Matches that lie entirely inside the
/// buffered data are replaced immediately; the last `max_len − 1` unmatched
/// bytes are held back until more data (or the end) arrives, so a value split
/// across chunks is still caught.
#[derive(Debug)]
pub struct StreamScrubber {
    scrubber: Scrubber,
    carry: Vec<u8>,
    /// Replacements so far.
    pub replaced: usize,
}

impl StreamScrubber {
    /// Wrap a scrubber.
    pub fn new(scrubber: Scrubber) -> Self {
        Self {
            scrubber,
            carry: Vec::new(),
            replaced: 0,
        }
    }

    /// Feed a chunk; returns bytes safe to emit now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let Some(ac) = &self.scrubber.ac else {
            return chunk.to_vec();
        };
        self.carry.extend_from_slice(chunk);
        let hold = self.scrubber.max_len.saturating_sub(1);
        if self.carry.len() <= hold {
            return Vec::new();
        }
        let cut = self.carry.len() - hold;
        let mut out = Vec::with_capacity(cut);
        let mut last = 0;
        for m in ac.find_iter(&self.carry) {
            if m.start() >= cut {
                // Starts inside the held-back tail: might continue into the next chunk.
                break;
            }
            out.extend_from_slice(&self.carry[last..m.start()]);
            self.scrubber.marker(m.pattern().as_usize(), &mut out);
            self.replaced += 1;
            last = m.end();
        }
        if last < cut {
            out.extend_from_slice(&self.carry[last..cut]);
            last = cut;
        }
        self.carry.drain(..last);
        out
    }

    /// Flush the held-back tail at end of stream.
    pub fn finish(&mut self) -> Vec<u8> {
        let (out, n) = self.scrubber.scrub(&self.carry);
        self.replaced += n;
        self.carry.clear();
        out
    }
}

#[cfg(test)]
mod pem_tests {
    use super::*;

    #[test]
    fn a_long_value_is_guarded_whole_where_it_can_be_and_its_ordinary_lines_are_not() {
        use base64::Engine;
        let line = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj";
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}-----END PRIVATE KEY-----\n",
            format!("{line}\n").repeat(8)
        );
        let value = SecretBytes::from(pem.as_str());
        let s = Scrubber::new(&[Guarded {
            name: "key",
            value: &value,
        }]);
        // Base64 of the whole file shares no text with base64 of its lines.
        let b64 = base64::engine::general_purpose::STANDARD.encode(&pem);
        assert_eq!(s.find(b64.as_bytes()), ["key"]);
        assert!(s.contains(b64.as_bytes()));
        let (clean, n) = s.scrub(format!("x{b64}y").as_bytes());
        assert!(n >= 1 && !String::from_utf8_lossy(&clean).contains(&b64));
        // Streams stay light: only the lines count towards what is held back.
        assert!(s.max_len() < 200, "{}", s.max_len());

        // Nothing but short lines: guarded whole, not left out.
        let short = "abcdefghi\n".repeat(30);
        let value = SecretBytes::from(short.as_str());
        let s = Scrubber::new(&[Guarded {
            name: "short",
            value: &value,
        }]);
        assert_eq!(s.find(short.as_bytes()), ["short"]);

        // A config's ordinary lines are not secrets, and traffic holding them is fine.
        let config = format!(
            "apiVersion: v1\nkind: Config\nclusters: []\n{}token: {line}\n",
            "users: []\n".repeat(30)
        );
        let value = SecretBytes::from(config.as_str());
        let s = Scrubber::new(&[Guarded {
            name: "kube",
            value: &value,
        }]);
        assert!(s.find(b"apiVersion: v1").is_empty());
        assert_eq!(s.find(line.as_bytes()), ["kube"]);
    }

    #[test]
    fn codes_secret_names_and_very_long_lines() {
        use base64::Engine;
        let guard = |name: &'static str, text: &str| {
            let value = SecretBytes::from(text);
            Scrubber::new(&[Guarded {
                name,
                value: &value,
            }])
        };
        // Recovery codes: short lines, each one a secret.
        let codes: Vec<String> = (0..20)
            .map(|i| format!("k29d-77qx-{i:02}m1-a8f3"))
            .collect();
        let s = guard("codes", &codes.join("\n"));
        assert_eq!(s.find(codes[3].as_bytes()), ["codes"]);
        assert!(s.max_len() < 100, "holds back {}", s.max_len());

        // The value after `token: ` is a secret; the URL after `server: ` is not.
        let token = "q7Wm2Lx9Vb4Nc8Rt1Yz6Hd3Kf5Pj0Gs";
        let server = "https://abc123.gr7.us-east-1.eks.amazonaws.com";
        let config = format!(
            "apiVersion: v1\nkind: Config\n{}    server: {server}\n    token: {token}\n",
            "- name: prod\n".repeat(20)
        );
        let s = guard("kube", &config);
        assert_eq!(s.find(token.as_bytes()), ["kube"]);
        assert!(s.find(server.as_bytes()).is_empty());
        assert!(s.find(b"region=us-east-1").is_empty());

        // A 3 KB line is guarded in pieces, so streams are not held back by it,
        // and any stretch of it is still hidden, in one piece or streamed.
        let mut x: u32 = 7;
        let data: Vec<u8> = (0..2250)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (x >> 16) as u8
            })
            .collect();
        let blob = base64::engine::general_purpose::STANDARD.encode(&data);
        let s = guard(
            "long",
            &format!("apiVersion: v1\nclient-key-data: {blob}\n"),
        );
        assert!(s.max_len() < 300, "holds back {}", s.max_len());
        let stretch = &blob[1000..1100];
        let reply = format!("{{\"echo\":\"{stretch}\"}}");
        let out = String::from_utf8(s.scrub(reply.as_bytes()).0).unwrap();
        assert!(!out.contains(&stretch[40..90]), "{out}");
        let mut st = StreamScrubber::new(s.clone());
        let mut streamed = Vec::new();
        for c in blob.as_bytes().chunks(37) {
            streamed.extend(st.push(c));
        }
        streamed.extend(st.finish());
        let streamed = String::from_utf8(streamed).unwrap();
        assert!(!streamed.contains(&blob[200..260]), "{streamed:.200}");
    }

    #[test]
    fn a_long_key_is_hidden_without_holding_back_streams() {
        let body: Vec<String> = (0..30)
            .map(|i| format!("MIIE/abc+def{i:02}ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012"))
            .collect();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            body.join("\n")
        );
        let value = SecretBytes::from(pem.as_str());
        let s = Scrubber::new(&[Guarded {
            name: "k",
            value: &value,
        }]);
        assert!(s.max_len() < 300, "holds back {} bytes", s.max_len());
        for form in [
            pem.clone(),
            pem.replace('\n', "\\n"),
            pem.replace('\n', "\\n").replace('/', "\\/"),
            pem.replace('\n', "\r\n"),
            body.concat(),
            format!(
                "{{\"private_key\":{}}}",
                serde_json::to_string(&pem).unwrap()
            ),
        ] {
            let out = String::from_utf8(s.scrub(form.as_bytes()).0).unwrap();
            assert!(
                !out.contains("ghijklmnopqrstuvwxyz"),
                "survived in {form:.60}: {out:.120}"
            );
        }
    }

    #[test]
    fn a_pem_key_is_guarded_as_a_json_string_too() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIE/abc+def\nghij\n-----END PRIVATE KEY-----\n";
        let found = variants(pem.as_bytes());
        for form in [
            pem.to_string(),
            pem.replace('\n', "\\n"),
            pem.replace('\n', "\\n").replace('/', "\\/"),
        ] {
            assert!(found.iter().any(|v| v == form.as_bytes()), "{form}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scrubber(pairs: &[(&str, &str)]) -> (Scrubber, Vec<SecretBytes>) {
        let values: Vec<SecretBytes> = pairs.iter().map(|(_, v)| SecretBytes::from(*v)).collect();
        let guarded: Vec<Guarded<'_>> = pairs
            .iter()
            .zip(&values)
            .map(|((n, _), v)| Guarded { name: n, value: v })
            .collect();
        (Scrubber::new(&guarded), values)
    }

    #[test]
    fn finds_raw_and_encoded() {
        let (s, _v) = scrubber(&[("openai", "sk-proj-abcdefghijklmnop"), ("short", "abc")]);
        assert!(s.contains(b"key=sk-proj-abcdefghijklmnop&x"));
        assert!(!s.contains(b"nothing here"));
        assert!(!s.contains(b"abc"), "short values are not guarded");
        let b64 = base64::engine::general_purpose::STANDARD.encode("sk-proj-abcdefghijklmnop");
        assert!(s.contains(b64.as_bytes()));
        assert_eq!(s.find(b"sk-proj-abcdefghijklmnop"), vec!["openai"]);
        let (s2, _v2) = scrubber(&[("slash", "abc/def/ghi/jkl")]);
        assert!(
            s2.contains(b"\"abc\\/def\\/ghi\\/jkl\""),
            "json-escaped form"
        );
        assert!(s2.contains(b"abc%2Fdef%2Fghi%2Fjkl"), "url-encoded form");
    }

    #[test]
    fn scrubs_with_names() {
        let (s, _v) = scrubber(&[("stripe", "sk_live_51Habcdefghijklmnop")]);
        let (out, n) = s.scrub(
            b"{\"key\":\"sk_live_51Habcdefghijklmnop\",\"again\":\"sk_live_51Habcdefghijklmnop\"}",
        );
        assert_eq!(n, 2);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\"key\":\"[REDACTED:usk:stripe]\",\"again\":\"[REDACTED:usk:stripe]\"}"
        );
    }

    #[test]
    fn stream_catches_split_values() {
        let secret = "sk_live_51Habcdefghijklmnop";
        let (s, _v) = scrubber(&[("stripe", secret), ("other", "xoxb-1234567890-abcdefgh")]);
        let text = format!("hello {secret} world xoxb-1234567890-abcdefgh and {secret}!");
        let expected = s.scrub(text.as_bytes()).0;
        for chunk in 1..=text.len() {
            let mut st = StreamScrubber::new(s.clone());
            let mut out = Vec::new();
            for c in text.as_bytes().chunks(chunk) {
                out.extend(st.push(c));
            }
            out.extend(st.finish());
            assert_eq!(
                String::from_utf8_lossy(&out),
                String::from_utf8_lossy(&expected),
                "chunk size {chunk}"
            );
            assert_eq!(st.replaced, 3, "chunk size {chunk}");
        }
    }

    #[test]
    fn stream_without_secrets_is_identity() {
        let (s, _v) = scrubber(&[("k", "sk_live_51Habcdefghijklmnop")]);
        let data = b"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n".repeat(50);
        let mut st = StreamScrubber::new(s);
        let mut out = Vec::new();
        for c in data.chunks(7) {
            out.extend(st.push(c));
        }
        out.extend(st.finish());
        assert_eq!(out, data);
        assert_eq!(st.replaced, 0);
    }

    #[test]
    fn empty_scrubber_is_passthrough() {
        let s = Scrubber::empty();
        assert!(!s.contains(b"anything"));
        assert_eq!(s.scrub(b"abc"), (b"abc".to_vec(), 0));
        let mut st = StreamScrubber::new(s);
        assert_eq!(st.push(b"xyz"), b"xyz".to_vec());
        assert!(st.finish().is_empty());
    }
}
