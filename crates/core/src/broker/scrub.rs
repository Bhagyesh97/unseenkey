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

impl Scrubber {
    /// Build from the given secrets. Values shorter than [`MIN_LEN`] are skipped.
    pub fn new(secrets: &[Guarded<'_>]) -> Self {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut names = Vec::new();
        for g in secrets {
            let v = g.value.expose();
            if v.len() < MIN_LEN {
                continue;
            }
            for variant in variants(v) {
                patterns.push(variant);
                names.push(g.name.to_string());
            }
        }
        let max_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
        let ac = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&patterns)
                    .expect("patterns are bounded and non-empty"),
            )
        };
        Self { ac, names, max_len }
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
        let Some(ac) = &self.ac else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        for m in ac.find_iter(data) {
            let n = &self.names[m.pattern().as_usize()];
            if !out.iter().any(|o| o == n) {
                out.push(n.clone());
            }
        }
        out
    }

    /// True if any guarded value (or encoding) appears in `data`.
    pub fn contains(&self, data: &[u8]) -> bool {
        self.ac.as_ref().is_some_and(|ac| ac.is_match(data))
    }

    fn marker(&self, pattern: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(MARKER_PREFIX.as_bytes());
        out.extend_from_slice(self.names[pattern].as_bytes());
        out.push(b']');
    }

    /// Replace every occurrence with `[REDACTED:usk:<name>]`. Returns the new
    /// bytes and the number of replacements.
    pub fn scrub(&self, data: &[u8]) -> (Vec<u8>, usize) {
        let Some(ac) = &self.ac else {
            return (data.to_vec(), 0);
        };
        let mut out = Vec::with_capacity(data.len());
        let mut last = 0;
        let mut count = 0;
        for m in ac.find_iter(data) {
            out.extend_from_slice(&data[last..m.start()]);
            self.marker(m.pattern().as_usize(), &mut out);
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
