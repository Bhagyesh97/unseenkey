//! Importers. `.env` files first; password-manager exports come later in M1.1.

use crate::crypto::SecretBytes;
use crate::providers::{self, Detection};
use alloc::string::String;
use alloc::vec::Vec;

/// One `KEY=value` line from a `.env` file.
#[derive(Debug)]
pub struct DotenvEntry {
    /// Variable name.
    pub key: String,
    /// Value with quotes and escapes resolved.
    pub value: SecretBytes,
    /// 1-based line number.
    pub line: usize,
    /// What the value looks like, if recognisable.
    pub detection: Option<Detection>,
    /// True if either the value shape or the key name suggests a secret.
    pub looks_secret: bool,
}

/// A key in two parts is often two variables (`TWILIO_ACCOUNT_SID` and
/// `TWILIO_AUTH_TOKEN`), and must become one secret. Returns the username for
/// each secret variable, and the variables that are those usernames.
pub fn paired_usernames(
    entries: &[DotenvEntry],
) -> (
    alloc::collections::BTreeMap<String, String>,
    alloc::collections::BTreeSet<String>,
) {
    let mut usernames = alloc::collections::BTreeMap::new();
    let mut joined = alloc::collections::BTreeSet::new();
    for e in entries {
        let pair = crate::presets::guess_by_name(&e.key)
            .filter(|p| p.pair_labels().is_some() && p.env.get("api_key") == Some(&e.key));
        let Some(var) = pair.and_then(|p| p.env.get("username")) else {
            continue;
        };
        let other = entries.iter().find(|o| o.key == *var);
        if let Some(user) = other.and_then(|o| core::str::from_utf8(o.value.expose()).ok()) {
            usernames.insert(e.key.clone(), user.trim().into());
            joined.insert(var.clone());
        }
    }
    (usernames, joined)
}

/// What frameworks put before a variable the browser may read.
const PUBLIC_PREFIXES: [&str; 5] = [
    "NEXT_PUBLIC_",
    "VITE_",
    "PUBLIC_",
    "REACT_APP_",
    "EXPO_PUBLIC_",
];

/// The owner's own host, for keys of a provider with a host per customer, from
/// the base URL variable beside them (`SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_URL`).
/// A URL outside the provider's hosts says nothing: it may already be the broker.
/// `PROD_SUPABASE_KEY` takes `PROD_SUPABASE_URL`, not `STAGING_SUPABASE_URL`; the
/// prefixes frameworks add to what the browser may read do not count.
pub fn own_hosts(entries: &[DotenvEntry]) -> alloc::collections::BTreeMap<String, String> {
    let mut hosts = alloc::collections::BTreeMap::new();
    for e in entries {
        let Some(p) = crate::presets::guess_by_name(&e.key).filter(|p| p.tenant.is_some()) else {
            continue;
        };
        let Some(var) = p.env.get("base_url") else {
            continue;
        };
        // The variable with the longest matching prefix wins, and only among those
        // that hold a usable host: `PROD_SUPABASE_URL` over a `SUPABASE_URL` above
        // it, and a real URL over one already pointing at the broker.
        let host = entries
            .iter()
            .rev()
            .filter_map(|o| {
                let prefix = o.key.strip_suffix(var.as_str())?;
                let own = PUBLIC_PREFIXES
                    .iter()
                    .find_map(|f| prefix.strip_prefix(f))
                    .unwrap_or(prefix);
                if !own.is_empty() && !e.key.starts_with(own) {
                    return None;
                }
                let url = core::str::from_utf8(o.value.expose()).ok()?;
                let host = crate::broker::Upstream::parse(url.trim()).ok()?.host;
                crate::policy::eval::host_allowed(&p.upstreams, &host).then_some((own.len(), host))
            })
            .max_by_key(|(own, _)| *own)
            .map(|(_, host)| host);
        if let Some(host) = host {
            hosts.insert(e.key.clone(), host);
        }
    }
    hosts
}

/// Parse `.env` text. Handles `export KEY=`, single/double quotes, `\n` and
/// `\"` escapes inside double quotes, `#` comments, and blank lines. Unquoted
/// values stop at ` #`.
pub fn parse_dotenv(text: &str) -> Vec<DotenvEntry> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some(eq) = line.find('=') else { continue };
        let key = line[..eq].trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        {
            continue;
        }
        let rest = line[eq + 1..].trim_start();
        let value = unquote(rest);
        if value.is_empty() {
            continue;
        }
        let detection = providers::detect(value.as_bytes());
        let looks_secret =
            detection.is_some() || (providers::key_name_suggests_secret(key) && value.len() >= 8);
        out.push(DotenvEntry {
            key: key.into(),
            value: SecretBytes::new(value.into_bytes()),
            line: i + 1,
            detection,
            looks_secret,
        });
    }
    out
}

fn unquote(rest: &str) -> String {
    if let Some(inner) = rest.strip_prefix('"') {
        let mut s = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('"') => s.push('"'),
                    Some('\\') => s.push('\\'),
                    Some(o) => {
                        s.push('\\');
                        s.push(o);
                    }
                    None => s.push('\\'),
                },
                '"' => break,
                o => s.push(o),
            }
        }
        s
    } else if let Some(inner) = rest.strip_prefix('\'') {
        inner.split('\'').next().unwrap_or("").into()
    } else {
        let v = match rest.find(" #") {
            Some(i) => &rest[..i],
            None => rest,
        };
        v.trim_end().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_finds_its_own_host_beside_it() {
        let hosts = own_hosts(&parse_dotenv(
            "SUPABASE_KEY=sb_secret_abc\nNEXT_PUBLIC_SUPABASE_URL=https://abcd1234.supabase.co/\n",
        ));
        assert_eq!(
            hosts.get("SUPABASE_KEY").map(String::as_str),
            Some("abcd1234.supabase.co")
        );
        // The URL beside it, not one for something else.
        let text = "DEMO_SUPABASE_URL=https://other.supabase.co\nSUPABASE_KEY=sb_secret_abc\n";
        assert_eq!(own_hosts(&parse_dotenv(text)).get("SUPABASE_KEY"), None);
        let hosts = own_hosts(&parse_dotenv(
            "STAGING_SUPABASE_URL=https://staging.supabase.co\nPROD_SUPABASE_URL=https://prod.supabase.co\nPROD_SUPABASE_KEY=sb_secret_abc\n",
        ));
        assert_eq!(
            hosts.get("PROD_SUPABASE_KEY").map(String::as_str),
            Some("prod.supabase.co")
        );
        // Already pointing at the broker, or somewhere else: says nothing.
        // The closest name wins wherever it is in the file, and a URL already
        // pointing at the broker does not hide a real one after it.
        let text = "SUPABASE_URL=https://dev.supabase.co\nPROD_SUPABASE_URL=https://prod.supabase.co\nPROD_SUPABASE_KEY=sb_secret_abc\n";
        let hosts = own_hosts(&parse_dotenv(text));
        assert_eq!(hosts["PROD_SUPABASE_KEY"], "prod.supabase.co");
        let text = "SUPABASE_URL=http://127.0.0.1:8080/p/supabase\nNEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co\nSUPABASE_KEY=sb_secret_abc\n";
        let hosts = own_hosts(&parse_dotenv(text));
        assert_eq!(hosts["SUPABASE_KEY"], "abc.supabase.co");
        for url in ["http://127.0.0.1:8080/p/supabase", "https://evil.example"] {
            let text = alloc::format!("SUPABASE_KEY=sb_secret_abc\nSUPABASE_URL={url}\n");
            assert!(own_hosts(&parse_dotenv(&text)).is_empty(), "{url}");
        }
    }

    #[test]
    fn parses_common_forms() {
        let text = r#"
# comment
PORT=3000
export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF
DB_PASSWORD="p@ss w0rd\"x"
SINGLE='keep # this'
UNQUOTED=value # trailing comment
EMPTY=
BAD KEY=1
"#;
        let e = parse_dotenv(text);
        let keys: Vec<&str> = e.iter().map(|x| x.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "PORT",
                "OPENAI_API_KEY",
                "DB_PASSWORD",
                "SINGLE",
                "UNQUOTED"
            ]
        );
        assert!(!e[0].looks_secret);
        assert_eq!(e[1].detection.unwrap().provider, "openai");
        assert!(e[1].looks_secret);
        assert_eq!(e[2].value.expose(), b"p@ss w0rd\"x");
        assert!(e[2].looks_secret);
        assert_eq!(e[3].value.expose(), b"keep # this");
        assert_eq!(e[4].value.expose(), b"value");
        assert_eq!(e[1].line, 4);
    }
}
