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
