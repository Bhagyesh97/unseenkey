//! How a secret is placed into an upstream request, per preset [`Auth`] style.

use super::BrokerError;
use crate::crypto::SecretBytes;
use crate::presets::Auth;
use crate::vault::Revealed;
use base64::Engine;
use zeroize::Zeroizing;

/// Modifications to apply to the outgoing request.
#[derive(Debug, Default)]
pub struct Injection {
    /// Headers to set (replacing any existing value).
    pub headers: Vec<(String, Zeroizing<String>)>,
    /// Query parameters to append.
    pub query: Vec<(String, Zeroizing<String>)>,
}

fn text(b: &SecretBytes) -> Result<Zeroizing<String>, BrokerError> {
    core::str::from_utf8(b.expose())
        .map(|s| Zeroizing::new(s.to_string()))
        .map_err(|_| BrokerError::MissingField("value (must be text)".into()))
}

/// Build the injection for `auth` from a revealed secret.
pub fn inject(auth: &Auth, secret: &Revealed) -> Result<Injection, BrokerError> {
    let mut inj = Injection::default();
    match auth {
        Auth::Bearer { also_headers } => {
            let v = text(&secret.value)?;
            inj.headers.push((
                "authorization".into(),
                Zeroizing::new(format!("Bearer {}", *v)),
            ));
            for h in also_headers {
                inj.headers.push((h.to_ascii_lowercase(), v.clone()));
            }
        }
        Auth::Header { name } => {
            inj.headers
                .push((name.to_ascii_lowercase(), text(&secret.value)?));
        }
        Auth::Basic => {
            // username/password fields, falling back to value as password with an empty user.
            let user = secret
                .fields
                .get("username")
                .or_else(|| secret.fields.get("user"))
                .or_else(|| secret.fields.get("account_sid"))
                .map(text)
                .transpose()?
                .unwrap_or_else(|| Zeroizing::new(String::new()));
            let pass = secret
                .fields
                .get("password")
                .map(text)
                .transpose()?
                .unwrap_or(text(&secret.value)?);
            let raw = Zeroizing::new(format!("{}:{}", *user, *pass));
            let enc = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
            inj.headers.push((
                "authorization".into(),
                Zeroizing::new(format!("Basic {enc}")),
            ));
        }
        Auth::Query { param } => {
            inj.query.push((param.clone(), text(&secret.value)?));
        }
        Auth::Template => {}
        Auth::AwsSigv4 => {
            return Err(BrokerError::MissingField(
                "aws_sigv4 adapter arrives in M2.3".into(),
            ));
        }
    }
    Ok(inj)
}

/// Placeholder opener for template injection.
pub const TEMPLATE_OPEN: &[u8] = b"{{usk:";
/// Placeholder closer.
pub const TEMPLATE_CLOSE: &[u8] = b"}}";

/// Names referenced by `{{usk:name}}` placeholders in `data`.
pub fn template_names(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(start) = find(&data[i..], TEMPLATE_OPEN) {
        let name_start = i + start + TEMPLATE_OPEN.len();
        match find(&data[name_start..], TEMPLATE_CLOSE) {
            Some(len) => {
                if let Ok(name) = core::str::from_utf8(&data[name_start..name_start + len]) {
                    if !name.is_empty() && !out.iter().any(|n| n == name) {
                        out.push(name.to_string());
                    }
                }
                i = name_start + len + TEMPLATE_CLOSE.len();
            }
            None => break,
        }
    }
    out
}

/// Replace `{{usk:name}}` placeholders using `resolve`. Unknown names are an error
/// (never silently forwarded, never silently blanked).
pub fn substitute(
    data: &[u8],
    mut resolve: impl FnMut(&str) -> Option<SecretBytes>,
) -> Result<(Zeroizing<Vec<u8>>, usize), BrokerError> {
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    let mut i = 0;
    let mut count = 0;
    while let Some(start) = find(&data[i..], TEMPLATE_OPEN) {
        out.extend_from_slice(&data[i..i + start]);
        let name_start = i + start + TEMPLATE_OPEN.len();
        let Some(len) = find(&data[name_start..], TEMPLATE_CLOSE) else {
            // Unterminated opener: copy literally.
            out.extend_from_slice(&data[i + start..]);
            return Ok((out, count));
        };
        let name = core::str::from_utf8(&data[name_start..name_start + len])
            .map_err(|_| BrokerError::UnknownPlaceholder("<non-utf8>".into()))?;
        let value = resolve(name).ok_or_else(|| BrokerError::UnknownPlaceholder(name.into()))?;
        out.extend_from_slice(value.expose());
        count += 1;
        i = name_start + len + TEMPLATE_CLOSE.len();
    }
    out.extend_from_slice(&data[i..]);
    Ok((out, count))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn revealed(value: &str, fields: &[(&str, &str)]) -> Revealed {
        Revealed {
            value: SecretBytes::from(value),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), SecretBytes::from(*v)))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn bearer_header_query_basic() {
        let r = revealed("sk-abc", &[]);
        let i = inject(
            &Auth::Bearer {
                also_headers: vec!["apikey".into()],
            },
            &r,
        )
        .unwrap();
        assert_eq!(i.headers.len(), 2);
        assert_eq!(*i.headers[0].1, "Bearer sk-abc");
        assert_eq!(i.headers[1].0, "apikey");
        assert_eq!(*i.headers[1].1, "sk-abc");

        let i = inject(
            &Auth::Header {
                name: "X-Api-Key".into(),
            },
            &r,
        )
        .unwrap();
        assert_eq!(i.headers[0].0, "x-api-key");

        let i = inject(
            &Auth::Query {
                param: "key".into(),
            },
            &r,
        )
        .unwrap();
        assert_eq!(i.query[0].0, "key");
        assert_eq!(*i.query[0].1, "sk-abc");

        let r = revealed("tok", &[("username", "AC123"), ("password", "tok")]);
        let i = inject(&Auth::Basic, &r).unwrap();
        let expected = base64::engine::general_purpose::STANDARD.encode("AC123:tok");
        assert_eq!(*i.headers[0].1, format!("Basic {expected}"));

        let i = inject(&Auth::Template, &r).unwrap();
        assert!(i.headers.is_empty() && i.query.is_empty());
        assert!(inject(&Auth::AwsSigv4, &r).is_err());
    }

    #[test]
    fn templates() {
        let data = b"Authorization: Bearer {{usk:openai}}; other={{usk:stripe}}; literal {{usk:";
        assert_eq!(template_names(data), vec!["openai", "stripe"]);
        let (out, n) = substitute(data, |name| match name {
            "openai" => Some(SecretBytes::from("sk-1")),
            "stripe" => Some(SecretBytes::from("sk_live_2")),
            _ => None,
        })
        .unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            String::from_utf8(out.to_vec()).unwrap(),
            "Authorization: Bearer sk-1; other=sk_live_2; literal {{usk:"
        );
        assert_eq!(
            substitute(b"{{usk:missing}}", |_| None).unwrap_err(),
            BrokerError::UnknownPlaceholder("missing".into())
        );
        let (out, n) = substitute(b"no placeholders", |_| None).unwrap();
        assert_eq!((out.as_slice(), n), (b"no placeholders".as_slice(), 0));
    }
}
