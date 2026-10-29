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
        Auth::Scheme { scheme } => {
            let v = text(&secret.value)?;
            inj.headers.push((
                "authorization".into(),
                Zeroizing::new(format!("{scheme} {}", *v)),
            ));
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
        // Template substitution and SigV4 signing need the whole request; the
        // pipeline does them (see `substitute` and `sigv4::sign`).
        Auth::Template | Auth::AwsSigv4 => {}
    }
    Ok(inj)
}

/// AWS credentials taken out of a revealed secret.
pub struct AwsCredentials {
    /// `AKIA…` or `ASIA…`.
    pub access_key_id: Zeroizing<String>,
    /// The secret access key.
    pub secret_access_key: SecretBytes,
    /// Session token of temporary credentials.
    pub session_token: Option<Zeroizing<String>>,
}

/// Read AWS credentials from a secret: fields `access_key_id`,
/// `secret_access_key` (or the secret's value) and optional `session_token`.
pub fn aws_credentials(secret: &Revealed) -> Result<AwsCredentials, BrokerError> {
    let field = |name: &str| secret.fields.get(name).filter(|v| !v.is_empty());
    let access_key_id = text(
        field("access_key_id").ok_or_else(|| BrokerError::MissingField("access_key_id".into()))?,
    )?;
    let secret_access_key = match field("secret_access_key") {
        Some(v) => v.clone(),
        None if !secret.value.is_empty() => secret.value.clone(),
        None => return Err(BrokerError::MissingField("secret_access_key".into())),
    };
    if secret_access_key.expose() == access_key_id.as_bytes() {
        return Err(BrokerError::MissingField("secret_access_key".into()));
    }
    let session_token = field("session_token").map(text).transpose()?;
    Ok(AwsCredentials {
        access_key_id,
        secret_access_key,
        session_token,
    })
}

/// An OAuth2 client taken out of a revealed secret: what it takes to trade
/// the refresh token for an access token.
pub struct Oauth2Client {
    /// Client id.
    pub client_id: Zeroizing<String>,
    /// Client secret; absent for public clients.
    pub client_secret: Option<Zeroizing<String>>,
    /// The long-lived refresh token.
    pub refresh_token: Zeroizing<String>,
    /// The provider's token endpoint.
    pub token_url: String,
    /// Scope to ask for, when the provider wants it repeated.
    pub scope: Option<String>,
    /// Authenticate the client with HTTP Basic instead of form fields.
    pub basic_auth: bool,
}

/// Read an OAuth2 client from a secret: the refresh token is the value (or a
/// field `refresh_token`), with fields `client_id`, `token_url` and optional
/// `client_secret`, `scope`, `token_auth` (`basic` or `post`).
pub fn oauth2_client(secret: &Revealed) -> Result<Oauth2Client, BrokerError> {
    let field = |name: &str| secret.fields.get(name).filter(|v| !v.is_empty());
    let need = |name: &str| field(name).ok_or_else(|| BrokerError::MissingField(name.into()));
    let refresh_token = match field("refresh_token") {
        Some(v) => text(v)?,
        None if !secret.value.is_empty() => text(&secret.value)?,
        None => return Err(BrokerError::MissingField("refresh_token".into())),
    };
    Ok(Oauth2Client {
        client_id: text(need("client_id")?)?,
        client_secret: field("client_secret").map(text).transpose()?,
        refresh_token,
        token_url: text(need("token_url")?)?.trim().to_string(),
        scope: field("scope")
            .map(text)
            .transpose()?
            .map(|s| s.trim().to_string()),
        basic_auth: field("token_auth")
            .map(text)
            .transpose()?
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("basic")),
    })
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
        let i = inject(&Auth::AwsSigv4, &r).unwrap();
        assert!(i.headers.is_empty() && i.query.is_empty());
    }

    #[test]
    fn aws_credentials_from_a_secret() {
        // Secret access key as the value, the rest in fields.
        let r = revealed(
            "wJalrXUtnFEMI/K7MDENG",
            &[("access_key_id", "AKIAIOSFODNN7EXAMPLE")],
        );
        let c = aws_credentials(&r).unwrap();
        assert_eq!(*c.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(c.secret_access_key.expose(), b"wJalrXUtnFEMI/K7MDENG");
        assert!(c.session_token.is_none());
        // Everything in fields, with a session token; the field wins over the value.
        let r = revealed(
            "ignored",
            &[
                ("access_key_id", "ASIAEXAMPLE"),
                ("secret_access_key", "s3cr3t"),
                ("session_token", "tok"),
            ],
        );
        let c = aws_credentials(&r).unwrap();
        assert_eq!(c.secret_access_key.expose(), b"s3cr3t");
        assert_eq!(c.session_token.as_deref().map(String::as_str), Some("tok"));
        // Incomplete secrets are refused, naming what is missing.
        assert_eq!(
            aws_credentials(&revealed("x", &[])).err(),
            Some(BrokerError::MissingField("access_key_id".into()))
        );
        assert_eq!(
            aws_credentials(&revealed(
                "AKIAIOSFODNN7EXAMPLE",
                &[("access_key_id", "AKIAIOSFODNN7EXAMPLE")]
            ))
            .err(),
            Some(BrokerError::MissingField("secret_access_key".into()))
        );
    }

    #[test]
    fn oauth2_client_from_a_secret() {
        let r = revealed(
            "rt-1",
            &[
                ("client_id", "cid"),
                ("client_secret", "cs"),
                ("token_url", " https://auth.example/token "),
                ("token_auth", "Basic"),
            ],
        );
        let c = oauth2_client(&r).unwrap();
        assert_eq!(
            (c.client_id.as_str(), c.refresh_token.as_str()),
            ("cid", "rt-1")
        );
        assert_eq!(c.client_secret.as_deref().map(String::as_str), Some("cs"));
        assert_eq!(c.token_url, "https://auth.example/token");
        assert!(c.basic_auth && c.scope.is_none());
        // A refresh_token field wins over the value; public clients have no secret.
        let r = revealed(
            "x",
            &[
                ("client_id", "cid"),
                ("refresh_token", "rt-2"),
                ("token_url", "https://a/t"),
                ("scope", "a b"),
            ],
        );
        let c = oauth2_client(&r).unwrap();
        assert_eq!(c.refresh_token.as_str(), "rt-2");
        assert!(c.client_secret.is_none() && !c.basic_auth);
        assert_eq!(c.scope.as_deref(), Some("a b"));
        for (fields, missing) in [
            (&[("token_url", "https://a/t")][..], "client_id"),
            (&[("client_id", "cid")][..], "token_url"),
        ] {
            assert_eq!(
                oauth2_client(&revealed("rt", fields)).err(),
                Some(BrokerError::MissingField(missing.into()))
            );
        }
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
