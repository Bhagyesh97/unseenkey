//! Provider detection from a pasted value, and provider defaults.
//!
//! Detection is prefix and shape based, not a regex engine: it runs on every
//! pasted value and every `.env` line, so it must be cheap and predictable.
//! Broker presets (auth style, policies) live with the broker in M1.4; this
//! module only answers "what is this and where may it go".

use crate::vault::SecretKind;

/// What a value looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detection {
    /// Provider preset id (`openai`, `stripe`, ...), or a generic id.
    pub provider: &'static str,
    /// Human name.
    pub display: &'static str,
    /// Secret kind to store as.
    pub kind: SecretKind,
    /// Default upstream hosts.
    pub upstreams: &'static [&'static str],
    /// Extra note for the UI (e.g. "live key", "test key").
    pub note: &'static str,
}

const fn det(
    provider: &'static str,
    display: &'static str,
    kind: SecretKind,
    upstreams: &'static [&'static str],
    note: &'static str,
) -> Detection {
    Detection {
        provider,
        display,
        kind,
        upstreams,
        note,
    }
}

/// All providers we know defaults for, by id.
pub const PROVIDERS: &[Detection] = &[
    det(
        "openai",
        "OpenAI",
        SecretKind::ApiKey,
        &["api.openai.com"],
        "",
    ),
    det(
        "anthropic",
        "Anthropic",
        SecretKind::ApiKey,
        &["api.anthropic.com"],
        "",
    ),
    det(
        "google-ai",
        "Google AI",
        SecretKind::ApiKey,
        &["generativelanguage.googleapis.com"],
        "",
    ),
    det(
        "mistral",
        "Mistral",
        SecretKind::ApiKey,
        &["api.mistral.ai"],
        "",
    ),
    det("groq", "Groq", SecretKind::ApiKey, &["api.groq.com"], ""),
    det(
        "openrouter",
        "OpenRouter",
        SecretKind::ApiKey,
        &["openrouter.ai"],
        "",
    ),
    det(
        "stripe",
        "Stripe",
        SecretKind::ApiKey,
        &["api.stripe.com"],
        "",
    ),
    det(
        "github",
        "GitHub",
        SecretKind::BearerToken,
        &["api.github.com"],
        "",
    ),
    det(
        "supabase",
        "Supabase",
        SecretKind::BearerToken,
        &["*.supabase.co"],
        "",
    ),
    det(
        "vercel",
        "Vercel",
        SecretKind::BearerToken,
        &["api.vercel.com"],
        "",
    ),
    det(
        "resend",
        "Resend",
        SecretKind::ApiKey,
        &["api.resend.com"],
        "",
    ),
    det(
        "sendgrid",
        "SendGrid",
        SecretKind::ApiKey,
        &["api.sendgrid.com"],
        "",
    ),
    det(
        "twilio",
        "Twilio",
        SecretKind::ApiKey,
        &["api.twilio.com"],
        "",
    ),
    det(
        "slack",
        "Slack",
        SecretKind::BearerToken,
        &["slack.com"],
        "",
    ),
    det(
        "notion",
        "Notion",
        SecretKind::BearerToken,
        &["api.notion.com"],
        "",
    ),
    det(
        "cloudflare",
        "Cloudflare",
        SecretKind::BearerToken,
        &["api.cloudflare.com"],
        "",
    ),
    det(
        "aws",
        "AWS",
        SecretKind::AwsCredentials,
        &["*.amazonaws.com"],
        "",
    ),
    det(
        "gcp",
        "Google Cloud",
        SecretKind::GcpServiceAccount,
        &["*.googleapis.com"],
        "",
    ),
];

/// Defaults for a provider id.
pub fn provider(id: &str) -> Option<&'static Detection> {
    PROVIDERS.iter().find(|d| d.provider == id)
}

fn is_token_charset(s: &str, extra: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.as_bytes().contains(&b))
}

fn with(mut d: Detection, note: &'static str) -> Detection {
    d.note = note;
    d
}

/// Guess what a value is. Returns `None` for values with no recognisable shape.
pub fn detect(value: &[u8]) -> Option<Detection> {
    let s = core::str::from_utf8(value).ok()?.trim();
    if s.is_empty() {
        return None;
    }
    let p = |id: &str| *provider(id).expect("known provider");

    // Order matters: most specific prefixes first.
    if s.starts_with("sk-ant-") {
        return Some(p("anthropic"));
    }
    if s.starts_with("sk-or-") {
        return Some(p("openrouter"));
    }
    if s.starts_with("sk-proj-")
        || (s.starts_with("sk-") && s.len() >= 40 && is_token_charset(&s[3..], "_-"))
    {
        return Some(p("openai"));
    }
    if s.starts_with("sk_live_") || s.starts_with("rk_live_") {
        return Some(with(p("stripe"), "live key"));
    }
    if s.starts_with("sk_test_") || s.starts_with("rk_test_") {
        return Some(with(p("stripe"), "test key"));
    }
    if s.starts_with("github_pat_")
        || (s.len() >= 40
            && (s.starts_with("ghp_")
                || s.starts_with("gho_")
                || s.starts_with("ghu_")
                || s.starts_with("ghs_")
                || s.starts_with("ghr_")))
    {
        return Some(p("github"));
    }
    if s.starts_with("AKIA") && s.len() == 20 && is_token_charset(s, "") {
        return Some(with(
            p("aws"),
            "access key id; also add the secret access key",
        ));
    }
    if s.starts_with("xoxb-")
        || s.starts_with("xoxp-")
        || s.starts_with("xoxa-")
        || s.starts_with("xoxr-")
    {
        return Some(p("slack"));
    }
    if s.starts_with("SG.") && s.len() > 20 {
        return Some(p("sendgrid"));
    }
    if s.starts_with("re_") && s.len() >= 20 && is_token_charset(&s[3..], "_") {
        return Some(p("resend"));
    }
    if s.starts_with("gsk_") && s.len() >= 40 {
        return Some(p("groq"));
    }
    if s.starts_with("ntn_") || s.starts_with("secret_") {
        return Some(p("notion"));
    }
    if s.starts_with("AIza") && s.len() == 39 && is_token_charset(s, "_-") {
        return Some(p("google-ai"));
    }
    if s.starts_with("SK") && s.len() == 34 && s[2..].bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(p("twilio"));
    }
    if s.starts_with('{') && s.contains("\"type\"") && s.contains("service_account") {
        return Some(p("gcp"));
    }
    if s.starts_with("sbp_") || (s.starts_with("eyJ") && s.contains(".") && s.contains("supabase"))
    {
        return Some(p("supabase"));
    }
    if s.starts_with("-----BEGIN") && s.contains("PRIVATE KEY") {
        return Some(det(
            "ssh",
            "Private key",
            SecretKind::SshKey,
            &[],
            "PEM private key",
        ));
    }
    for scheme in [
        "postgres://",
        "postgresql://",
        "mysql://",
        "redis://",
        "rediss://",
        "mongodb://",
        "mongodb+srv://",
        "amqp://",
    ] {
        if s.starts_with(scheme) {
            return Some(det(
                "connection",
                "Connection string",
                SecretKind::ConnectionString,
                &[],
                "",
            ));
        }
    }
    if s.starts_with("eyJ") && s.matches('.').count() == 2 {
        return Some(det(
            "jwt",
            "JWT / bearer token",
            SecretKind::BearerToken,
            &[],
            "",
        ));
    }
    None
}

/// Whether an environment variable name suggests its value is a secret.
pub fn key_name_suggests_secret(key: &str) -> bool {
    let k = key.to_ascii_uppercase();
    [
        "KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "PRIVATE",
        "CREDENTIAL",
        "AUTH",
        "DSN",
    ]
    .iter()
    .any(|w| k.contains(w))
        && !k.ends_with("_PUBLIC_KEY")
        && !k.contains("PUBLISHABLE")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_providers() {
        let cases: &[(&str, &str)] = &[
            (
                "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
                "anthropic",
            ),
            (
                "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
                "openai",
            ),
            (
                "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ",
                "openai",
            ),
            ("sk-or-v1-abcdef", "openrouter"),
            ("sk_live_51Habcdefghijklmnop", "stripe"),
            ("sk_test_51Habcdefghijklmnop", "stripe"),
            ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "github"),
            ("github_pat_11ABC", "github"),
            ("AKIAIOSFODNN7EXAMPLE", "aws"),
            ("xoxb-123-456-abc", "slack"),
            ("SG.abcdefghijklmnop.qrstuvwxyz", "sendgrid"),
            ("re_abcdefghijklmnopqrstuvwxyz", "resend"),
            ("gsk_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF", "groq"),
            ("ntn_abc", "notion"),
            ("AIzaSyA-abcdefghijklmnopqrstuvwxyz01234", "google-ai"),
            ("SK0123456789abcdef0123456789abcdef", "twilio"),
            (
                "{\"type\": \"service_account\", \"project_id\": \"x\"}",
                "gcp",
            ),
            ("postgres://u:p@h/db", "connection"),
            ("-----BEGIN OPENSSH PRIVATE KEY-----\nabc", "ssh"),
            ("eyJhbGciOi.eyJzdWIi.sig", "jwt"),
        ];
        for (value, expected) in cases {
            let d = detect(value.as_bytes()).unwrap_or_else(|| panic!("no detection for {value}"));
            assert_eq!(d.provider, *expected, "{value}");
        }
        assert_eq!(detect(b"hello world"), None);
        assert_eq!(detect(b""), None);
        assert_eq!(detect(b"sk-short"), None);
    }

    #[test]
    fn stripe_note_distinguishes_live() {
        assert_eq!(detect(b"sk_live_abc").unwrap().note, "live key");
        assert_eq!(detect(b"sk_test_abc").unwrap().note, "test key");
    }

    #[test]
    fn key_names() {
        assert!(key_name_suggests_secret("OPENAI_API_KEY"));
        assert!(key_name_suggests_secret("db_password"));
        assert!(key_name_suggests_secret("DATABASE_DSN"));
        assert!(!key_name_suggests_secret("PORT"));
        assert!(!key_name_suggests_secret(
            "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY"
        ));
        assert!(!key_name_suggests_secret("JWT_PUBLIC_KEY"));
    }

    #[test]
    fn every_provider_has_upstreams() {
        for d in PROVIDERS {
            assert!(!d.upstreams.is_empty(), "{}", d.provider);
        }
    }
}
