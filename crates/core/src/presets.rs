//! Provider presets: upstream host, how the secret is sent, and ready-made
//! policies with plain-English names. Source of truth is `presets/*.toml`,
//! embedded at build time; users may override in `~/.unseenkey/presets/`
//! (loading of overrides arrives with the broker).

use crate::policy::{Policy, PolicyError, Rule};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// How the broker places the secret into an upstream request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Auth {
    /// `Authorization: Bearer <secret>`; optionally the same value in extra headers.
    Bearer {
        /// Extra header names that also receive the secret (e.g. Supabase `apikey`).
        #[serde(default)]
        also_headers: Vec<String>,
    },
    /// `<name>: <secret>`.
    Header {
        /// Header name.
        name: String,
    },
    /// `Authorization: Basic base64(username:password)` from the secret's fields.
    Basic,
    /// `?<param>=<secret>` on the URL.
    Query {
        /// Parameter name.
        param: String,
    },
    /// `{{usk:name}}` placeholders anywhere in the request.
    Template,
    /// AWS SigV4 signing (adapter arrives in M2.3).
    AwsSigv4,
}

/// A named policy inside a preset.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetPolicy {
    /// Short id, e.g. `chat`, `read-only`, `full`.
    pub id: String,
    /// Human name shown in pickers.
    pub display: String,
    /// Allow rules.
    #[serde(default)]
    pub allow: Vec<Rule>,
    /// Deny rules.
    #[serde(default)]
    pub deny: Vec<Rule>,
    /// Recommended for delegation to others?
    #[serde(default)]
    pub recommended: bool,
}

/// A provider preset.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    /// Id, matches `providers::Detection::provider`.
    pub id: String,
    /// Human name.
    pub display: String,
    /// Hosts.
    pub upstreams: Vec<String>,
    /// Injection style.
    pub auth: Auth,
    /// Where to get a key.
    #[serde(default)]
    pub docs: String,
    /// Base path the proxy route maps to (e.g. `/v1` for OpenAI). Informational for setup snippets.
    #[serde(default)]
    pub base_path: String,
    /// Environment variable names SDKs read for the base URL and key, for `usk env`.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Policies, first is the default suggestion.
    #[serde(default)]
    pub policies: Vec<PresetPolicy>,
}

impl Preset {
    /// Build a full [`Policy`] from one of this preset's policies.
    pub fn policy(&self, policy_id: &str) -> Option<Policy> {
        let pp = self.policies.iter().find(|p| p.id == policy_id)?;
        Some(Policy {
            upstreams: self.upstreams.clone(),
            allow: pp.allow.clone(),
            deny: pp.deny.clone(),
            notes: Some(format!("{}: {}", self.display, pp.display)),
            ..Policy::default()
        })
    }
}

macro_rules! embedded {
    ($($name:literal),* $(,)?) => {
        &[$(($name, include_str!(concat!("../presets/", $name, ".toml")))),*]
    };
}

/// (id, toml) for every built-in preset.
pub const EMBEDDED: &[(&str, &str)] = embedded![
    "openai",
    "anthropic",
    "google-ai",
    "mistral",
    "groq",
    "openrouter",
    "stripe",
    "github",
    "supabase",
    "vercel",
    "resend",
    "sendgrid",
    "twilio",
    "slack",
    "notion",
    "cloudflare",
    "generic",
];

fn parse(id: &str, text: &str) -> Result<Preset, PolicyError> {
    let p: Preset =
        toml::from_str(text).map_err(|e| PolicyError::Parse(format!("preset {id}: {e}")))?;
    if p.id != id {
        return Err(PolicyError::Invalid(format!(
            "preset file {id} declares id {}",
            p.id
        )));
    }
    if p.upstreams.is_empty() && id != "generic" {
        return Err(PolicyError::Invalid(format!(
            "preset {id} has no upstreams"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for pol in &p.policies {
        if !seen.insert(pol.id.as_str()) {
            return Err(PolicyError::Invalid(format!(
                "preset {id} has duplicate policy {}",
                pol.id
            )));
        }
        if pol.allow.is_empty() {
            return Err(PolicyError::Invalid(format!(
                "preset {id} policy {} allows nothing",
                pol.id
            )));
        }
    }
    Ok(p)
}

fn table() -> &'static BTreeMap<&'static str, Preset> {
    static TABLE: OnceLock<BTreeMap<&'static str, Preset>> = OnceLock::new();
    TABLE.get_or_init(|| {
        EMBEDDED
            .iter()
            .map(|(id, text)| {
                let p = parse(id, text)
                    .unwrap_or_else(|e| panic!("built-in preset {id} is invalid: {e}"));
                (*id, p)
            })
            .collect()
    })
}

/// All built-in presets, by id.
pub fn all() -> impl Iterator<Item = &'static Preset> {
    table().values()
}

/// One preset.
pub fn get(id: &str) -> Option<&'static Preset> {
    table().get(id)
}

/// Resolve `"stripe:payments"` to a policy.
pub fn policy_ref(spec: &str) -> Result<Policy, PolicyError> {
    let (pid, pol) = spec
        .split_once(':')
        .ok_or_else(|| PolicyError::Invalid(format!("expected provider:policy, got {spec:?}")))?;
    let preset =
        get(pid).ok_or_else(|| PolicyError::Invalid(format!("unknown provider {pid:?}")))?;
    preset
        .policy(pol)
        .ok_or_else(|| PolicyError::Invalid(format!("provider {pid} has no policy {pol:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{evaluate, explain, Decision, Request, Usage};

    #[test]
    fn every_embedded_preset_parses_and_explains() {
        let ids: Vec<&str> = EMBEDDED.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids.len(), 17);
        for id in ids {
            let p = get(id).unwrap_or_else(|| panic!("missing {id}"));
            assert!(!p.policies.is_empty(), "{id} has no policies");
            assert!(
                p.policies.iter().any(|pp| pp.id == "full"),
                "{id} lacks a full policy"
            );
            for pp in &p.policies {
                let pol = p.policy(&pp.id).unwrap();
                pol.validate().unwrap();
                let text = explain(&pol);
                assert!(text.starts_with("Can "), "{id}:{}: {text}", pp.id);
            }
        }
        // Detection ids and preset ids agree where both exist.
        for d in crate::providers::PROVIDERS {
            if let Some(p) = get(d.provider) {
                assert_eq!(p.upstreams, d.upstreams, "{}", d.provider);
            }
        }
    }

    #[test]
    fn stripe_payments_policy_behaves() {
        let p = policy_ref("stripe:payments").unwrap();
        let r = |m: &'static str, path: &'static str| Request {
            method: m,
            path,
            host: "api.stripe.com",
            body_len: None,
            caller: None,
        };
        assert!(evaluate(&p, &r("GET", "/v1/customers"), 0, Usage::default()).is_allow());
        assert!(evaluate(&p, &r("POST", "/v1/payment_intents"), 0, Usage::default()).is_allow());
        assert!(matches!(
            evaluate(&p, &r("POST", "/v1/refunds"), 0, Usage::default()),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate(&p, &r("POST", "/v1/payouts"), 0, Usage::default()),
            Decision::Deny(_)
        ));
        let wrong_host = Request {
            host: "evil.example",
            ..r("GET", "/v1/customers")
        };
        assert!(matches!(
            evaluate(&p, &wrong_host, 0, Usage::default()),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn openai_chat_policy_behaves() {
        let p = policy_ref("openai:chat").unwrap();
        let r = |m: &'static str, path: &'static str| Request {
            method: m,
            path,
            host: "api.openai.com",
            body_len: None,
            caller: None,
        };
        assert!(evaluate(&p, &r("POST", "/v1/chat/completions"), 0, Usage::default()).is_allow());
        assert!(evaluate(&p, &r("GET", "/v1/models"), 0, Usage::default()).is_allow());
        assert!(matches!(
            evaluate(&p, &r("POST", "/v1/fine_tuning/jobs"), 0, Usage::default()),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate(&p, &r("GET", "/v1/organization/users"), 0, Usage::default()),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn policy_ref_errors() {
        assert!(policy_ref("stripe").is_err());
        assert!(policy_ref("nope:full").is_err());
        assert!(policy_ref("stripe:nope").is_err());
    }
}
