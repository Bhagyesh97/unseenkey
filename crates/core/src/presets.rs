//! Provider presets: upstream host, how the secret is sent, and ready-made
//! policies with plain-English names. Source of truth is `presets/*.toml`,
//! embedded at build time. A user may add providers without rebuilding by
//! dropping `<id>.toml` files into the vault directory's `presets/` folder
//! ([`load_user_dir`]); those sit beside the built-in ones and win on an id
//! clash.

use crate::policy::{Policy, PolicyError, Rule};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};

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
    /// `Authorization: <scheme> <secret>` for providers that do not say
    /// `Bearer` (`Token` for Deepgram, `Bot` for Discord, `Key` for fal).
    Scheme {
        /// The word before the secret.
        scheme: String,
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
    /// AWS Signature Version 4: the broker signs each request with the real
    /// key (`broker::sigv4`); the SDK is given a handle as its access key id.
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
    /// Hosts this policy is limited to, when narrower than the preset's
    /// (for example only the S3 endpoints of AWS).
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Recommended for delegation to others?
    #[serde(default)]
    pub recommended: bool,
}

/// A key-shaped handle format, optionally only for real keys with a given prefix.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleFormat {
    /// Applies when the real key starts with this text (empty: any key).
    #[serde(default)]
    pub when: String,
    /// The format, see [`crate::handles::Format`].
    pub format: String,
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
    /// Variables the SDK insists on that carry no secret: name to literal value
    /// (AWS SDKs refuse to start without a secret access key, any will do).
    #[serde(default)]
    pub env_static: BTreeMap<String, String>,
    /// Policies, first is the default suggestion.
    #[serde(default)]
    pub policies: Vec<PresetPolicy>,
    /// Camouflage handle formats (D-26), most specific `when` first. Used only
    /// when a handle is created with camouflage asked for.
    #[serde(default)]
    pub handle_formats: Vec<HandleFormat>,
    /// Grouping for pickers: `ai`, `payments`, `hosting`, `email`, …
    #[serde(default)]
    pub category: String,
    /// Prefixes only this provider's keys start with. Used to recognise a
    /// pasted key; a prefix another preset also claims is ignored
    /// ([`detect_by_prefix`]).
    #[serde(default)]
    pub key_prefixes: Vec<String>,
    /// Variable or name words that point at this provider when the key has
    /// no recognisable shape (`CLOUDFLARE_API_TOKEN`, `cloudflare`).
    #[serde(default)]
    pub env_names: Vec<String>,
    /// One read-only request that tells a working key from a refused one.
    #[serde(default)]
    pub verify: Option<Verify>,
}

/// A harmless request that tests a key: 2xx means accepted, 401/403 refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verify {
    /// Always a read: `GET` unless the provider only reads through `POST`.
    #[serde(default = "get_method")]
    pub method: String,
    /// Path and query, without the key.
    pub path: String,
    /// Host when not the first of `upstreams`.
    #[serde(default)]
    pub host: Option<String>,
    /// Extra non-secret headers the provider requires (API versions).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

fn get_method() -> String {
    "GET".to_string()
}

impl Preset {
    /// The camouflage format for a real key of this provider, if there is one.
    pub fn handle_format_for(&self, real_key: &[u8]) -> Option<crate::handles::Format> {
        self.handle_formats
            .iter()
            .find(|f| real_key.starts_with(f.when.as_bytes()))
            .and_then(|f| crate::handles::Format::parse(&f.format).ok())
    }

    /// Build a full [`Policy`] from one of this preset's policies.
    pub fn policy(&self, policy_id: &str) -> Option<Policy> {
        let pp = self.policies.iter().find(|p| p.id == policy_id)?;
        Some(Policy {
            upstreams: if pp.upstreams.is_empty() {
                self.upstreams.clone()
            } else {
                pp.upstreams.clone()
            },
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
    "hostinger",
    "assemblyai",
    "cohere",
    "deepseek",
    "elevenlabs",
    "replicate",
    "clerk",
    "supabase-management",
    "hubspot",
    "figma",
    "beehiiv",
    "loops",
    "digitalocean",
    "linode",
    "netlify",
    "render",
    "mapbox",
    "vapi",
    "alpha-vantage",
    "openweathermap",
    "mercado-pago",
    "mollie",
    "paddle",
    "paystack",
    "polar",
    "airtable",
    "calendly",
    "clickup",
    "coda",
    "tally",
    "youtube-data",
    "xai",
    "together",
    "fireworks",
    "deepgram",
    "perplexity",
    "cerebras",
    "postmark",
    "brevo",
    "lemon-squeezy",
    "square",
    "heroku",
    "neon",
    "vultr",
    "hetzner-cloud",
    "circleci",
    "discord",
    "telnyx",
    "aws",
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
    for f in &p.handle_formats {
        crate::handles::Format::parse(&f.format)
            .map_err(|e| PolicyError::Invalid(format!("preset {id} handle format: {e}")))?;
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
        // A policy may narrow the preset's hosts, never widen them.
        if let Some(wide) = pol.upstreams.iter().find(|u| {
            !p.upstreams.contains(u) && !crate::policy::eval::host_allowed(&p.upstreams, u)
        }) {
            return Err(PolicyError::Invalid(format!(
                "preset {id} policy {} names host {wide}, outside the preset's hosts",
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

/// Presets loaded from the user's presets directory.
#[derive(Default)]
struct UserPresets {
    by_id: BTreeMap<String, &'static Preset>,
    formats: Vec<crate::handles::Format>,
}

fn user() -> &'static RwLock<UserPresets> {
    static USER: OnceLock<RwLock<UserPresets>> = OnceLock::new();
    USER.get_or_init(|| RwLock::new(UserPresets::default()))
}

/// Load every `<id>.toml` in `dir` as a preset, replacing whatever user
/// presets were loaded before. A missing directory means no user presets.
/// Returns the ids loaded and one message per file that was skipped. Each
/// loaded preset lives for the rest of the process.
pub fn load_user_dir(dir: &std::path::Path) -> (Vec<String>, Vec<String>) {
    let mut loaded = UserPresets::default();
    let mut ids = Vec::new();
    let mut problems = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => {
            *user().write().unwrap_or_else(|e| e.into_inner()) = loaded;
            return (ids, problems);
        }
    };
    let mut files: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    for path in files {
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                problems.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        match parse(&id, &text) {
            Ok(p) => {
                for f in &p.handle_formats {
                    if let Ok(fmt) = crate::handles::Format::parse(&f.format) {
                        loaded.formats.push(fmt);
                    }
                }
                let leaked: &'static Preset = Box::leak(Box::new(p));
                loaded.by_id.insert(id.clone(), leaked);
                ids.push(id);
            }
            Err(e) => problems.push(format!("{}: {e}", path.display())),
        }
    }
    *user().write().unwrap_or_else(|e| e.into_inner()) = loaded;
    (ids, problems)
}

/// Is `id` one of the presets loaded from the user's directory?
pub fn is_user_preset(id: &str) -> bool {
    user()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .by_id
        .contains_key(id)
}

/// Is `s` a camouflage handle, that is, does it have exactly the shape of one
/// of the presets' handle formats?
pub fn is_camouflage_handle(s: &str) -> bool {
    static FORMATS: OnceLock<Vec<crate::handles::Format>> = OnceLock::new();
    let built_in = FORMATS.get_or_init(|| {
        table()
            .values()
            .flat_map(|p| &p.handle_formats)
            .filter_map(|f| crate::handles::Format::parse(&f.format).ok())
            .collect()
    });
    built_in.iter().any(|f| f.matches(s))
        || user()
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .formats
            .iter()
            .any(|f| f.matches(s))
}

/// Is `s` a handle of either kind (canonical `usk_h_…` or camouflage)? Shape
/// only: whether it exists is the vault's business.
pub fn is_handle(s: &str) -> bool {
    crate::handles::is_handle_shaped(s) || is_camouflage_handle(s)
}

/// Prefixes shorter than this, or claimed by more than one preset, never
/// decide a provider on their own (`sk-`, `AIza` and `pk_` are shared).
const MIN_PREFIX: usize = 4;

/// The preset whose distinctive key prefix `value` starts with. A prefix that
/// overlaps another preset's (one is a prefix of the other) is ambiguous and
/// skipped; the longest matching unambiguous prefix wins.
pub fn detect_by_prefix(value: &str) -> Option<&'static Preset> {
    let v = value.trim();
    let presets: Vec<&'static Preset> = all().collect();
    let mut best: Option<(&'static Preset, usize)> = None;
    for p in &presets {
        for pre in &p.key_prefixes {
            if pre.len() < MIN_PREFIX || !v.starts_with(pre.as_str()) || v.len() <= pre.len() {
                continue;
            }
            let shared = presets.iter().any(|q| {
                q.id != p.id
                    && q.key_prefixes
                        .iter()
                        .any(|o| o.starts_with(pre.as_str()) || pre.starts_with(o.as_str()))
            });
            if !shared && best.is_none_or(|(_, n)| pre.len() > n) {
                best = Some((p, pre.len()));
            }
        }
    }
    best.map(|(p, _)| p)
}

/// The preset a secret's name points at: an exact variable name
/// (`OPENAI_API_KEY`), or a word of the name equal to a preset id, a word of
/// its display name, or one of its `env_names` (`my-cloudflare-token`).
/// `None` when nothing or more than one preset matches.
pub fn guess_by_name(name: &str) -> Option<&'static Preset> {
    let upper = name.trim().to_ascii_uppercase();
    let words: Vec<String> = name
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(str::to_string)
        .collect();
    let joined = words.join("");
    let mut hits: Vec<&'static Preset> = Vec::new();
    for p in all().filter(|p| p.id != "generic") {
        let vars = p.env.values().chain(p.env_names.iter());
        let exact = vars.clone().any(|e| e.eq_ignore_ascii_case(&upper));
        let id_flat = p.id.replace('-', "");
        let display_flat: String = p
            .display
            .to_ascii_lowercase()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();
        let word = words.iter().any(|w| *w == id_flat || *w == display_flat)
            || (!joined.is_empty() && (joined == id_flat || joined == display_flat))
            || p.env_names.iter().any(|e| {
                let e = e.to_ascii_lowercase();
                !e.contains('_') && words.contains(&e)
            });
        if exact {
            return Some(p);
        }
        if word && !hits.iter().any(|h| h.id == p.id) {
            hits.push(p);
        }
    }
    (hits.len() == 1).then(|| hits[0])
}

/// Every preset, user-loaded ones first, then the built-in ones they did not
/// override, each group by id.
pub fn all() -> impl Iterator<Item = &'static Preset> {
    let u = user().read().unwrap_or_else(|e| e.into_inner());
    let mut v: Vec<&'static Preset> = u.by_id.values().copied().collect();
    v.extend(
        table()
            .iter()
            .filter(|(id, _)| !u.by_id.contains_key(**id))
            .map(|(_, p)| p),
    );
    v.into_iter()
}

/// One preset, the user's version first.
pub fn get(id: &str) -> Option<&'static Preset> {
    if let Some(p) = user()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .by_id
        .get(id)
    {
        return Some(p);
    }
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
    fn a_pasted_key_is_recognised_only_by_a_prefix_it_owns() {
        let id = |v: &str| detect_by_prefix(v).map(|p| p.id.as_str());
        assert_eq!(
            id("cfut_0123456789abcdefghijklmnopqrstuvwxyzABCD"),
            Some("cloudflare")
        );
        assert_eq!(
            id("xkeysib-0123456789abcdef0123456789abcdef-xyz"),
            Some("brevo")
        );
        assert_eq!(
            id("pdl_live_apikey_01abcdefghijklmnopqrstuvwx"),
            Some("paddle")
        );
        assert_eq!(
            id("napi_abcdefghijklmnopqrstuvwxyz0123456789"),
            Some("neon")
        );
        // Shared by Stripe, Clerk and Paystack, or too common: the prefix alone
        // never decides (Stripe's own shape check in `providers::detect` does).
        assert_eq!(id("sk_live_abcdefghijklmnop"), None);
        assert_eq!(id("sk-0123456789abcdefghijklmnopqrstuvwxyz"), None);
        assert_eq!(id("live_abcdefghijklmnopqrstuvwxyz012345"), None);
        // A bare prefix is not a key.
        assert_eq!(id("cfut_"), None);
        // No preset may claim a prefix of fewer than four characters for detection.
        for p in all() {
            for pre in &p.key_prefixes {
                assert!(!pre.is_empty(), "{} has an empty prefix", p.id);
            }
        }
    }

    #[test]
    fn a_name_points_at_its_provider() {
        let id = |n: &str| guess_by_name(n).map(|p| p.id.as_str());
        assert_eq!(id("CLOUDFLARE_API_TOKEN"), Some("cloudflare"));
        assert_eq!(id("cloudflare"), Some("cloudflare"));
        assert_eq!(id("Hostinger"), Some("hostinger"));
        assert_eq!(id("my-deepgram-key"), Some("deepgram"));
        assert_eq!(id("LEMONSQUEEZY_API_KEY"), Some("lemon-squeezy"));
        assert_eq!(id("lemon squeezy"), Some("lemon-squeezy"));
        assert_eq!(id("SENDINBLUE_API_KEY"), Some("brevo"));
        assert_eq!(id("db-password"), None);
        assert_eq!(id("api"), None);
        assert_eq!(id("generic"), None);
    }

    #[test]
    fn every_test_call_is_a_read_on_one_of_the_presets_hosts() {
        for p in all() {
            let Some(v) = &p.verify else { continue };
            assert!(
                v.method == "GET" || v.method == "POST",
                "{}: {}",
                p.id,
                v.method
            );
            assert!(v.path.starts_with('/'), "{}: {}", p.id, v.path);
            let host = v.host.clone().unwrap_or_else(|| p.upstreams[0].clone());
            assert!(
                !host.contains('*'),
                "{}: test host {host} must be concrete",
                p.id
            );
            assert!(
                crate::policy::eval::host_allowed(&p.upstreams, &host),
                "{}: {host}",
                p.id
            );
            if let Auth::Query { param } = &p.auth {
                assert!(
                    !v.path.contains(&format!("{param}=")),
                    "{}: the broker adds the key",
                    p.id
                );
            }
        }
    }

    #[test]
    fn every_embedded_preset_parses_and_explains() {
        let ids: Vec<&str> = EMBEDDED.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids.len(), 66);
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
    fn camouflage_handles_look_like_keys_and_are_never_mistaken_for_them() {
        let real: &[(&str, &str, &str)] = &[
            (
                "openai",
                "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",
                "sk-proj-usk-",
            ),
            (
                "openai",
                "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL",
                "sk-usk-",
            ),
            (
                "anthropic",
                "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
                "sk-ant-api03-usk-",
            ),
            (
                "anthropic",
                "sk-ant-oat01-abcdefghijklmnopqrstuvwxyz0123456789",
                "sk-ant-oat01-usk-",
            ),
            ("stripe", "sk_live_51Habcdefghijklmnop", "sk_live_usk"),
            ("stripe", "sk_test_51Habcdefghijklmnop", "sk_test_usk"),
            ("stripe", "rk_live_51Habcdefghijklmnop", "rk_live_usk"),
            (
                "github",
                "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
                "ghp_usk",
            ),
            (
                "github",
                "github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz",
                "github_pat_usk",
            ),
            ("slack", "xoxb-1234567890-abcdefghijklmnop", "xoxb-usk-"),
            (
                "sendgrid",
                "SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
                "SG.usk",
            ),
            (
                "google-ai",
                "AIzaSyA-abcdefghijklmnopqrstuvwxyz01234",
                "AIzaSyusk",
            ),
            (
                "groq",
                "gsk_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP",
                "gsk_usk",
            ),
        ];
        for (provider, key, prefix) in real {
            let preset = get(provider).unwrap();
            let format = preset
                .handle_format_for(key.as_bytes())
                .unwrap_or_else(|| panic!("no format for {provider} key {key}"));
            let handle = format.generate();
            assert!(handle.starts_with(prefix), "{provider}: {handle}");
            assert!(handle.contains(crate::handles::MARKER));
            assert!(
                is_camouflage_handle(&handle) && is_handle(&handle),
                "{handle}"
            );
            // A camouflage handle is never detected as the provider's key...
            assert_eq!(
                crate::providers::detect(handle.as_bytes()),
                None,
                "{handle}"
            );
            // ...and a real key is never taken for a handle.
            assert!(!is_handle(key), "{key}");
        }
        // GitHub's classic token length is kept exactly.
        let ghp = get("github")
            .unwrap()
            .handle_format_for(b"ghp_x")
            .unwrap()
            .generate();
        assert_eq!(ghp.len(), 40);
        // No format for keys of an unknown shape, or for providers without one.
        assert!(get("stripe")
            .unwrap()
            .handle_format_for(b"whsec_abc")
            .is_none());
        assert!(get("aws").unwrap().handle_format_for(b"anything").is_none());
        assert!(is_handle(&crate::handles::generate()));
        assert!(!is_handle("sk-usk-short"));
    }

    #[test]
    fn aws_policies_narrow_hosts() {
        let aws = get("aws").unwrap();
        assert_eq!(aws.auth, Auth::AwsSigv4);
        assert!(aws.env_static.contains_key("AWS_SECRET_ACCESS_KEY"));
        let r = |m: &'static str, host: &'static str, path: &'static str| Request {
            method: m,
            path,
            host,
            body_len: None,
            caller: None,
        };
        let ro = policy_ref("aws:s3-read-only").unwrap();
        let s3 = "s3.eu-west-1.amazonaws.com";
        assert!(evaluate(&ro, &r("GET", s3, "/bucket/key"), 0, Usage::default()).is_allow());
        assert!(evaluate(
            &ro,
            &r("HEAD", "s3.amazonaws.com", "/bucket"),
            0,
            Usage::default()
        )
        .is_allow());
        assert!(matches!(
            evaluate(&ro, &r("PUT", s3, "/bucket/key"), 0, Usage::default()),
            Decision::Deny(_)
        ));
        // GET is not "read-only" outside S3 (query APIs take actions in a GET).
        assert!(matches!(
            evaluate(
                &ro,
                &r("GET", "ec2.eu-west-1.amazonaws.com", "/"),
                0,
                Usage::default()
            ),
            Decision::Deny(_)
        ));
        let s3_all = policy_ref("aws:s3").unwrap();
        assert!(evaluate(&s3_all, &r("PUT", s3, "/bucket/key"), 0, Usage::default()).is_allow());
        assert!(matches!(
            evaluate(
                &s3_all,
                &r("POST", "dynamodb.eu-west-1.amazonaws.com", "/"),
                0,
                Usage::default()
            ),
            Decision::Deny(_)
        ));
        let full = policy_ref("aws:full").unwrap();
        assert!(evaluate(
            &full,
            &r("POST", "dynamodb.eu-west-1.amazonaws.com", "/"),
            0,
            Usage::default()
        )
        .is_allow());
        assert!(matches!(
            evaluate(&full, &r("GET", "evil.example", "/"), 0, Usage::default()),
            Decision::Deny(_)
        ));
        // Narrowing that widens is rejected at load time.
        let bad = r#"
id = "x"
display = "X"
upstreams = ["api.example.com"]
auth = { kind = "bearer" }
[[policies]]
id = "full"
display = "f"
allow = ["* /**"]
upstreams = ["other.example.com"]
"#;
        assert!(parse("x", bad).is_err());
    }

    #[test]
    fn policy_ref_errors() {
        assert!(policy_ref("stripe").is_err());
        assert!(policy_ref("nope:full").is_err());
        assert!(policy_ref("stripe:nope").is_err());
    }

    #[test]
    fn user_presets_load_from_a_directory_and_win_on_id_clash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("acme.toml"),
            r#"id = "acme"
display = "Acme"
upstreams = ["api.acme.test"]
auth = { kind = "bearer" }
base_path = ""
[env]
api_key = "ACME_TOKEN"
[[policies]]
id = "read-only"
display = "Read only"
recommended = true
allow = ["GET /**"]
"#,
        )
        .unwrap();
        // Wrong id inside, so it is skipped with a message.
        std::fs::write(dir.path().join("broken.toml"), "id = \"other\"\n").unwrap();
        // Not a preset file at all.
        std::fs::write(dir.path().join("notes.txt"), "ignored").unwrap();
        let (ids, problems) = load_user_dir(dir.path());
        assert_eq!(ids, vec!["acme".to_string()]);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("broken.toml"));
        let acme = get("acme").expect("user preset is visible");
        assert_eq!(acme.display, "Acme");
        assert!(is_user_preset("acme"));
        assert!(!is_user_preset("stripe"));
        assert!(all().any(|p| p.id == "acme"));
        assert!(all().any(|p| p.id == "stripe"), "built-ins remain");
        assert!(policy_ref("acme:read-only").is_ok());
        // A user file with a built-in id overrides it.
        std::fs::write(
            dir.path().join("stripe.toml"),
            r#"id = "stripe"
display = "Stripe (mine)"
upstreams = ["api.stripe.com"]
auth = { kind = "bearer" }
base_path = ""
[[policies]]
id = "full"
display = "Everything"
allow = ["* /**"]
"#,
        )
        .unwrap();
        let (ids, _) = load_user_dir(dir.path());
        assert_eq!(ids, vec!["acme".to_string(), "stripe".to_string()]);
        assert_eq!(get("stripe").unwrap().display, "Stripe (mine)");
        assert_eq!(all().filter(|p| p.id == "stripe").count(), 1);
        // Reloading an empty directory clears the user set again.
        let empty = tempfile::tempdir().unwrap();
        load_user_dir(empty.path());
        assert!(get("acme").is_none());
        assert_eq!(get("stripe").unwrap().display, "Stripe");
    }
}
