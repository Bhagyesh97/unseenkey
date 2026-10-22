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
    fn every_embedded_preset_parses_and_explains() {
        let ids: Vec<&str> = EMBEDDED.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids.len(), 19);
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
