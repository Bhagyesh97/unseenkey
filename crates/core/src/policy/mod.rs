//! Policies: what a handle may do with a secret.
//!
//! A policy is a plain document (TOML when a human edits it, JSON when the
//! vault stores it) with a fixed schema. There is no rule language: the schema
//! is small enough for a non-technical owner to read, and [`explain`] renders
//! it as sentences so they can confirm what they are granting.
//!
//! Evaluation ([`eval`]) is pure: it takes a policy, a request summary, the
//! current time and a usage snapshot and returns a decision. All state (rate
//! counters, approval caches) lives in the broker.
//!
//! Invariant INV-5: anything unparseable or unknown denies.

use serde::{Deserialize, Serialize};

pub mod eval;
pub mod explain;
pub mod rules;
pub mod schedule;

pub use eval::{evaluate, ApprovalScope, Decision, DenyReason, Request, Usage};
pub use explain::explain;
pub use rules::{Method, Rule};
pub use schedule::Schedule;

/// Policy parsing and validation errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// Not valid TOML/JSON for the schema (unknown fields included).
    #[error("invalid policy: {0}")]
    Parse(String),
    /// A rule string is malformed.
    #[error("invalid rule {0:?}: {1}")]
    Rule(String, String),
    /// A schedule window is malformed.
    #[error("invalid schedule window {0:?}: {1}")]
    Window(String, String),
    /// Unknown IANA time zone.
    #[error("unknown time zone {0:?}")]
    TimeZone(String),
    /// A timestamp is not RFC 3339.
    #[error("invalid timestamp {0:?}")]
    Timestamp(String),
    /// Semantic problem.
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// Current schema version.
pub const VERSION: u32 = 1;

/// Request caps. Missing means unlimited.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Sliding one-minute window.
    pub requests_per_minute: Option<u32>,
    /// Sliding 24-hour window.
    pub requests_per_day: Option<u32>,
    /// Lifetime of the handle.
    pub requests_total: Option<u64>,
    /// Largest request body accepted.
    pub max_body_bytes: Option<u64>,
}

/// When human approval is needed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Never.
    #[default]
    None,
    /// Once per (method, path pattern); the broker caches the decision.
    FirstUse,
    /// Every request.
    EveryUse,
    /// Only requests matching `approval.paths`.
    Paths,
}

/// Approval settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Approval {
    /// Mode.
    pub mode: ApprovalMode,
    /// Rules that need approval when `mode == paths`.
    pub paths: Vec<Rule>,
    /// Seconds to wait for a decision before denying.
    pub timeout_seconds: u32,
}

impl Default for Approval {
    fn default() -> Self {
        Self {
            mode: ApprovalMode::None,
            paths: Vec::new(),
            timeout_seconds: 120,
        }
    }
}

/// An RFC 3339 instant stored as Unix milliseconds. Serialises back to RFC 3339.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(pub i64);

impl Instant {
    /// Parse RFC 3339 (`2026-12-31T00:00:00Z`, offsets allowed).
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let ts: jiff::Timestamp = s
            .trim()
            .parse()
            .map_err(|_| PolicyError::Timestamp(s.to_string()))?;
        Ok(Self(ts.as_millisecond()))
    }

    /// RFC 3339 in UTC.
    pub fn to_rfc3339(self) -> String {
        jiff::Timestamp::from_millisecond(self.0)
            .map(|t| t.to_string())
            .unwrap_or_else(|_| "invalid".into())
    }
}

impl Serialize for Instant {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for Instant {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Instant::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Schema version; must be 1.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Name of the secret this policy was written for (informational; the
    /// binding is by id in the handle record).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Hosts the secret may be sent to. Empty means "inherit the secret's list".
    /// Non-empty must be a subset of the secret's list (checked by the broker).
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Allowed method/path rules. At least one must match.
    #[serde(default)]
    pub allow: Vec<Rule>,
    /// Denied rules; a match here wins over `allow`.
    #[serde(default)]
    pub deny: Vec<Rule>,
    /// Caps.
    #[serde(default)]
    pub limits: Limits,
    /// Time windows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<Schedule>,
    /// Hard expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Instant>,
    /// Approval settings.
    #[serde(default)]
    pub approval: Approval,
    /// Caller ids allowed to use the handle. Empty means any registered caller.
    #[serde(default)]
    pub callers: Vec<String>,
    /// Allow `usk run` env injection.
    #[serde(default)]
    pub injection: bool,
    /// Expose to MCP clients.
    #[serde(default = "default_true")]
    pub mcp: bool,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

fn default_version() -> u32 {
    VERSION
}

fn default_true() -> bool {
    true
}

impl Default for Policy {
    /// The empty policy: denies everything (INV-5).
    fn default() -> Self {
        Self {
            version: VERSION,
            secret: None,
            upstreams: Vec::new(),
            allow: Vec::new(),
            deny: Vec::new(),
            limits: Limits::default(),
            schedule: None,
            expires_at: None,
            approval: Approval::default(),
            callers: Vec::new(),
            injection: false,
            mcp: true,
            notes: None,
        }
    }
}

impl Policy {
    /// Parse TOML.
    pub fn from_toml(text: &str) -> Result<Self, PolicyError> {
        let p: Policy = toml::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))?;
        p.validate()?;
        Ok(p)
    }

    /// Parse JSON.
    pub fn from_json(text: &str) -> Result<Self, PolicyError> {
        let p: Policy =
            serde_json::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))?;
        p.validate()?;
        Ok(p)
    }

    /// Render as TOML for editing.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// Render as JSON for storage.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Semantic checks beyond the schema.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != VERSION {
            return Err(PolicyError::Invalid(format!(
                "unsupported policy version {}",
                self.version
            )));
        }
        if self.approval.mode == ApprovalMode::Paths && self.approval.paths.is_empty() {
            return Err(PolicyError::Invalid(
                "approval.mode is \"paths\" but approval.paths is empty".into(),
            ));
        }
        if self.approval.timeout_seconds == 0 || self.approval.timeout_seconds > 3600 {
            return Err(PolicyError::Invalid(
                "approval.timeout_seconds must be between 1 and 3600".into(),
            ));
        }
        if let Some(s) = &self.schedule {
            s.validate()?;
        }
        for u in &self.upstreams {
            if u.is_empty() || u.contains('/') || u.contains(' ') {
                return Err(PolicyError::Invalid(format!("invalid upstream host {u:?}")));
            }
        }
        for c in &self.callers {
            if c.is_empty() {
                return Err(PolicyError::Invalid("empty caller id".into()));
            }
        }
        Ok(())
    }

    /// A policy allowing everything for the given hosts. For presets' "full" option.
    pub fn allow_all() -> Self {
        Self {
            allow: vec![Rule::any()],
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
version = 1
secret = "stripe-live"
upstreams = ["api.stripe.com"]
allow = ["GET /v1/**", "POST /v1/payment_intents", "POST /v1/payment_intents/*/confirm"]
deny = ["POST /v1/refunds", "* /v1/payouts/**"]
expires_at = "2026-12-31T00:00:00Z"
callers = ["device:2f9c"]
injection = false
mcp = true
notes = "For the checkout project"

[limits]
requests_per_minute = 120
requests_per_day = 5000
requests_total = 100000
max_body_bytes = 1048576

[schedule]
timezone = "Asia/Kolkata"
allowed = ["Mon-Fri 09:00-19:00"]

[approval]
mode = "paths"
paths = ["POST /v1/transfers/**"]
timeout_seconds = 120
"#;

    #[test]
    fn parses_example_and_round_trips() {
        let p = Policy::from_toml(EXAMPLE).unwrap();
        assert_eq!(p.allow.len(), 3);
        assert_eq!(p.deny.len(), 2);
        assert_eq!(p.limits.requests_per_minute, Some(120));
        assert_eq!(p.approval.mode, ApprovalMode::Paths);
        assert_eq!(
            p.expires_at.unwrap(),
            Instant::parse("2026-12-31T00:00:00Z").unwrap()
        );
        let json = p.to_json();
        assert_eq!(Policy::from_json(&json).unwrap(), p);
        let toml = p.to_toml();
        assert_eq!(Policy::from_toml(&toml).unwrap(), p);
    }

    #[test]
    fn unknown_field_is_an_error() {
        let err = Policy::from_toml("version = 1\nallow = [\"GET /**\"]\nallow_all = true\n")
            .unwrap_err();
        assert!(matches!(err, PolicyError::Parse(_)), "{err}");
        let err = Policy::from_json(r#"{"version":1,"limits":{"per_second":1}}"#).unwrap_err();
        assert!(matches!(err, PolicyError::Parse(_)));
    }

    #[test]
    fn semantic_validation() {
        assert!(Policy::from_toml("version = 2").is_err());
        assert!(Policy::from_toml("[approval]\nmode = \"paths\"").is_err());
        assert!(Policy::from_toml("[approval]\ntimeout_seconds = 0").is_err());
        assert!(Policy::from_toml("upstreams = [\"https://x\"]").is_err());
        assert!(Policy::from_toml(
            "[schedule]\ntimezone = \"Mars/Olympus\"\nallowed = [\"Mon 09:00-10:00\"]"
        )
        .is_err());
        assert!(Policy::from_toml("allow = [\"FETCH /x\"]").is_err());
        assert!(Policy::from_toml("expires_at = \"tomorrow\"").is_err());
    }

    #[test]
    fn defaults() {
        let p = Policy::from_toml("").unwrap();
        assert_eq!(p, Policy::default());
        assert!(p.mcp);
        assert!(!p.injection);
        assert_eq!(p.approval.timeout_seconds, 120);
    }
}
