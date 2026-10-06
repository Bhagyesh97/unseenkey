//! Handles: the strings that stand in for secrets.
//!
//! `usk_h_` + 32 base62 characters (about 190 bits). The vault stores only a
//! domain-separated BLAKE3 hash of the string, so a stolen vault file yields
//! no usable handles, and a leaked handle is useless without a registered
//! caller and a policy that allows the request (D-06).

use crate::crypto::hash::{handle_hash, Digest};
use crate::crypto::random_base62;
use crate::ids::Id;
use crate::policy::Policy;
use serde::{Deserialize, Serialize};

/// Canonical prefix.
pub const PREFIX: &str = "usk_h_";
/// Characters after the prefix.
pub const BODY_LEN: usize = 32;

/// A fresh canonical handle string.
pub fn generate() -> String {
    format!("{PREFIX}{}", random_base62(BODY_LEN))
}

/// Cheap shape check before hashing.
pub fn is_handle_shaped(s: &str) -> bool {
    s.len() == PREFIX.len() + BODY_LEN
        && s.starts_with(PREFIX)
        && s[PREFIX.len()..].bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The marker every handle carries, canonical or camouflaged.
pub const MARKER: &str = "usk";
/// Fewest random characters a camouflage format may have (base62, about 131 bits).
pub const MIN_RANDOM: usize = 22;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Literal(String),
    Random(usize),
}

/// A camouflage handle format (D-26): literal text with `{N}` runs of N random
/// base62 characters, for example `sk-usk-{32}`. Some tools refuse a key that
/// does not look like the provider's; a handle in this shape gets past the
/// check and is still only a handle. The literal part must contain the
/// [`MARKER`] so a person or a scanner can tell it from a real key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Format {
    parts: Vec<Part>,
}

impl Format {
    /// Parse and validate a format.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut parts: Vec<Part> = Vec::new();
        let mut literal = String::new();
        let mut chars = spec.chars();
        while let Some(c) = chars.next() {
            if c == '{' {
                let mut digits = String::new();
                let mut closed = false;
                for d in chars.by_ref() {
                    if d == '}' {
                        closed = true;
                        break;
                    }
                    digits.push(d);
                }
                if !closed {
                    return Err(format!("unterminated placeholder in {spec:?}"));
                }
                let n: usize = digits
                    .parse()
                    .map_err(|_| format!("bad placeholder {{{digits}}} in {spec:?}"))?;
                if n == 0 || n > 128 {
                    return Err(format!("placeholder length {n} out of range in {spec:?}"));
                }
                if !literal.is_empty() {
                    parts.push(Part::Literal(core::mem::take(&mut literal)));
                } else if matches!(parts.last(), Some(Part::Random(_))) {
                    return Err(format!("adjacent placeholders in {spec:?}"));
                }
                parts.push(Part::Random(n));
            } else if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                literal.push(c);
            } else {
                return Err(format!("character {c:?} not allowed in {spec:?}"));
            }
        }
        if !literal.is_empty() {
            parts.push(Part::Literal(literal));
        }
        let format = Self { parts };
        let fixed: String = format
            .parts
            .iter()
            .filter_map(|p| match p {
                Part::Literal(l) => Some(l.as_str()),
                Part::Random(_) => None,
            })
            .collect();
        if !fixed.contains(MARKER) {
            return Err(format!("{spec:?} lacks the {MARKER:?} marker"));
        }
        if format.random_len() < MIN_RANDOM {
            return Err(format!(
                "{spec:?} has fewer than {MIN_RANDOM} random characters"
            ));
        }
        Ok(format)
    }

    fn random_len(&self) -> usize {
        self.parts
            .iter()
            .map(|p| match p {
                Part::Random(n) => *n,
                Part::Literal(_) => 0,
            })
            .sum()
    }

    /// A fresh handle string in this format.
    pub fn generate(&self) -> String {
        self.parts
            .iter()
            .map(|p| match p {
                Part::Literal(l) => l.clone(),
                Part::Random(n) => random_base62(*n),
            })
            .collect()
    }

    /// Does `s` have exactly this shape?
    pub fn matches(&self, s: &str) -> bool {
        let mut rest = s;
        for part in &self.parts {
            match part {
                Part::Literal(l) => match rest.strip_prefix(l.as_str()) {
                    Some(r) => rest = r,
                    None => return false,
                },
                Part::Random(n) => {
                    if rest.len() < *n
                        || !rest.is_char_boundary(*n)
                        || !rest[..*n].bytes().all(|b| b.is_ascii_alphanumeric())
                    {
                        return false;
                    }
                    rest = &rest[*n..];
                }
            }
        }
        rest.is_empty()
    }
}

/// Lookup key for a handle string.
pub fn hash_of(handle: &str) -> Digest {
    handle_hash(handle.as_bytes())
}

/// What the vault stores about a handle (encrypted record, kind `Handle`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleRecord {
    /// Record id.
    pub handle_id: Id,
    /// Hex BLAKE3 of the handle string. The string itself is never stored.
    pub handle_hash: String,
    /// Secret the handle resolves to.
    pub secret_id: Id,
    /// Human label, e.g. `cursor on laptop`.
    pub label: String,
    /// Policy applied to every use.
    pub policy: Policy,
    /// Unix milliseconds.
    pub created_at: i64,
    /// Hard expiry (also enforced via `policy.expires_at`).
    pub expires_at: Option<i64>,
    /// When revoked, if ever.
    pub revoked_at: Option<i64>,
    /// Uses recorded so far (persisted lazily).
    #[serde(default)]
    pub use_count: u64,
    /// Last use, if any.
    #[serde(default)]
    pub last_used_at: Option<i64>,
    /// Rules the owner approved with "allow always" (for example
    /// `POST /v1/refunds`). Cleared whenever the policy is replaced.
    #[serde(default)]
    pub remembered: Vec<String>,
}

impl HandleRecord {
    /// Usable at `now`?
    pub fn is_active(&self, now_unix_ms: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|e| now_unix_ms < e)
    }

    /// Hash as bytes.
    pub fn hash_bytes(&self) -> Option<Digest> {
        let v = hex::decode(&self.handle_hash).ok()?;
        v.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_and_hash() {
        let h = generate();
        assert!(is_handle_shaped(&h));
        assert_ne!(generate(), h);
        assert!(!is_handle_shaped("usk_h_short"));
        assert!(!is_handle_shaped(&format!("usk_s_{}", "a".repeat(32))));
        assert!(!is_handle_shaped(&format!("usk_h_{}", "-".repeat(32))));
        assert_eq!(hash_of(&h), hash_of(&h));
        assert_ne!(hash_of(&h), hash_of(&generate()));
    }

    #[test]
    fn camouflage_formats() {
        let f = Format::parse("sk-usk-{32}").unwrap();
        let h = f.generate();
        assert_eq!(h.len(), 7 + 32);
        assert!(h.starts_with("sk-usk-"));
        assert!(f.matches(&h));
        assert_ne!(f.generate(), h);
        assert!(!f.matches(&h[..h.len() - 1]));
        assert!(!f.matches(&format!("{h}x")));
        assert!(!f.matches(&h.replace("sk-usk-", "sk-abc-")));
        assert!(!f.matches(&format!("sk-usk-{}", "-".repeat(32))));
        assert!(!f.matches("sk-usk-éééééééééééééééééééééééééééééééé"));
        // Several random runs with literals between them.
        let g = Format::parse("SG.usk{19}.{43}").unwrap();
        let h = g.generate();
        assert_eq!(h.len(), 3 + 3 + 19 + 1 + 43);
        assert!(g.matches(&h) && !f.matches(&h));
        // Refused: no marker, too little randomness, odd characters, bad placeholders.
        for bad in [
            "sk-{40}",
            "sk-usk-{21}",
            "sk usk {32}",
            "sk-usk-{}",
            "sk-usk-{0}",
            "sk-usk-{999}",
            "sk-usk-{16}{16}",
            "sk-usk-{32",
            "{usk}{32}",
        ] {
            assert!(Format::parse(bad).is_err(), "{bad}");
        }
        // The marker has to be in the fixed text, where it survives every draw.
        assert!(Format::parse("usk{22}").is_ok());
    }

    #[test]
    fn activity() {
        let mut r = HandleRecord {
            handle_id: Id::new_v7(1),
            handle_hash: hex::encode([0u8; 32]),
            secret_id: Id::new_v7(2),
            label: "x".into(),
            policy: Policy::default(),
            created_at: 0,
            expires_at: Some(100),
            revoked_at: None,
            use_count: 0,
            last_used_at: None,
            remembered: Vec::new(),
        };
        assert!(r.is_active(99));
        assert!(!r.is_active(100));
        r.expires_at = None;
        r.revoked_at = Some(5);
        assert!(!r.is_active(0));
        assert_eq!(r.hash_bytes(), Some([0u8; 32]));
    }
}
