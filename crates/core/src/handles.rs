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
