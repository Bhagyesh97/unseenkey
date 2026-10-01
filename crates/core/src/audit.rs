//! Tamper-evident audit log: append-only, hash-chained, bodies encrypted.
//!
//! Each row carries `prev_hash` (the previous row's `this_hash`) and
//! `this_hash = H(prev_hash ‖ seq ‖ ts ‖ kind ‖ nonce ‖ ciphertext)`, so the
//! chain can be verified without decrypting anything, even while the vault is
//! locked. Bodies are encrypted under an audit DEK derived from the vault key,
//! so a stolen file reveals only event kinds and timestamps.

use crate::crypto::hash::{digest_eq, Digest};
use crate::ids::Id;
use serde::{Deserialize, Serialize};

/// Stored form of one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    /// 1-based, contiguous.
    pub seq: u64,
    /// Unix milliseconds.
    pub ts: i64,
    /// Event kind, cleartext.
    pub kind: String,
    /// Previous row's `this_hash`, or the genesis hash for `seq == 1`.
    pub prev_hash: Digest,
    /// Chain hash of this row.
    pub this_hash: Digest,
    /// AEAD nonce for the body.
    pub nonce: [u8; 24],
    /// Encrypted JSON body.
    pub ciphertext: Vec<u8>,
    /// Broker signature over `this_hash` (delegation mode; unused locally).
    pub signature: Option<Vec<u8>>,
}

/// A decrypted event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Sequence number.
    pub seq: u64,
    /// Unix milliseconds.
    pub ts: i64,
    /// Kind.
    pub kind: String,
    /// Body (never contains secret values).
    pub body: serde_json::Value,
}

/// Event kinds written by the daemon and CLI. Kept as constants so audit
/// consumers can filter without typos.
pub mod kinds {
    /// A handle was used to reach an upstream.
    pub const USE: &str = "use";
    /// A request was refused by policy or limits.
    pub const DENY: &str = "deny";
    /// The egress guard blocked a request carrying another secret.
    pub const EGRESS_BLOCKED: &str = "egress_blocked";
    /// A request needed approval and none was available.
    pub const APPROVAL_REQUIRED: &str = "approval_required";
    /// A value was revealed to a human.
    pub const REVEAL: &str = "reveal";
    /// A value was injected into a process environment.
    pub const INJECT: &str = "inject";
    /// Vault unlocked.
    pub const UNLOCK: &str = "unlock";
    /// Vault locked.
    pub const LOCK: &str = "lock";
    /// Secret created.
    pub const SECRET_CREATED: &str = "secret_created";
    /// Secret value or metadata updated.
    pub const SECRET_UPDATED: &str = "secret_updated";
    /// Secret deleted.
    pub const SECRET_DELETED: &str = "secret_deleted";
    /// Handle created.
    pub const HANDLE_CREATED: &str = "handle_created";
    /// Handle revoked.
    pub const HANDLE_REVOKED: &str = "handle_revoked";
    /// A handle's policy changed.
    pub const POLICY_CHANGED: &str = "policy_changed";
}

/// Genesis `prev_hash` for a vault.
pub fn genesis(vault_id: &Id) -> Digest {
    let mut h = blake3::Hasher::new_derive_key("usk/audit-genesis/v1");
    h.update(vault_id.as_bytes());
    *h.finalize().as_bytes()
}

/// Chain hash of a row's contents.
pub fn chain_hash(
    prev_hash: &Digest,
    seq: u64,
    ts: i64,
    kind: &str,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Digest {
    let mut h = blake3::Hasher::new_derive_key("usk/audit-chain/v1");
    h.update(prev_hash);
    h.update(&seq.to_be_bytes());
    h.update(&ts.to_be_bytes());
    h.update(&(kind.len() as u32).to_be_bytes());
    h.update(kind.as_bytes());
    h.update(nonce);
    h.update(ciphertext);
    *h.finalize().as_bytes()
}

/// Result of walking the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    /// Rows examined.
    pub rows: u64,
    /// First sequence number whose hash or linkage is wrong, if any.
    pub first_broken: Option<u64>,
    /// Whether the sequence numbers were contiguous from 1.
    pub contiguous: bool,
}

impl VerifyReport {
    /// True if nothing is wrong.
    pub fn ok(&self) -> bool {
        self.first_broken.is_none() && self.contiguous
    }
}

/// Verify rows in order. `rows` must be the complete log from `seq == 1`.
pub fn verify(vault_id: &Id, rows: &[AuditRow]) -> VerifyReport {
    let mut prev = genesis(vault_id);
    let mut contiguous = true;
    for (i, row) in rows.iter().enumerate() {
        let expected_seq = i as u64 + 1;
        if row.seq != expected_seq {
            contiguous = false;
            return VerifyReport {
                rows: rows.len() as u64,
                first_broken: Some(row.seq),
                contiguous,
            };
        }
        let want = chain_hash(
            &prev,
            row.seq,
            row.ts,
            &row.kind,
            &row.nonce,
            &row.ciphertext,
        );
        if !digest_eq(&row.prev_hash, &prev) || !digest_eq(&row.this_hash, &want) {
            return VerifyReport {
                rows: rows.len() as u64,
                first_broken: Some(row.seq),
                contiguous,
            };
        }
        prev = row.this_hash;
    }
    VerifyReport {
        rows: rows.len() as u64,
        first_broken: None,
        contiguous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(prev: &Digest, seq: u64) -> AuditRow {
        let nonce = [seq as u8; 24];
        let ct = vec![1, 2, 3, seq as u8];
        let kind = "use".to_string();
        let this = chain_hash(prev, seq, 1000 + seq as i64, &kind, &nonce, &ct);
        AuditRow {
            seq,
            ts: 1000 + seq as i64,
            kind,
            prev_hash: *prev,
            this_hash: this,
            nonce,
            ciphertext: ct,
            signature: None,
        }
    }

    #[test]
    fn chain_verifies_and_detects_tampering() {
        let vid = Id::new_v7(1);
        let mut rows = Vec::new();
        let mut prev = genesis(&vid);
        for seq in 1..=5 {
            let r = row(&prev, seq);
            prev = r.this_hash;
            rows.push(r);
        }
        assert!(verify(&vid, &rows).ok());
        assert!(!verify(&Id::new_v7(2), &rows).ok(), "wrong vault genesis");

        let mut edited = rows.clone();
        edited[2].kind = "reveal".into();
        assert_eq!(verify(&vid, &edited).first_broken, Some(3));

        let mut edited = rows.clone();
        edited[3].ciphertext[0] ^= 1;
        assert_eq!(verify(&vid, &edited).first_broken, Some(4));

        let mut deleted = rows.clone();
        deleted.remove(1);
        let r = verify(&vid, &deleted);
        assert_eq!(r.first_broken, Some(3));
        assert!(!r.contiguous);

        let truncated = &rows[..3];
        assert!(
            verify(&vid, truncated).ok(),
            "truncation is caught by checkpoints, not the chain"
        );
    }
}
