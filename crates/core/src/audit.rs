//! Tamper-evident audit log: append-only, hash-chained, bodies encrypted.
//!
//! Each row carries `prev_hash` (the previous row's `this_hash`) and
//! `this_hash = H(prev_hash ‖ seq ‖ ts ‖ kind ‖ nonce ‖ ciphertext)`, so the
//! chain can be verified without decrypting anything, even while the vault is
//! locked. Bodies are encrypted under an audit DEK derived from the vault key,
//! so a stolen file reveals only event kinds and timestamps.
//!
//! The chain alone cannot tell a log that was cut short (or rewritten from
//! some point on) from an honest one: the hash is unkeyed, so whoever can
//! write the file can recompute it. The vault therefore also keeps a **keyed
//! head**: with every append it stores `(seq, this_hash)` of the newest row
//! and `mac = BLAKE3_keyed(K_head, seq ‖ this_hash)`, where `K_head` is
//! derived from the vault key. Without the vault key nobody can produce a
//! head for a shorter or different log, so an unlocked `verify` catches
//! truncation and rewrites as well as edits.

use crate::crypto::hash::{blake3_keyed, digest_eq, Digest};
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

/// The keyed head: which row is the newest, authenticated under a key only
/// the unlocked vault has. Stored next to the log and replaced on every append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditHead {
    /// `seq` of the newest row.
    pub seq: u64,
    /// `this_hash` of the newest row.
    pub hash: Digest,
    /// [`head_mac`] over `seq` and `hash`.
    pub mac: Digest,
}

/// MAC over a head. `key` is `HKDF(VK, "usk/audit-head/v1")`.
pub fn head_mac(key: &[u8; 32], seq: u64, hash: &Digest) -> Digest {
    let mut data = [0u8; 8 + 32];
    data[..8].copy_from_slice(&seq.to_be_bytes());
    data[8..].copy_from_slice(hash);
    blake3_keyed(key, &data)
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
    /// A request needed approval and one was requested.
    pub const APPROVAL_REQUIRED: &str = "approval_required";
    /// An approval was allowed, denied or timed out.
    pub const APPROVAL_DECIDED: &str = "approval_decided";
    /// An MCP client asked for access via `request_access`.
    pub const ACCESS_REQUESTED: &str = "access_requested";
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
    /// A device unlock method (Windows Hello, Touch ID) was enrolled.
    pub const UNLOCK_METHOD_ADDED: &str = "unlock_method_added";
    /// A device unlock method was removed.
    pub const UNLOCK_METHOD_REMOVED: &str = "unlock_method_removed";
    /// Remembered ("allow always") approvals were cleared for a handle.
    pub const APPROVAL_FORGOTTEN: &str = "approval_forgotten";
    /// A handle behaved unusually (`kind`, `detail`, `response`).
    pub const ANOMALY: &str = "anomaly";
    /// A canary handle was used: whoever did it has the file it was planted in.
    pub const CANARY_TRIPPED: &str = "canary_tripped";
    /// The owner put a handle back to normal after an incident.
    pub const HANDLE_RESUMED: &str = "handle_resumed";
    /// A stored key was tested with one read-only request to its provider.
    pub const KEY_TESTED: &str = "key_tested";
    /// A project was created.
    pub const PROJECT_CREATED: &str = "project_created";
    /// A project's name, folders, limit, notes or secrets changed.
    pub const PROJECT_CHANGED: &str = "project_changed";
    /// A project was deleted (its secrets and handles stay).
    pub const PROJECT_DELETED: &str = "project_deleted";
    /// On unlock, the keyed head did not match the log (`state`, `head_seq`,
    /// `last_seq`): the log was cut short or rewritten while locked. Recorded
    /// as an event because the next append replaces the head.
    pub const AUDIT_TAMPERED: &str = "audit_tampered";
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

/// What the keyed head said about the log's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HeadStatus {
    /// The vault is locked, so the head key could not be derived. The chain
    /// was checked; truncation cannot be ruled out.
    Unchecked,
    /// No head is stored: the log predates keyed heads and nothing has been
    /// appended since. The chain was checked; truncation cannot be ruled out.
    Missing,
    /// The head authenticates and names the newest row.
    Verified,
    /// The stored head does not authenticate under the vault key: the header
    /// was rewritten without the key.
    Forged,
    /// The head authenticates but the log's newest row is not the one it
    /// names: rows were removed after `head_seq`, the newest row was
    /// rewritten, or rows were appended without the key.
    Mismatch {
        /// `seq` the head names.
        head_seq: u64,
        /// `seq` of the newest row actually present (0 for an empty log).
        last_seq: u64,
    },
}

/// Result of walking the chain and checking the head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyReport {
    /// Rows examined.
    pub rows: u64,
    /// First sequence number whose hash or linkage is wrong, if any.
    pub first_broken: Option<u64>,
    /// Whether the sequence numbers were contiguous from 1.
    pub contiguous: bool,
    /// What the keyed head said.
    pub head: HeadStatus,
}

impl VerifyReport {
    /// True if nothing is wrong. A head that could not be checked
    /// ([`HeadStatus::Unchecked`], [`HeadStatus::Missing`]) is not wrong, only
    /// weaker; see [`VerifyReport::head_checked`].
    pub fn ok(&self) -> bool {
        self.first_broken.is_none()
            && self.contiguous
            && matches!(
                self.head,
                HeadStatus::Unchecked | HeadStatus::Missing | HeadStatus::Verified
            )
    }

    /// True if the keyed head was available and authenticated, so a cut-short
    /// or rewritten log would have been noticed.
    pub fn head_checked(&self) -> bool {
        self.head == HeadStatus::Verified
    }
}

/// Verify rows in order. `rows` must be the complete log from `seq == 1`.
/// Checks the chain only; the head is reported as [`HeadStatus::Unchecked`]
/// until [`check_head`] runs.
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
                head: HeadStatus::Unchecked,
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
                head: HeadStatus::Unchecked,
            };
        }
        prev = row.this_hash;
    }
    VerifyReport {
        rows: rows.len() as u64,
        first_broken: None,
        contiguous,
        head: HeadStatus::Unchecked,
    }
}

/// Check the stored head against the newest row, given the head key.
pub fn check_head(key: &[u8; 32], head: Option<&AuditHead>, last: Option<&AuditRow>) -> HeadStatus {
    let Some(head) = head else {
        return HeadStatus::Missing;
    };
    if !digest_eq(&head.mac, &head_mac(key, head.seq, &head.hash)) {
        return HeadStatus::Forged;
    }
    match last {
        Some(row) if row.seq == head.seq && digest_eq(&row.this_hash, &head.hash) => {
            HeadStatus::Verified
        }
        _ => HeadStatus::Mismatch {
            head_seq: head.seq,
            last_seq: last.map(|r| r.seq).unwrap_or(0),
        },
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
            "truncation is caught by the keyed head, not the chain"
        );
    }

    #[test]
    fn keyed_head_catches_what_the_chain_cannot() {
        let vid = Id::new_v7(1);
        let mut rows = Vec::new();
        let mut prev = genesis(&vid);
        for seq in 1..=5 {
            let r = row(&prev, seq);
            prev = r.this_hash;
            rows.push(r);
        }
        let key = [9u8; 32];
        let last = rows.last().unwrap();
        let head = AuditHead {
            seq: last.seq,
            hash: last.this_hash,
            mac: head_mac(&key, last.seq, &last.this_hash),
        };
        assert_eq!(
            check_head(&key, Some(&head), Some(last)),
            HeadStatus::Verified
        );

        // Cut the log short: the chain is fine, the head is not.
        assert!(verify(&vid, &rows[..3]).ok());
        assert_eq!(
            check_head(&key, Some(&head), rows[..3].last()),
            HeadStatus::Mismatch {
                head_seq: 5,
                last_seq: 3
            }
        );
        assert_eq!(
            check_head(&key, Some(&head), None),
            HeadStatus::Mismatch {
                head_seq: 5,
                last_seq: 0
            }
        );
        // Rewrite the tail with the right shape but no key: the recomputed
        // hash no longer matches the head.
        let mut rewritten = rows.clone();
        rewritten[4].ts += 1;
        rewritten[4].this_hash = chain_hash(
            &rewritten[3].this_hash,
            5,
            rewritten[4].ts,
            &rewritten[4].kind,
            &rewritten[4].nonce,
            &rewritten[4].ciphertext,
        );
        assert!(verify(&vid, &rewritten).ok());
        assert!(matches!(
            check_head(&key, Some(&head), rewritten.last()),
            HeadStatus::Mismatch {
                head_seq: 5,
                last_seq: 5
            }
        ));
        // A head written without the key, or edited, is forged.
        let mut forged = head.clone();
        forged.seq = 3;
        forged.hash = rows[2].this_hash;
        assert_eq!(
            check_head(&key, Some(&forged), rows[..3].last()),
            HeadStatus::Forged
        );
        assert_eq!(
            check_head(&[1u8; 32], Some(&head), Some(last)),
            HeadStatus::Forged
        );
        // No head at all is reported, not failed.
        assert_eq!(check_head(&key, None, Some(last)), HeadStatus::Missing);

        let mut report = verify(&vid, &rows);
        assert!(report.ok() && !report.head_checked());
        report.head = HeadStatus::Verified;
        assert!(report.ok() && report.head_checked());
        report.head = HeadStatus::Forged;
        assert!(!report.ok());
    }
}
