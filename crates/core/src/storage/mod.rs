//! Pluggable, ciphertext-only storage for the vault.
//!
//! A backend stores the vault header and versioned encrypted records. It never
//! sees plaintext or keys: everything sensitive arrives already sealed by
//! [`crate::vault`]. Backends are therefore not security boundaries, and a
//! vault file may be copied, synced or backed up by any means.

use crate::audit::AuditRow;
use crate::crypto::aead::Sealed;
use crate::crypto::kdf::Argon2Profile;
use crate::ids::Id;
use alloc::string::String;
use alloc::vec::Vec;

pub mod memory;
#[cfg(feature = "sqlite")]
pub mod sqlite;

/// What a record holds. Stored in cleartext so backends can filter without decrypting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// A secret's value (and multi-field values).
    Secret,
    /// A secret's metadata: name, provider, upstreams, tags.
    SecretMeta,
    /// A policy document.
    Policy,
    /// A handle bound to a secret and policy.
    Handle,
    /// A delegation grant.
    Grant,
    /// A registered caller (MCP client, device, process).
    Caller,
    /// A vault-level setting.
    Setting,
}

impl RecordKind {
    /// Stable string form used by backends.
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordKind::Secret => "secret",
            RecordKind::SecretMeta => "secret_meta",
            RecordKind::Policy => "policy",
            RecordKind::Handle => "handle",
            RecordKind::Grant => "grant",
            RecordKind::Caller => "caller",
            RecordKind::Setting => "setting",
        }
    }

    /// Parse the string form.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "secret" => RecordKind::Secret,
            "secret_meta" => RecordKind::SecretMeta,
            "policy" => RecordKind::Policy,
            "handle" => RecordKind::Handle,
            "grant" => RecordKind::Grant,
            "caller" => RecordKind::Caller,
            "setting" => RecordKind::Setting,
            _ => return None,
        })
    }
}

/// One version of one record, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    /// Record identity; all versions share it.
    pub record_id: Id,
    /// Kind, cleartext.
    pub kind: RecordKind,
    /// Monotonically increasing per record, starting at 1.
    pub version: u64,
    /// AEAD nonce.
    pub nonce: [u8; 24],
    /// AEAD ciphertext including tag. Empty for tombstones.
    pub ciphertext: Vec<u8>,
    /// Unix milliseconds when this version was written.
    pub updated_at: i64,
    /// Tombstone marker; a deleted record's latest version has this set.
    pub deleted: bool,
}

/// The vault header: everything needed to unlock, none of it secret on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderRow {
    /// Vault identity, bound into every record's AAD.
    pub vault_id: Id,
    /// On-disk format version; readers refuse newer formats.
    pub format_version: u32,
    /// Argon2id parameters for the password wrap.
    pub argon2: Argon2Profile,
    /// Salt for the password KDF.
    pub salt_pw: [u8; 16],
    /// Vault key wrapped under the password-derived KEK.
    pub wrapped_vk_pw: Sealed,
    /// Vault key wrapped under the recovery-kit KEK, if a kit was issued.
    pub wrapped_vk_rec: Option<Sealed>,
    /// Unix milliseconds of creation.
    pub created_at: i64,
}

/// Backend failures. Messages never contain record contents.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StorageError {
    /// A version at or below the latest was submitted for an existing record.
    #[error("version conflict on record {record_id} (submitted {version})")]
    Conflict {
        /// Record whose version was rejected.
        record_id: Id,
        /// The rejected version.
        version: u64,
    },
    /// Stored data could not be interpreted.
    #[error("corrupt storage: {0}")]
    Corrupt(String),
    /// The backend itself failed (I/O, SQL).
    #[error("storage backend error: {0}")]
    Backend(String),
    /// An audit row was appended out of order.
    #[error("audit sequence error: expected {expected}, got {got}")]
    AuditSequence {
        /// Next sequence number the log expected.
        expected: u64,
        /// Sequence number that was submitted.
        got: u64,
    },
}

/// A vault storage backend.
pub trait Storage {
    /// Read the header, or `None` if the store is empty.
    fn load_header(&self) -> Result<Option<HeaderRow>, StorageError>;
    /// Write (or replace) the header.
    fn save_header(&mut self, header: &HeaderRow) -> Result<(), StorageError>;
    /// Append a new version of a record. Fails with [`StorageError::Conflict`]
    /// unless `record.version` is greater than every stored version of that record.
    fn insert_record(&mut self, record: &StoredRecord) -> Result<(), StorageError>;
    /// The latest version of a record, tombstones included.
    fn latest_record(&self, record_id: &Id) -> Result<Option<StoredRecord>, StorageError>;
    /// A specific version of a record.
    fn record_version(
        &self,
        record_id: &Id,
        version: u64,
    ) -> Result<Option<StoredRecord>, StorageError>;
    /// Latest version of every record, optionally filtered by kind and excluding tombstones.
    fn list_latest(
        &self,
        kind: Option<RecordKind>,
        include_deleted: bool,
    ) -> Result<Vec<StoredRecord>, StorageError>;

    /// Append an audit row. `row.seq` must be exactly one more than the last stored row
    /// (or 1 for an empty log), otherwise [`StorageError::AuditSequence`].
    fn append_audit(&mut self, row: &AuditRow) -> Result<(), StorageError>;
    /// The most recent audit row.
    fn audit_last(&self) -> Result<Option<AuditRow>, StorageError>;
    /// Audit rows with `seq >= from_seq`, ascending, at most `limit`.
    fn audit_rows(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditRow>, StorageError>;
    /// Number of audit rows.
    fn audit_count(&self) -> Result<u64, StorageError>;
}
