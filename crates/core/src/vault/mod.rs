//! The vault: encrypted, versioned secret storage with a key hierarchy.
//!
//! ```text
//! password ─Argon2id─▶ KEK_pw ─┐
//! recovery ─HKDF────▶ KEK_rec ─┤ each wraps ▶ Vault Key (VK)
//!                               │
//!            HKDF(VK, "usk/dek/<record>/<version>") ▶ per-record DEK
//!            XChaCha20-Poly1305(DEK, nonce, payload, aad = vault||record||version||kind)
//! ```
//!
//! Every secret is two records: its value ([`records::SecretPayload`]) and its
//! metadata ([`records::SecretMeta`]), so listing never decrypts values.

use crate::crypto::kdf::{self, Argon2Profile};
use crate::crypto::{CryptoError, SecretBytes};
use crate::ids::Id;
use crate::storage::{RecordKind, Storage, StorageError, StoredRecord};
use crate::time::Clock;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub mod header;
mod ops;
pub mod records;
pub mod recovery;

pub use records::{SecretKind, SecretMeta};
pub use recovery::RecoveryKit;

/// Vault-level failures. Never carry secret material.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The operation needs an unlocked vault.
    #[error("vault is locked")]
    Locked,
    /// The store has no header: no vault has been created there.
    #[error("no vault found")]
    NoVault,
    /// A vault already exists in this store.
    #[error("a vault already exists here")]
    AlreadyExists,
    /// Wrong password or recovery kit, or the header was tampered with.
    #[error("wrong password or recovery kit")]
    WrongCredential,
    /// The header's KDF parameters are below the accepted floor.
    #[error("vault key derivation parameters are too weak")]
    WeakKdf,
    /// The on-disk format is newer than this build understands.
    #[error("unsupported vault format version {0}; upgrade Unseenkey")]
    UnsupportedFormat(u32),
    /// No secret with that id.
    #[error("secret not found")]
    NotFound,
    /// A secret with that name already exists.
    #[error("a secret named {0:?} already exists")]
    NameExists(String),
    /// The name is empty or otherwise unusable.
    #[error("invalid secret name")]
    InvalidName,
    /// A record failed to decrypt or parse: corruption or tampering.
    #[error("record {0} is corrupt or was tampered with")]
    Corrupt(Id),
    /// No handle with that id or label.
    #[error("handle not found")]
    HandleNotFound,
    /// A handle with that label is already active.
    #[error("a handle labelled {0:?} already exists")]
    LabelExists(String),
    /// The policy's upstreams are not a subset of the secret's.
    #[error("policy upstreams must be within the secret's upstreams")]
    PolicyWidensHosts,
    /// The policy failed validation.
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    /// The recovery phrase could not be parsed.
    #[error("invalid recovery phrase")]
    Recovery,
    /// Storage failure.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// Cryptographic failure.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// A secret to add.
#[derive(Debug)]
pub struct NewSecret {
    /// Unique, human-chosen name such as `openai` or `stripe-live`.
    pub name: String,
    /// Type of secret.
    pub kind: SecretKind,
    /// The primary value.
    pub value: SecretBytes,
    /// Extra named values for multi-part secrets (client id/secret, key id/secret).
    pub fields: BTreeMap<String, SecretBytes>,
    /// Provider preset id, if known.
    pub provider: Option<String>,
    /// Hosts this secret may be sent to. Empty means "not yet locked" and is flagged in UIs.
    pub upstreams: Vec<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Free-form notes.
    pub notes: Option<String>,
}

/// A decrypted secret, returned only by explicit reveal calls.
#[derive(Debug)]
pub struct Revealed {
    /// The primary value.
    pub value: SecretBytes,
    /// Extra named values.
    pub fields: BTreeMap<String, SecretBytes>,
}

/// An open vault over some storage. Locked until a credential unwraps the vault key.
pub struct Vault<S: Storage, C: Clock> {
    storage: S,
    clock: C,
    header: crate::storage::HeaderRow,
    vk: Option<SecretBytes>,
    /// Decrypted metadata index, rebuilt on unlock.
    index: BTreeMap<Id, SecretMeta>,
    /// Decrypted handles, rebuilt on unlock.
    handles: BTreeMap<Id, crate::handles::HandleRecord>,
    /// Handle hash → handle id.
    handle_hashes: BTreeMap<crate::crypto::hash::Digest, Id>,
    /// Use counts as last persisted, per handle.
    handle_counters_flushed: BTreeMap<Id, u64>,
}

impl<S: Storage, C: Clock> core::fmt::Debug for Vault<S, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("vault_id", &self.header.vault_id)
            .field("locked", &self.vk.is_none())
            .field("secrets", &self.index.len())
            .finish()
    }
}

impl<S: Storage, C: Clock> Vault<S, C> {
    /// Create a new vault in empty storage. Returns the unlocked vault and the
    /// recovery kit, which must be shown to the user exactly once.
    pub fn create(
        mut storage: S,
        clock: C,
        password: &SecretBytes,
        profile: Argon2Profile,
    ) -> Result<(Self, RecoveryKit), VaultError> {
        if storage.load_header()?.is_some() {
            return Err(VaultError::AlreadyExists);
        }
        if !profile.is_acceptable() {
            return Err(VaultError::WeakKdf);
        }
        let now = clock.now_unix_ms();
        let vault_id = Id::new_v7(now);
        let vk = SecretBytes::random(crate::crypto::aead::KEY_LEN);
        let kit = RecoveryKit::generate();
        let hdr = header::build(&vault_id, &vk, password, profile, &kit, now)?;
        storage.save_header(&hdr)?;
        Ok((
            Self {
                storage,
                clock,
                header: hdr,
                vk: Some(vk),
                index: BTreeMap::new(),
                handles: BTreeMap::new(),
                handle_hashes: BTreeMap::new(),
                handle_counters_flushed: BTreeMap::new(),
            },
            kit,
        ))
    }

    /// Open an existing vault (locked).
    pub fn open(storage: S, clock: C) -> Result<Self, VaultError> {
        let hdr = storage.load_header()?.ok_or(VaultError::NoVault)?;
        if hdr.format_version > header::FORMAT_VERSION {
            return Err(VaultError::UnsupportedFormat(hdr.format_version));
        }
        Ok(Self {
            storage,
            clock,
            header: hdr,
            vk: None,
            index: BTreeMap::new(),
            handles: BTreeMap::new(),
            handle_hashes: BTreeMap::new(),
            handle_counters_flushed: BTreeMap::new(),
        })
    }

    /// The vault's identity.
    pub fn vault_id(&self) -> Id {
        self.header.vault_id
    }

    /// True until a credential has unwrapped the vault key.
    pub fn is_locked(&self) -> bool {
        self.vk.is_none()
    }

    /// Argon2 parameters in use.
    pub fn argon2_profile(&self) -> Argon2Profile {
        self.header.argon2
    }

    /// Re-read the header from storage. A long-running daemon calls this before
    /// each unlock so a password reset done by another process (e.g. `usk recover`)
    /// takes effect without a restart.
    pub fn reload_header(&mut self) -> Result<(), VaultError> {
        let hdr = self.storage.load_header()?.ok_or(VaultError::NoVault)?;
        if hdr.format_version > header::FORMAT_VERSION {
            return Err(VaultError::UnsupportedFormat(hdr.format_version));
        }
        self.header = hdr;
        Ok(())
    }

    /// Unlock with the password.
    pub fn unlock_with_password(&mut self, password: &SecretBytes) -> Result<(), VaultError> {
        if !self.header.argon2.is_acceptable() {
            return Err(VaultError::WeakKdf);
        }
        let kek = kdf::derive_password_key(password, &self.header.salt_pw, self.header.argon2)?;
        let vk = header::unwrap_vk(
            &kek,
            &self.header.wrapped_vk_pw,
            header::KekKind::Password,
            &self.header.vault_id,
        )?;
        self.finish_unlock(vk)
    }

    /// Unlock with the recovery phrase.
    pub fn unlock_with_recovery(&mut self, phrase: &str) -> Result<(), VaultError> {
        let wrapped = self
            .header
            .wrapped_vk_rec
            .as_ref()
            .ok_or(VaultError::WrongCredential)?;
        let kit = RecoveryKit::parse(phrase).map_err(|_| VaultError::Recovery)?;
        let vk = header::unwrap_vk(
            &kit.kek(),
            wrapped,
            header::KekKind::Recovery,
            &self.header.vault_id,
        )?;
        self.finish_unlock(vk)
    }

    fn finish_unlock(&mut self, vk: SecretBytes) -> Result<(), VaultError> {
        let index = self.build_index(&vk)?;
        let (handles, hashes) = self.build_handle_index(&vk)?;
        self.handle_counters_flushed = handles.iter().map(|(id, h)| (*id, h.use_count)).collect();
        self.vk = Some(vk);
        self.index = index;
        self.handles = handles;
        self.handle_hashes = hashes;
        Ok(())
    }

    /// Forget the vault key and the decrypted index.
    pub fn lock(&mut self) {
        let _ = self.flush_handle_counters();
        self.vk = None;
        self.index.clear();
        self.handles.clear();
        self.handle_hashes.clear();
        self.handle_counters_flushed.clear();
    }

    /// Re-wrap the vault key under a new password. Requires an unlocked vault.
    pub fn change_password(
        &mut self,
        new_password: &SecretBytes,
        profile: Argon2Profile,
    ) -> Result<(), VaultError> {
        let vk = self.vk.as_ref().ok_or(VaultError::Locked)?;
        if !profile.is_acceptable() {
            return Err(VaultError::WeakKdf);
        }
        let (salt, wrapped) =
            header::wrap_password(&self.header.vault_id, vk, new_password, profile)?;
        self.header.salt_pw = salt;
        self.header.argon2 = profile;
        self.header.wrapped_vk_pw = wrapped;
        self.storage.save_header(&self.header)?;
        Ok(())
    }

    fn vk(&self) -> Result<&SecretBytes, VaultError> {
        self.vk.as_ref().ok_or(VaultError::Locked)
    }

    fn build_index(&self, vk: &SecretBytes) -> Result<BTreeMap<Id, SecretMeta>, VaultError> {
        let mut index = BTreeMap::new();
        for rec in self
            .storage
            .list_latest(Some(RecordKind::SecretMeta), false)?
        {
            let meta: SecretMeta = records::decrypt_json(vk, &self.header.vault_id, &rec)
                .map_err(|_| VaultError::Corrupt(rec.record_id))?;
            index.insert(meta.secret_id, meta);
        }
        Ok(index)
    }

    /// All secrets' metadata, sorted by name. Never values.
    pub fn list(&self) -> Result<Vec<&SecretMeta>, VaultError> {
        self.vk()?;
        let mut v: Vec<&SecretMeta> = self.index.values().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(v)
    }

    /// Metadata by id.
    pub fn get(&self, id: &Id) -> Result<&SecretMeta, VaultError> {
        self.vk()?;
        self.index.get(id).ok_or(VaultError::NotFound)
    }

    /// Metadata by name (exact match).
    pub fn get_by_name(&self, name: &str) -> Result<&SecretMeta, VaultError> {
        self.vk()?;
        self.index
            .values()
            .find(|m| m.name == name)
            .ok_or(VaultError::NotFound)
    }

    /// Add a secret. Names must be unique.
    pub fn add(&mut self, new: NewSecret) -> Result<Id, VaultError> {
        let vk = self.vk()?.clone();
        let name = new.name.trim();
        if name.is_empty() || name.len() > 128 {
            return Err(VaultError::InvalidName);
        }
        if self.index.values().any(|m| m.name == name) {
            return Err(VaultError::NameExists(name.into()));
        }
        let now = self.clock.now_unix_ms();
        let secret_id = Id::new_v7(now);
        let payload = records::SecretPayload::new(secret_id, new.kind, new.value, new.fields, now);
        let meta = SecretMeta {
            secret_id,
            name: name.into(),
            kind: new.kind,
            provider: new.provider,
            tags: new.tags,
            upstreams: new.upstreams,
            notes: new.notes,
            no_scrub: false,
            allow_injection: false,
            created_at: now,
            updated_at: now,
            value_version: 1,
        };
        let value_rec = records::encrypt_json(
            &vk,
            &self.header.vault_id,
            secret_id,
            RecordKind::Secret,
            1,
            &payload,
            now,
        )?;
        let meta_rec = records::encrypt_json(
            &vk,
            &self.header.vault_id,
            records::meta_record_id(&secret_id),
            RecordKind::SecretMeta,
            1,
            &meta,
            now,
        )?;
        self.storage.insert_record(&value_rec)?;
        self.storage.insert_record(&meta_rec)?;
        self.index.insert(secret_id, meta);
        Ok(secret_id)
    }

    /// Decrypt a secret's value. Callers must audit this (M1.4) and never log the result.
    pub fn reveal(&self, id: &Id) -> Result<Revealed, VaultError> {
        let vk = self.vk()?;
        let meta = self.index.get(id).ok_or(VaultError::NotFound)?;
        let rec = self
            .storage
            .record_version(id, meta.value_version)?
            .ok_or(VaultError::NotFound)?;
        let payload: records::SecretPayload =
            records::decrypt_json(vk, &self.header.vault_id, &rec)
                .map_err(|_| VaultError::Corrupt(*id))?;
        Ok(payload.into_revealed())
    }

    /// Store a new version of a secret's value.
    pub fn update_value(
        &mut self,
        id: &Id,
        value: SecretBytes,
        fields: BTreeMap<String, SecretBytes>,
    ) -> Result<u64, VaultError> {
        let vk = self.vk()?.clone();
        let meta = self.index.get(id).ok_or(VaultError::NotFound)?.clone();
        let now = self.clock.now_unix_ms();
        let next = meta.value_version + 1;
        let payload = records::SecretPayload::new(*id, meta.kind, value, fields, now);
        let rec = records::encrypt_json(
            &vk,
            &self.header.vault_id,
            *id,
            RecordKind::Secret,
            next,
            &payload,
            now,
        )?;
        self.storage.insert_record(&rec)?;
        let mut updated = meta;
        updated.value_version = next;
        updated.updated_at = now;
        self.write_meta(&vk, updated)?;
        Ok(next)
    }

    /// Modify metadata (name, tags, upstreams, flags). The closure edits a copy;
    /// the result is validated and written as a new version.
    pub fn update_meta(
        &mut self,
        id: &Id,
        edit: impl FnOnce(&mut SecretMeta),
    ) -> Result<(), VaultError> {
        let vk = self.vk()?.clone();
        let mut meta = self.index.get(id).ok_or(VaultError::NotFound)?.clone();
        edit(&mut meta);
        meta.secret_id = *id;
        let name = meta.name.trim();
        if name.is_empty() || name.len() > 128 {
            return Err(VaultError::InvalidName);
        }
        if self
            .index
            .values()
            .any(|m| m.secret_id != *id && m.name == name)
        {
            return Err(VaultError::NameExists(name.into()));
        }
        meta.name = name.into();
        meta.updated_at = self.clock.now_unix_ms();
        self.write_meta(&vk, meta)
    }

    fn write_meta(&mut self, vk: &SecretBytes, meta: SecretMeta) -> Result<(), VaultError> {
        let rid = records::meta_record_id(&meta.secret_id);
        let version = self
            .storage
            .latest_record(&rid)?
            .map(|r| r.version + 1)
            .unwrap_or(1);
        let rec = records::encrypt_json(
            vk,
            &self.header.vault_id,
            rid,
            RecordKind::SecretMeta,
            version,
            &meta,
            meta.updated_at,
        )?;
        self.storage.insert_record(&rec)?;
        self.index.insert(meta.secret_id, meta);
        Ok(())
    }

    /// Delete a secret: tombstone both records and drop it from the index.
    pub fn delete(&mut self, id: &Id) -> Result<(), VaultError> {
        self.vk()?;
        if !self.index.contains_key(id) {
            return Err(VaultError::NotFound);
        }
        let now = self.clock.now_unix_ms();
        for rid in [*id, records::meta_record_id(id)] {
            let version = self
                .storage
                .latest_record(&rid)?
                .map(|r| r.version + 1)
                .unwrap_or(1);
            let kind = if rid == *id {
                RecordKind::Secret
            } else {
                RecordKind::SecretMeta
            };
            self.storage.insert_record(&StoredRecord {
                record_id: rid,
                kind,
                version,
                nonce: [0; 24],
                ciphertext: Vec::new(),
                updated_at: now,
                deleted: true,
            })?;
        }
        self.index.remove(id);
        Ok(())
    }

    /// Number of secrets.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// True if no secrets are stored (or the vault is locked).
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}
