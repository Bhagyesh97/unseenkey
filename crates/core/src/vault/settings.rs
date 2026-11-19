//! The owner's settings, kept as a record in the vault.
//!
//! How careful Unseenkey is, when it locks and whether AI tools may add keys
//! are the owner's to decide. A file next to the vault can be edited by any
//! program running as the user; a record under the vault key cannot be written
//! without the vault unlocked, and its absence can be told from the audit log.

use super::{records, Vault, VaultError};
use crate::audit::kinds;
use crate::ids::Id;
use crate::presets::Care;
use crate::storage::{RecordKind, Storage};
use crate::time::Clock;
use serde::{Deserialize, Serialize};

/// The longest idle lock that can be set, in minutes (a day). 0 means never.
pub const MAX_IDLE_LOCK_MINUTES: u64 = 24 * 60;

/// What only the owner may change. Stored as one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OwnerSettings {
    /// How careful the access Unseenkey hands out by itself is.
    pub care: Care,
    /// Lock after this many minutes without use; 0 means never.
    pub idle_lock_minutes: u64,
    /// Lock when the machine goes to sleep.
    pub lock_on_sleep: bool,
    /// Lock when the screen is locked.
    pub lock_on_session_lock: bool,
    /// Whether AI tools may add keys they come across (MCP `store_secret`).
    pub mcp_allow_store: bool,
}

impl Default for OwnerSettings {
    /// What a new vault starts with.
    fn default() -> Self {
        Self {
            care: Care::Balanced,
            idle_lock_minutes: 15,
            lock_on_sleep: true,
            lock_on_session_lock: true,
            mcp_allow_store: false,
        }
    }
}

impl OwnerSettings {
    /// What applies when the stored settings cannot be trusted: nothing here
    /// is looser than anything the owner could have chosen, except the idle
    /// time, which stays at its default.
    pub fn cautious() -> Self {
        Self {
            care: Care::Strict,
            ..Self::default()
        }
    }

    /// The same settings with the idle lock inside its range.
    pub fn clamped(mut self) -> Self {
        self.idle_lock_minutes = self.idle_lock_minutes.min(MAX_IDLE_LOCK_MINUTES);
        self
    }

    fn json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Where the settings in force after an unlock came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsOrigin {
    /// The vault's own record.
    Stored,
    /// The vault had none yet (it is new, or from before settings were kept
    /// in it): the values the daemon was started with were written as its
    /// record, and a `settings_adopted` event says which.
    Adopted,
    /// The record is gone or unreadable although the vault had one, or the
    /// log that would tell is damaged. [`OwnerSettings::cautious`] was written
    /// in its place with a `settings_tampered` event. The reason is one of
    /// `record_missing`, `record_unreadable`, `log_damaged`.
    Reset(&'static str),
}

impl<S: Storage, C: Clock> Vault<S, C> {
    fn owner_settings_id(&self) -> Id {
        Id::derived("usk/owner-settings", &self.header.vault_id)
    }

    /// The stored settings, if the vault has any. An unreadable record is
    /// [`VaultError::Corrupt`], never "none".
    pub fn owner_settings(&self) -> Result<Option<OwnerSettings>, VaultError> {
        let vk = self.vk()?;
        let id = self.owner_settings_id();
        match self.storage.latest_record(&id)? {
            None => Ok(None),
            Some(rec) => {
                if rec.kind != RecordKind::Setting {
                    return Err(VaultError::Corrupt(id));
                }
                records::decrypt_json(vk, &self.header.vault_id, &rec)
                    .map(Some)
                    .map_err(|_| VaultError::Corrupt(id))
            }
        }
    }

    /// Store the settings. The caller has checked that the owner asked.
    pub fn set_owner_settings(&mut self, settings: &OwnerSettings) -> Result<(), VaultError> {
        let vk = self.vk()?.clone();
        let id = self.owner_settings_id();
        let version = self
            .storage
            .latest_record(&id)?
            .map(|r| r.version + 1)
            .unwrap_or(1);
        let rec = records::encrypt_json(
            &vk,
            &self.header.vault_id,
            id,
            RecordKind::Setting,
            version,
            &settings.clamped(),
            self.clock.now_unix_ms(),
        )?;
        self.storage.insert_record(&rec)?;
        self.storage.prune_versions(&id, version)?;
        Ok(())
    }

    fn had_owner_settings(&self) -> Result<bool, VaultError> {
        for kind in [kinds::SETTINGS_ADOPTED, kinds::SETTINGS_TAMPERED] {
            if !self.audit_events(0, Some(kind), 1)?.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The settings to apply after an unlock.
    ///
    /// A vault without a record takes `seed` (what the daemon was started
    /// with) once, and only when the audit log is whole and shows that the
    /// vault never had settings. From then on the record is the only source:
    /// if it is missing or unreadable, or the log cannot vouch for a first
    /// time, the cautious values are stored and the log says why. The event
    /// is written before the record, so a record never exists unannounced.
    pub fn settle_owner_settings(
        &mut self,
        seed: &OwnerSettings,
    ) -> Result<(OwnerSettings, SettingsOrigin), VaultError> {
        let reason = match self.owner_settings() {
            Ok(Some(stored)) => return Ok((stored.clamped(), SettingsOrigin::Stored)),
            Ok(None) => {
                if self.had_owner_settings()? {
                    "record_missing"
                } else if self.log_broken {
                    "log_damaged"
                } else {
                    let adopted = seed.clamped();
                    self.audit(kinds::SETTINGS_ADOPTED, adopted.json())?;
                    self.set_owner_settings(&adopted)?;
                    return Ok((adopted, SettingsOrigin::Adopted));
                }
            }
            Err(VaultError::Corrupt(_)) => "record_unreadable",
            Err(e) => return Err(e),
        };
        let cautious = OwnerSettings::cautious();
        let mut body = cautious.json();
        body["reason"] = serde_json::json!(reason);
        self.audit(kinds::SETTINGS_TAMPERED, body)?;
        self.set_owner_settings(&cautious)?;
        Ok((cautious, SettingsOrigin::Reset(reason)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::Argon2Profile;
    use crate::crypto::SecretBytes;
    use crate::storage::memory::MemoryStorage;
    use crate::time::FixedClock;

    const PW: &str = "owner-settings-test";

    fn vault() -> Vault<MemoryStorage, FixedClock> {
        Vault::create(
            MemoryStorage::new(),
            FixedClock(1_000),
            &SecretBytes::from(PW),
            Argon2Profile::MINIMUM,
        )
        .unwrap()
        .0
    }

    fn loose() -> OwnerSettings {
        OwnerSettings {
            care: Care::Relaxed,
            idle_lock_minutes: 0,
            lock_on_sleep: false,
            lock_on_session_lock: false,
            mcp_allow_store: true,
        }
    }

    #[test]
    fn a_vault_without_settings_takes_the_seed_once() {
        let mut v = vault();
        assert_eq!(v.owner_settings().unwrap(), None);
        let seed = OwnerSettings {
            idle_lock_minutes: 30,
            ..OwnerSettings::default()
        };
        assert_eq!(
            v.settle_owner_settings(&seed).unwrap(),
            (seed, SettingsOrigin::Adopted)
        );
        // The record now decides; another seed is not looked at.
        v.lock();
        v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
        assert_eq!(
            v.settle_owner_settings(&loose()).unwrap(),
            (seed, SettingsOrigin::Stored)
        );
        assert_eq!(
            v.audit_events(0, Some(kinds::SETTINGS_ADOPTED), 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn the_owner_changes_them_and_they_stay() {
        let mut v = vault();
        v.settle_owner_settings(&OwnerSettings::default()).unwrap();
        let mine = OwnerSettings {
            care: Care::Strict,
            idle_lock_minutes: 5,
            ..OwnerSettings::default()
        };
        v.set_owner_settings(&mine).unwrap();
        v.set_owner_settings(&mine).unwrap();
        assert_eq!(v.owner_settings().unwrap(), Some(mine));
        assert_eq!(
            v.settle_owner_settings(&loose()).unwrap(),
            (mine, SettingsOrigin::Stored)
        );
    }

    #[test]
    fn an_idle_lock_beyond_a_day_is_a_day() {
        let mut v = vault();
        let seed = OwnerSettings {
            idle_lock_minutes: 1_000_000,
            ..OwnerSettings::default()
        };
        let (got, _) = v.settle_owner_settings(&seed).unwrap();
        assert_eq!(got.idle_lock_minutes, MAX_IDLE_LOCK_MINUTES);
    }

    #[test]
    fn a_locked_vault_tells_nothing_and_takes_nothing() {
        let mut v = vault();
        v.lock();
        assert!(matches!(v.owner_settings(), Err(VaultError::Locked)));
        assert!(matches!(
            v.set_owner_settings(&loose()),
            Err(VaultError::Locked)
        ));
        assert!(matches!(
            v.settle_owner_settings(&loose()),
            Err(VaultError::Locked)
        ));
    }

    #[test]
    fn fields_added_later_take_their_defaults() {
        let s: OwnerSettings = serde_json::from_str(r#"{"care":"strict"}"#).unwrap();
        assert_eq!(s, OwnerSettings::cautious());
    }
}
