//! Vault header construction and vault-key wrapping.

use super::recovery::RecoveryKit;
use super::VaultError;
use crate::crypto::aead::{self, Sealed};
use crate::crypto::kdf::{self, Argon2Profile};
use crate::crypto::{CryptoError, SecretBytes};
use crate::ids::Id;
use crate::storage::HeaderRow;
use alloc::vec::Vec;

/// Current on-disk format version.
pub const FORMAT_VERSION: u32 = 1;

/// Which credential a wrapped vault key belongs to. Bound into the wrap's AAD
/// so a recovery wrap can never be presented as a password wrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KekKind {
    /// Password-derived KEK.
    Password,
    /// Recovery-kit-derived KEK.
    Recovery,
    /// Passkey (WebAuthn PRF) derived KEK. Reserved for M2.2.
    Passkey,
}

impl KekKind {
    fn label(&self) -> &'static [u8] {
        match self {
            KekKind::Password => b"pw",
            KekKind::Recovery => b"rec",
            KekKind::Passkey => b"pk",
        }
    }
}

fn wrap_aad(kind: KekKind, vault_id: &Id) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(b"usk/vk/");
    aad.extend_from_slice(kind.label());
    aad.push(b'/');
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

/// Wrap the vault key under a KEK.
pub fn wrap_vk(
    kek: &SecretBytes,
    vk: &SecretBytes,
    kind: KekKind,
    vault_id: &Id,
) -> Result<Sealed, CryptoError> {
    aead::seal(kek, &wrap_aad(kind, vault_id), vk)
}

/// Unwrap the vault key. Any failure is reported as a wrong credential.
pub fn unwrap_vk(
    kek: &SecretBytes,
    wrapped: &Sealed,
    kind: KekKind,
    vault_id: &Id,
) -> Result<SecretBytes, VaultError> {
    let vk = aead::open(kek, &wrap_aad(kind, vault_id), wrapped)
        .map_err(|_| VaultError::WrongCredential)?;
    if vk.len() != aead::KEY_LEN {
        return Err(VaultError::WrongCredential);
    }
    Ok(vk)
}

/// Derive a password KEK with a fresh salt and wrap the vault key under it.
pub fn wrap_password(
    vault_id: &Id,
    vk: &SecretBytes,
    password: &SecretBytes,
    profile: Argon2Profile,
) -> Result<([u8; kdf::PASSWORD_SALT_LEN], Sealed), VaultError> {
    let salt = crate::crypto::random_array::<{ kdf::PASSWORD_SALT_LEN }>();
    let kek = kdf::derive_password_key(password, &salt, profile)?;
    let wrapped = wrap_vk(&kek, vk, KekKind::Password, vault_id)?;
    Ok((salt, wrapped))
}

/// Build a complete header for a new vault.
pub fn build(
    vault_id: &Id,
    vk: &SecretBytes,
    password: &SecretBytes,
    profile: Argon2Profile,
    kit: &RecoveryKit,
    now: i64,
) -> Result<HeaderRow, VaultError> {
    let (salt_pw, wrapped_vk_pw) = wrap_password(vault_id, vk, password, profile)?;
    let wrapped_vk_rec = wrap_vk(&kit.kek(), vk, KekKind::Recovery, vault_id)?;
    Ok(HeaderRow {
        vault_id: *vault_id,
        format_version: FORMAT_VERSION,
        argon2: profile,
        salt_pw,
        wrapped_vk_pw,
        wrapped_vk_rec: Some(wrapped_vk_rec),
        created_at: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_kinds_are_not_interchangeable() {
        let vid = Id::new_v7(1);
        let kek = SecretBytes::random(32);
        let vk = SecretBytes::random(32);
        let w = wrap_vk(&kek, &vk, KekKind::Password, &vid).unwrap();
        assert_eq!(unwrap_vk(&kek, &w, KekKind::Password, &vid).unwrap(), vk);
        assert!(matches!(
            unwrap_vk(&kek, &w, KekKind::Recovery, &vid),
            Err(VaultError::WrongCredential)
        ));
        let other = Id::new_v7(2);
        assert!(matches!(
            unwrap_vk(&kek, &w, KekKind::Password, &other),
            Err(VaultError::WrongCredential)
        ));
    }
}
