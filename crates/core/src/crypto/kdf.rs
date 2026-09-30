//! Key derivation: Argon2id for passwords, HKDF-SHA256 for everything else.

use super::{CryptoError, SecretBytes};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

/// Argon2id cost profile (`docs/06-cryptography.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Profile {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism lanes.
    pub p_cost: u32,
}

impl Argon2Profile {
    /// Desktop profile: 256 MiB, 3 passes, 1 lane. About 0.5–1 s on a 2020 laptop.
    pub const DESKTOP: Self = Self {
        m_cost_kib: 256 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    /// Light profile for mobile and WASM: 64 MiB, 3 passes, 1 lane.
    pub const LIGHT: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };

    /// Minimum we will ever accept when opening a vault. Weaker headers are refused.
    pub const MINIMUM: Self = Self {
        m_cost_kib: 32 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    /// True if this profile is at least as strong as `MINIMUM` in every dimension.
    pub fn is_acceptable(&self) -> bool {
        self.m_cost_kib >= Self::MINIMUM.m_cost_kib
            && self.t_cost >= Self::MINIMUM.t_cost
            && self.p_cost >= 1
    }
}

/// Length of salts used with [`derive_password_key`].
pub const PASSWORD_SALT_LEN: usize = 16;

/// Derive a 32-byte key from a password with Argon2id v1.3.
///
/// `salt` must be at least 8 bytes and unique per vault (we use 16 random bytes).
pub fn derive_password_key(
    password: &SecretBytes,
    salt: &[u8],
    profile: Argon2Profile,
) -> Result<SecretBytes, CryptoError> {
    if salt.len() < 8 {
        return Err(CryptoError::Length);
    }
    let params = Params::new(profile.m_cost_kib, profile.t_cost, profile.p_cost, Some(32))
        .map_err(|_| CryptoError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = alloc::vec![0u8; 32];
    argon
        .hash_password_into(password.expose(), salt, &mut out)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(SecretBytes::new(out))
}

/// HKDF-SHA256 expand-and-extract: derive `len` bytes from `ikm` bound to `info`.
///
/// `salt` may be empty (HKDF then uses a zero salt, per RFC 5869).
/// `info` should be a domain-separation string such as `b"usk/dek/<id>/<version>"`.
pub fn hkdf_sha256(
    ikm: &SecretBytes,
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<SecretBytes, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm.expose());
    let mut out = alloc::vec![0u8; len];
    hk.expand(info, &mut out).map_err(|_| CryptoError::Length)?;
    Ok(SecretBytes::new(out))
}

/// Convenience: derive a 32-byte subkey with an empty salt.
pub fn subkey(ikm: &SecretBytes, info: &[u8]) -> SecretBytes {
    hkdf_sha256(ikm, &[], info, 32).expect("32 bytes is always a valid HKDF length")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_info_gives_different_keys() {
        let ikm = SecretBytes::random(32);
        assert_ne!(subkey(&ikm, b"usk/a"), subkey(&ikm, b"usk/b"));
        assert_eq!(subkey(&ikm, b"usk/a"), subkey(&ikm, b"usk/a"));
    }

    #[test]
    fn short_salt_rejected() {
        let pw = SecretBytes::from("pw");
        assert_eq!(
            derive_password_key(&pw, b"short", Argon2Profile::MINIMUM).unwrap_err(),
            CryptoError::Length
        );
    }

    #[test]
    fn profile_floor() {
        assert!(Argon2Profile::DESKTOP.is_acceptable());
        assert!(Argon2Profile::LIGHT.is_acceptable());
        assert!(!Argon2Profile {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1
        }
        .is_acceptable());
    }
}
