//! Windows Hello as a device unlock method.
//!
//! Enrollment creates a Hello-protected key pair for this vault (TPM-backed
//! where available). The daemon stores a random 32-byte salt and the vault key
//! wrapped under `KEK = HKDF(sign(salt), "usk/kek/hello/v1")`. Signing needs
//! the user's PIN or biometric every time, and RSA PKCS#1 v1.5 signatures are
//! deterministic, so the same salt always yields the same KEK. Nothing derived
//! from Hello is written to disk; the salt alone is public and useless.

use unseenkey_core::crypto::{kdf, SecretBytes};

/// Kind string stored with the wrap.
pub const KIND: &str = "hello";

#[cfg(windows)]
mod win {
    use super::*;
    use windows::core::HSTRING;
    use windows::Security::Credentials::{
        KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;

    fn name(vault_id: &str) -> HSTRING {
        HSTRING::from(format!("Unseenkey/{vault_id}"))
    }

    fn status(s: KeyCredentialStatus) -> Result<(), String> {
        match s {
            KeyCredentialStatus::Success => Ok(()),
            KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
                Err("cancelled: the Windows Hello prompt was dismissed".into())
            }
            KeyCredentialStatus::NotFound => {
                Err("not_found: no Windows Hello key for this vault on this computer; enable it again in Settings".into())
            }
            KeyCredentialStatus::SecurityDeviceLocked => {
                Err("locked: the security device is locked; try again later".into())
            }
            KeyCredentialStatus::CredentialAlreadyExists => {
                Err("exists: a Windows Hello key already exists".into())
            }
            _ => Err("hello: Windows Hello is not available right now".into()),
        }
    }

    fn werr(e: windows::core::Error) -> String {
        format!("hello: {e}")
    }

    pub fn available() -> bool {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .unwrap_or(false)
    }

    pub fn create_key(vault_id: &str) -> Result<(), String> {
        let r = KeyCredentialManager::RequestCreateAsync(
            &name(vault_id),
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .and_then(|op| op.join())
        .map_err(werr)?;
        status(r.Status().map_err(werr)?)
    }

    pub fn delete_key(vault_id: &str) {
        let _ = KeyCredentialManager::DeleteAsync(&name(vault_id)).and_then(|op| op.join());
    }

    pub fn derive_kek(vault_id: &str, salt: &[u8; 32]) -> Result<SecretBytes, String> {
        let opened = KeyCredentialManager::OpenAsync(&name(vault_id))
            .and_then(|op| op.join())
            .map_err(werr)?;
        status(opened.Status().map_err(werr)?)?;
        let cred = opened.Credential().map_err(werr)?;
        let challenge = CryptographicBuffer::CreateFromByteArray(salt).map_err(werr)?;
        let signed = cred
            .RequestSignAsync(&challenge)
            .and_then(|op| op.join())
            .map_err(werr)?;
        status(signed.Status().map_err(werr)?)?;
        let sig = signed.Result().map_err(werr)?;
        let mut bytes = windows::core::Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&sig, &mut bytes).map_err(werr)?;
        let ikm = SecretBytes::from_slice(&bytes);
        bytes.clear();
        if ikm.len() < 32 {
            return Err("hello: unexpected signature length".into());
        }
        Ok(kdf::subkey(&ikm, b"usk/kek/hello/v1"))
    }
}

#[cfg(windows)]
pub use win::{available, create_key, delete_key, derive_kek};

#[cfg(not(windows))]
pub fn available() -> bool {
    false
}
#[cfg(not(windows))]
pub fn create_key(_vault_id: &str) -> Result<(), String> {
    Err("unsupported: Windows Hello unlock is only available on Windows".into())
}
#[cfg(not(windows))]
pub fn delete_key(_vault_id: &str) {}
#[cfg(not(windows))]
pub fn derive_kek(_vault_id: &str, _salt: &[u8; 32]) -> Result<SecretBytes, String> {
    Err("unsupported: Windows Hello unlock is only available on Windows".into())
}

/// A label for the enrollment: machine and account, best effort.
pub fn device_label() -> String {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "this computer".into());
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();
    if user.is_empty() {
        host
    } else {
        format!("{host} ({user})")
    }
}
