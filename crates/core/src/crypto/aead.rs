//! Authenticated encryption: XChaCha20-Poly1305 with random 24-byte nonces.

use super::{CryptoError, SecretBytes};
use alloc::vec::Vec;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// Nonce length for XChaCha20-Poly1305. Large enough that random nonces are safe.
pub const NONCE_LEN: usize = 24;
/// Key length.
pub const KEY_LEN: usize = 32;
/// Poly1305 tag length appended to every ciphertext.
pub const TAG_LEN: usize = 16;

/// Ciphertext plus the nonce it was produced with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Random nonce, stored alongside the ciphertext.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with the 16-byte Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
}

fn cipher(key: &SecretBytes) -> Result<XChaCha20Poly1305, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::KeyMaterial);
    }
    XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| CryptoError::KeyMaterial)
}

/// Encrypt `plaintext` under `key`, binding `aad`, with a fresh random nonce.
pub fn seal(key: &SecretBytes, aad: &[u8], plaintext: &SecretBytes) -> Result<Sealed, CryptoError> {
    let nonce = super::random_array::<NONCE_LEN>();
    seal_with_nonce(key, &nonce, aad, plaintext)
}

/// Encrypt with a caller-supplied nonce. Only for tests and known-answer
/// vectors; production code must use [`seal`]. Reusing a nonce with the same
/// key destroys confidentiality and integrity.
pub fn seal_with_nonce(
    key: &SecretBytes,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &SecretBytes,
) -> Result<Sealed, CryptoError> {
    let c = cipher(key)?;
    let ct = c
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext.expose(),
                aad,
            },
        )
        .map_err(|_| CryptoError::Length)?;
    Ok(Sealed {
        nonce: *nonce,
        ciphertext: ct,
    })
}

/// Decrypt and authenticate. Any failure is reported as [`CryptoError::Decrypt`]
/// without distinguishing the cause.
pub fn open(key: &SecretBytes, aad: &[u8], sealed: &Sealed) -> Result<SecretBytes, CryptoError> {
    let c = cipher(key)?;
    let pt = c
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(SecretBytes::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = SecretBytes::random(KEY_LEN);
        let pt = SecretBytes::from("sk-live-example");
        let sealed = seal(&key, b"aad", &pt).unwrap();
        assert_eq!(sealed.ciphertext.len(), pt.len() + TAG_LEN);
        assert_eq!(open(&key, b"aad", &sealed).unwrap(), pt);
    }

    #[test]
    fn wrong_aad_fails() {
        let key = SecretBytes::random(KEY_LEN);
        let sealed = seal(&key, b"record-1", &SecretBytes::from("x")).unwrap();
        assert_eq!(
            open(&key, b"record-2", &sealed).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&SecretBytes::random(KEY_LEN), b"", &SecretBytes::from("x")).unwrap();
        assert_eq!(
            open(&SecretBytes::random(KEY_LEN), b"", &sealed).unwrap_err(),
            CryptoError::Decrypt
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = SecretBytes::random(KEY_LEN);
        let mut sealed = seal(&key, b"", &SecretBytes::from("hello")).unwrap();
        sealed.ciphertext[0] ^= 0x01;
        assert_eq!(open(&key, b"", &sealed).unwrap_err(), CryptoError::Decrypt);
    }

    #[test]
    fn nonces_are_unique() {
        let key = SecretBytes::random(KEY_LEN);
        let a = seal(&key, b"", &SecretBytes::from("x")).unwrap();
        let b = seal(&key, b"", &SecretBytes::from("x")).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn bad_key_length_rejected() {
        let key = SecretBytes::random(16);
        assert_eq!(
            seal(&key, b"", &SecretBytes::from("x")).unwrap_err(),
            CryptoError::KeyMaterial
        );
    }
}
