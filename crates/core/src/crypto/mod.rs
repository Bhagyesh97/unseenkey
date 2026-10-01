//! Cryptographic primitives, exactly as specified in `docs/06-cryptography.md`.
//!
//! Boring, standard, reviewed:
//! - password KDF: Argon2id ([`kdf`])
//! - key derivation: HKDF-SHA256 ([`kdf`])
//! - AEAD: XChaCha20-Poly1305 ([`aead`])
//! - hashing: BLAKE3 ([`hash`])
//! - signatures: Ed25519 ([`sign`])
//!
//! Every construction has a known-answer test in `tests/vectors.rs`.

pub mod aead;
pub mod hash;
pub mod kdf;
mod platform;
pub mod secret_bytes;
pub mod sign;

pub use secret_bytes::SecretBytes;

/// Errors from the crypto layer. Messages never include key or plaintext material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD authentication failed: wrong key, wrong nonce, wrong AAD, or tampered ciphertext.
    #[error("decryption failed")]
    Decrypt,
    /// Argon2 rejected the parameters or failed internally.
    #[error("key derivation failed")]
    Kdf,
    /// Requested output length is not supported by the primitive.
    #[error("invalid length")]
    Length,
    /// A signature did not verify.
    #[error("signature invalid")]
    Signature,
    /// A key or signature had the wrong encoding.
    #[error("invalid key material")]
    KeyMaterial,
}

/// Fill `buf` with bytes from the operating system CSPRNG.
///
/// The only source of randomness in the crate. Panics if the OS RNG is
/// unavailable: there is no safe way to continue without entropy.
pub fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("operating system CSPRNG unavailable");
}

/// Return `N` fresh random bytes.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    random_bytes(&mut out);
    out
}

/// The base62 alphabet used for tokens and handles.
pub const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// `len` uniformly random base62 characters (rejection sampling, no modulo bias).
pub fn random_base62(len: usize) -> alloc::string::String {
    let mut out = alloc::string::String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        random_bytes(&mut buf);
        for &b in buf.iter() {
            // 248 = 4 * 62: bytes at or above are rejected to keep the draw uniform.
            if b < 248 && out.len() < len {
                out.push(BASE62[(b % 62) as usize] as char);
            }
        }
    }
    out
}
