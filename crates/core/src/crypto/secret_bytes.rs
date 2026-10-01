//! [`SecretBytes`]: the only container for plaintext secret material.

use super::platform;
use alloc::vec::Vec;
use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Owned bytes that are wiped from memory on drop and can never be printed.
///
/// - `Debug` and `Display` render `[secret]`.
/// - There is deliberately no `Serialize`; the only way to persist a secret is
///   through the vault's encryption path.
/// - Equality is constant-time.
/// - The buffer is locked in memory on a best-effort basis (no swap, no core
///   dump) for as long as it lives.
/// - The contents are reachable only through [`SecretBytes::expose`], so every
///   use site is greppable.
#[derive(Zeroize)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Take ownership of `bytes`. The caller must not keep another copy.
    pub fn new(mut bytes: Vec<u8>) -> Self {
        platform::lock(&mut bytes);
        Self(bytes)
    }

    /// Copy `bytes` into a new secret.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// A secret of `len` fresh random bytes from the OS CSPRNG.
    pub fn random(len: usize) -> Self {
        let mut v = alloc::vec![0u8; len];
        super::random_bytes(&mut v);
        Self::new(v)
    }

    /// Borrow the plaintext. Keep the borrow as short as possible.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes. Not secret.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        platform::unlock(&mut self.0);
        self.0.zeroize();
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

impl From<&str> for SecretBytes {
    fn from(s: &str) -> Self {
        Self::from_slice(s.as_bytes())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        // Length leaks through timing; that is acceptable (lengths are not secret).
        self.0.len() == other.0.len() && bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[secret]")
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[secret]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn never_prints_contents() {
        let s = SecretBytes::from("sk-live-do-not-print");
        assert_eq!(format!("{s:?}"), "[secret]");
        assert_eq!(format!("{s}"), "[secret]");
    }

    #[test]
    fn equality_is_by_value() {
        assert_eq!(SecretBytes::from("a"), SecretBytes::from("a"));
        assert_ne!(SecretBytes::from("a"), SecretBytes::from("b"));
        assert_ne!(SecretBytes::from("a"), SecretBytes::from("ab"));
    }

    #[test]
    fn random_is_random() {
        let a = SecretBytes::random(32);
        let b = SecretBytes::random(32);
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
    }

    #[test]
    fn clone_and_drop_many() {
        // Exercises lock/unlock on many small buffers; must never fail or panic
        // even when the platform refuses to lock more pages.
        let originals: alloc::vec::Vec<SecretBytes> = (0..500)
            .map(|i| SecretBytes::from_slice(&[i as u8; 40]))
            .collect();
        let clones: alloc::vec::Vec<SecretBytes> = originals.to_vec();
        assert_eq!(originals, clones);
        drop(originals);
        assert_eq!(clones[3].expose(), &[3u8; 40]);
    }
}
