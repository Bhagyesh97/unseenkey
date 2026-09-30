//! Ed25519 signatures: device keys, broker audit signatures, release manifests.

use super::{CryptoError, SecretBytes};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Length of an Ed25519 secret seed.
pub const SEED_LEN: usize = 32;
/// Length of an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// A signing key. The seed is held in a [`SecretBytes`]-like zeroizing type.
pub struct SigningKeyPair {
    key: SigningKey,
}

impl SigningKeyPair {
    /// Generate a fresh key pair from the OS CSPRNG.
    pub fn generate() -> Self {
        let seed = super::random_array::<SEED_LEN>();
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// Load from a 32-byte seed.
    pub fn from_seed(seed: &SecretBytes) -> Result<Self, CryptoError> {
        let bytes: [u8; SEED_LEN] = seed
            .expose()
            .try_into()
            .map_err(|_| CryptoError::KeyMaterial)?;
        Ok(Self {
            key: SigningKey::from_bytes(&bytes),
        })
    }

    /// Export the seed for storage in the OS keychain (encrypted by the caller).
    pub fn seed(&self) -> SecretBytes {
        SecretBytes::from_slice(&self.key.to_bytes())
    }

    /// The public half.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.key.verifying_key().to_bytes()
    }

    /// Sign `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.key.sign(message).to_bytes()
    }
}

impl core::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKeyPair")
            .field("public_key", &hex_prefix(&self.public_key()))
            .finish()
    }
}

fn hex_prefix(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write;
    let mut s = alloc::string::String::new();
    for b in bytes.iter().take(4) {
        let _ = write!(s, "{b:02x}");
    }
    s.push('…');
    s
}

/// Verify `signature` over `message` with `public_key`.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::KeyMaterial)?;
    let sig = Signature::from_bytes(signature);
    vk.verify(message, &sig).map_err(|_| CryptoError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let kp = SigningKeyPair::generate();
        let sig = kp.sign(b"audit event 1");
        assert!(verify(&kp.public_key(), b"audit event 1", &sig).is_ok());
        assert_eq!(
            verify(&kp.public_key(), b"audit event 2", &sig).unwrap_err(),
            CryptoError::Signature
        );
    }

    #[test]
    fn seed_round_trip() {
        let kp = SigningKeyPair::generate();
        let again = SigningKeyPair::from_seed(&kp.seed()).unwrap();
        assert_eq!(kp.public_key(), again.public_key());
    }

    #[test]
    fn debug_does_not_print_seed() {
        let kp = SigningKeyPair::generate();
        let dbg = alloc::format!("{kp:?}");
        let seed_hex = hex_all(kp.seed().expose());
        assert!(!dbg.contains(&seed_hex));
    }

    fn hex_all(b: &[u8]) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        for x in b {
            let _ = write!(s, "{x:02x}");
        }
        s
    }
}
