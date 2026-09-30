//! Recovery kit: 24 BIP-39 words encoding 256 bits of entropy.
//!
//! `KEK_rec = HKDF(entropy, "usk/kek/rec/v1")`. There is no other recovery path.

use crate::crypto::{kdf, SecretBytes};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The phrase was not a valid 24-word BIP-39 mnemonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid recovery phrase")]
pub struct InvalidPhrase;

/// Recovery entropy plus its word form.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKit {
    entropy: Vec<u8>,
    phrase: String,
}

impl core::fmt::Debug for RecoveryKit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryKit([secret])")
    }
}

impl RecoveryKit {
    /// Generate a fresh 256-bit kit.
    pub fn generate() -> Self {
        let entropy = crate::crypto::random_array::<32>().to_vec();
        let m = bip39::Mnemonic::from_entropy(&entropy).expect("32 bytes is valid BIP-39 entropy");
        let phrase = m.to_string();
        Self { entropy, phrase }
    }

    /// Parse a phrase typed by the user. Whitespace and case are normalised.
    pub fn parse(phrase: &str) -> Result<Self, InvalidPhrase> {
        let normalised: String = phrase
            .split_whitespace()
            .map(|w| w.to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");
        let m = bip39::Mnemonic::parse_normalized(&normalised).map_err(|_| InvalidPhrase)?;
        if m.word_count() != 24 {
            return Err(InvalidPhrase);
        }
        let entropy = m.to_entropy();
        Ok(Self {
            entropy,
            phrase: normalised,
        })
    }

    /// The 24 words, space separated. Show once, then drop.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// The words as a list, for numbered display.
    pub fn words(&self) -> Vec<&str> {
        self.phrase.split(' ').collect()
    }

    /// Derive the recovery KEK.
    pub fn kek(&self) -> SecretBytes {
        kdf::subkey(&SecretBytes::from_slice(&self.entropy), b"usk/kek/rec/v1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_parse_round_trip() {
        let kit = RecoveryKit::generate();
        assert_eq!(kit.words().len(), 24);
        let upper = kit.phrase().to_uppercase().replace(' ', "   ");
        let back = RecoveryKit::parse(&upper).unwrap();
        assert_eq!(back.kek(), kit.kek());
    }

    #[test]
    fn bad_phrase_rejected() {
        assert!(RecoveryKit::parse("abandon abandon abandon").is_err());
        let kit = RecoveryKit::generate();
        let mut words = kit.words();
        words.swap(0, 1);
        // A swapped phrase either fails the checksum or yields a different key.
        match RecoveryKit::parse(&words.join(" ")) {
            Err(InvalidPhrase) => {}
            Ok(other) => assert_ne!(other.kek(), kit.kek()),
        }
    }
}
