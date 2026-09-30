//! 128-bit identifiers: UUIDv7 for records and secrets, derived ids for linked records.

use alloc::string::String;
use core::fmt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 16-byte identifier. Time-ordered (UUIDv7) when generated, deterministic when derived.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id([u8; 16]);

impl Id {
    /// Generate a UUIDv7: 48-bit Unix millisecond timestamp, version and variant bits,
    /// and 74 random bits.
    pub fn new_v7(now_unix_ms: i64) -> Self {
        let ts = (now_unix_ms.max(0) as u64) & 0x0000_FFFF_FFFF_FFFF;
        let rnd = crate::crypto::random_array::<10>();
        let mut b = [0u8; 16];
        b[..6].copy_from_slice(&ts.to_be_bytes()[2..]);
        b[6..].copy_from_slice(&rnd);
        b[6] = (b[6] & 0x0F) | 0x70; // version 7
        b[8] = (b[8] & 0x3F) | 0x80; // RFC 4122 variant
        Self(b)
    }

    /// Deterministically derive an id from a domain string and a parent id.
    /// Used to locate a secret's metadata record from its secret id.
    pub fn derived(domain: &str, parent: &Id) -> Self {
        let mut h = blake3::Hasher::new_derive_key(domain);
        h.update(&parent.0);
        let d = h.finalize();
        let mut b = [0u8; 16];
        b.copy_from_slice(&d.as_bytes()[..16]);
        Self(b)
    }

    /// Wrap raw bytes.
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Lowercase hex, 32 characters.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse 32 hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        let v = hex::decode(s).ok()?;
        let b: [u8; 16] = v.try_into().ok()?;
        Some(Self(b))
    }

    /// Milliseconds since the epoch embedded in a v7 id (meaningless for derived ids).
    pub fn timestamp_ms(&self) -> i64 {
        let mut t = [0u8; 8];
        t[2..].copy_from_slice(&self.0[..6]);
        u64::from_be_bytes(t) as i64
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.to_hex())
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Id::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid id"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v7_is_time_ordered_and_versioned() {
        let a = Id::new_v7(1_000);
        let b = Id::new_v7(2_000);
        assert!(a < b);
        assert_eq!(a.as_bytes()[6] >> 4, 7);
        assert_eq!(a.as_bytes()[8] & 0xC0, 0x80);
        assert_eq!(a.timestamp_ms(), 1_000);
    }

    #[test]
    fn hex_round_trip() {
        let a = Id::new_v7(5);
        assert_eq!(Id::from_hex(&a.to_hex()), Some(a));
        assert_eq!(Id::from_hex("zz"), None);
    }

    #[test]
    fn derived_is_deterministic_and_distinct() {
        let p = Id::new_v7(1);
        assert_eq!(Id::derived("usk/meta", &p), Id::derived("usk/meta", &p));
        assert_ne!(Id::derived("usk/meta", &p), Id::derived("usk/other", &p));
        assert_ne!(Id::derived("usk/meta", &p), p);
    }
}
