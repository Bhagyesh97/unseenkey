//! Hashing with BLAKE3: audit-log chaining, handle lookup hashes, checksums.

use subtle::ConstantTimeEq;

/// A 32-byte BLAKE3 digest.
pub type Digest = [u8; 32];

/// BLAKE3 hash of `data`.
pub fn blake3(data: &[u8]) -> Digest {
    *blake3::hash(data).as_bytes()
}

/// Keyed BLAKE3 (a MAC). `key` must be exactly 32 bytes.
pub fn blake3_keyed(key: &[u8; 32], data: &[u8]) -> Digest {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Hash used to look up handles and tokens: the daemon stores only this,
/// never the handle string. Domain-separated so a handle hash can never be
/// confused with an audit or content hash.
pub fn handle_hash(handle: &[u8]) -> Digest {
    let mut h = blake3::Hasher::new_derive_key("usk/handle-hash/v1");
    h.update(handle);
    *h.finalize().as_bytes()
}

/// Constant-time comparison of two digests.
pub fn digest_eq(a: &Digest, b: &Digest) -> bool {
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_hash_is_domain_separated() {
        assert_ne!(handle_hash(b"usk_h_abc"), blake3(b"usk_h_abc"));
    }

    #[test]
    fn digest_eq_works() {
        let a = blake3(b"a");
        assert!(digest_eq(&a, &blake3(b"a")));
        assert!(!digest_eq(&a, &blake3(b"b")));
    }
}
