//! Per-session bearer token for the management API.
//!
//! The daemon keeps only the BLAKE3 hash; the plaintext goes to a 0600 file
//! that the same user's CLI reads. A stolen hash is useless.

use std::path::Path;
use unseenkey_core::crypto::hash::{digest_eq, handle_hash, Digest};
use unseenkey_core::crypto::random_base62;

/// Prefix for session tokens (registered with secret scanners alongside handles).
pub const PREFIX: &str = "usk_s_";

/// A freshly generated session token.
#[derive(Clone)]
pub struct SessionToken {
    plain: String,
    hash: Digest,
}

impl SessionToken {
    /// Generate `usk_s_` + 32 base62 characters (~190 bits).
    pub fn generate() -> Self {
        let plain = format!("{PREFIX}{}", random_base62(32));
        let hash = handle_hash(plain.as_bytes());
        Self { plain, hash }
    }

    /// The plaintext, for writing to the token file. Do not log.
    pub fn plain(&self) -> &str {
        &self.plain
    }

    /// The hash the daemon verifies against.
    pub fn hash(&self) -> Digest {
        self.hash
    }
}

impl core::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionToken([redacted])")
    }
}

/// Constant-time check of a presented token against the stored hash.
pub fn verify(expected: &Digest, presented: &str) -> bool {
    if !presented.starts_with(PREFIX) || presented.len() != PREFIX.len() + 32 {
        return false;
    }
    digest_eq(expected, &handle_hash(presented.as_bytes()))
}

/// Write the token file with owner-only permissions.
pub fn write_token_file(path: &Path, token: &SessionToken) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(token.plain().as_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, token.plain().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify() {
        let t = SessionToken::generate();
        assert!(t.plain().starts_with(PREFIX));
        assert_eq!(t.plain().len(), PREFIX.len() + 32);
        assert!(verify(&t.hash(), t.plain()));
        assert!(!verify(&t.hash(), "usk_s_wrong"));
        let other = SessionToken::generate();
        assert!(!verify(&t.hash(), other.plain()));
        assert_eq!(format!("{t:?}"), "SessionToken([redacted])");
    }
}
