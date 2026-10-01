//! Registered callers: MCP clients (and later devices) that get their own
//! identity (`mcp:<name>`) and bearer token (`usk_m_…`).
//!
//! Stored outside the vault in `<vault dir>/mcp/clients.json` as token hashes
//! plus names, so a client can authenticate while the vault is locked (it
//! still cannot use any secret then). The plaintext token is returned once at
//! creation and written by the CLI to `<vault dir>/mcp/<name>.token` (0600).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use unseenkey_core::crypto::hash::{digest_eq, handle_hash, Digest};
use unseenkey_core::crypto::random_base62;

/// Token prefix for callers.
pub const PREFIX: &str = "usk_m_";

/// One registered caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerEntry {
    /// Hex BLAKE3 of the token.
    pub hash: String,
    /// Unix milliseconds.
    pub created_at: i64,
    /// Unix milliseconds of last successful authentication.
    #[serde(default)]
    pub last_seen_at: Option<i64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default)]
    clients: BTreeMap<String, CallerEntry>,
}

/// The caller registry.
pub struct Callers {
    path: PathBuf,
    inner: RwLock<File>,
}

impl std::fmt::Debug for Callers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Callers").field("path", &self.path).finish()
    }
}

/// Valid caller names: `[a-z0-9-]{1,32}`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Callers {
    /// Load `path` (missing file = empty registry).
    pub fn load(path: &Path) -> Self {
        let inner = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Self {
            path: path.to_path_buf(),
            inner: RwLock::new(inner),
        }
    }

    fn save(&self, f: &File) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(f).unwrap_or_default();
        std::fs::write(&self.path, text)
    }

    /// Register (or re-key) a caller. Returns the plaintext token, shown once.
    pub fn create(&self, name: &str, now: i64) -> std::io::Result<String> {
        if !valid_name(name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "caller names are 1-32 chars of a-z, 0-9 and -",
            ));
        }
        let token = format!("{PREFIX}{}", random_base62(32));
        let hash = hex::encode(handle_hash(token.as_bytes()));
        let mut f = self.inner.write().unwrap_or_else(|e| e.into_inner());
        f.clients.insert(
            name.to_string(),
            CallerEntry {
                hash,
                created_at: now,
                last_seen_at: None,
            },
        );
        self.save(&f)?;
        Ok(token)
    }

    /// Remove a caller.
    pub fn remove(&self, name: &str) -> std::io::Result<bool> {
        let mut f = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let existed = f.clients.remove(name).is_some();
        if existed {
            self.save(&f)?;
        }
        Ok(existed)
    }

    /// Names and metadata (no hashes).
    pub fn list(&self) -> Vec<(String, CallerEntry)> {
        let f = self.inner.read().unwrap_or_else(|e| e.into_inner());
        f.clients
            .iter()
            .map(|(n, e)| {
                (
                    n.clone(),
                    CallerEntry {
                        hash: String::new(),
                        created_at: e.created_at,
                        last_seen_at: e.last_seen_at,
                    },
                )
            })
            .collect()
    }

    /// Resolve a presented token to a caller name (constant-time hash compare).
    pub fn verify(&self, token: &str, now: i64) -> Option<String> {
        if !token.starts_with(PREFIX) || token.len() != PREFIX.len() + 32 {
            return None;
        }
        let presented: Digest = handle_hash(token.as_bytes());
        let mut f = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let mut found = None;
        for (name, entry) in f.clients.iter() {
            let stored: Option<Digest> = hex::decode(&entry.hash)
                .ok()
                .and_then(|v| v.try_into().ok());
            if let Some(h) = stored {
                if digest_eq(&h, &presented) {
                    found = Some(name.clone());
                }
            }
        }
        if let Some(name) = &found {
            if let Some(e) = f.clients.get_mut(name) {
                e.last_seen_at = Some(now);
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_verify_remove_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp").join("clients.json");
        let c = Callers::load(&path);
        assert!(c.create("Bad Name", 1).is_err());
        let tok = c.create("cursor", 1).unwrap();
        assert!(tok.starts_with("usk_m_"));
        assert_eq!(c.verify(&tok, 2), Some("cursor".into()));
        assert_eq!(c.verify("usk_m_00000000000000000000000000000000", 2), None);
        assert_eq!(c.verify("garbage", 2), None);
        // Persisted: a fresh load verifies the same token; the file holds no plaintext.
        let again = Callers::load(&path);
        assert_eq!(again.verify(&tok, 3), Some("cursor".into()));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&tok));
        assert_eq!(again.list().len(), 1);
        assert!(again.remove("cursor").unwrap());
        assert_eq!(again.verify(&tok, 4), None);
        assert!(!again.remove("cursor").unwrap());
    }
}
