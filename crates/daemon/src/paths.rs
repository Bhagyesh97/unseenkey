//! Where the vault and the daemon's runtime files live.

use std::path::{Path, PathBuf};

/// File locations derived from the vault file's directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPaths {
    /// Directory holding everything.
    pub dir: PathBuf,
    /// The SQLite vault.
    pub vault: PathBuf,
    /// `config.toml`.
    pub config: PathBuf,
    /// Session token of the running daemon (mode 0600).
    pub token: PathBuf,
    /// `host:port` the running daemon listens on.
    pub addr: PathBuf,
    /// Process id of the running daemon.
    pub pid: PathBuf,
    /// Daemon log directory.
    pub logs: PathBuf,
}

impl VaultPaths {
    /// Paths for a vault at `vault_file`.
    pub fn from_vault_file(vault_file: &Path) -> Self {
        let dir = vault_file
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            vault: vault_file.to_path_buf(),
            config: dir.join("config.toml"),
            token: dir.join("daemon.token"),
            addr: dir.join("daemon.addr"),
            pid: dir.join("daemon.pid"),
            logs: dir.join("logs"),
            dir,
        }
    }

    /// The per-user default vault file: `%APPDATA%\Unseenkey\vault.db` on
    /// Windows, `~/.unseenkey/vault.db` elsewhere.
    pub fn default_vault_file() -> Option<PathBuf> {
        let base = if cfg!(windows) {
            dirs::config_dir().map(|d| d.join("Unseenkey"))
        } else {
            dirs::home_dir().map(|d| d.join(".unseenkey"))
        };
        base.map(|d| d.join("vault.db"))
    }
}
