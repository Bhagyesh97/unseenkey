//! `config.toml` next to the vault file. Contains no secret material.

use serde::Deserialize;
use std::path::Path;

/// Whole configuration file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    /// `[daemon]` section.
    pub daemon: DaemonConfig,
    /// `[mcp]` section.
    pub mcp: McpConfig,
}

/// `[mcp]` section.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct McpConfig {
    /// Let MCP clients store secrets they find (`store_secret` tool). Off by default.
    pub allow_store: bool,
}

/// `[daemon]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    /// Loopback address to listen on. Port `0` picks a free port.
    pub listen: String,
    /// Lock the vault after this many minutes without an authenticated request. `0` disables.
    pub idle_lock_minutes: u64,
    /// Lock when the machine suspends (and, as a fallback, when it wakes).
    pub lock_on_sleep: bool,
    /// Lock when the interactive session locks (Win+L, lock screen).
    pub lock_on_session_lock: bool,
    /// How careful the access Unseenkey hands out by itself is:
    /// `relaxed`, `balanced` (default) or `strict`.
    pub care: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7391".into(),
            idle_lock_minutes: 15,
            lock_on_sleep: true,
            lock_on_session_lock: true,
            care: "balanced".into(),
        }
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file exists but could not be read.
    #[error("cannot read config {0}: {1}")]
    Io(String, std::io::Error),
    /// The file is not valid TOML for our schema.
    #[error("invalid config {0}: {1}")]
    Parse(String, String),
}

/// Set one `[daemon]` key in `config.toml`, keeping everything else in the file.
pub fn set_daemon_value(path: &Path, key: &str, value: toml::Value) -> Result<(), ConfigError> {
    let shown = path.display().to_string();
    let mut doc: toml::Table = match std::fs::read_to_string(path) {
        Ok(t) => {
            toml::from_str(&t).map_err(|e| ConfigError::Parse(shown.clone(), e.to_string()))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(e) => return Err(ConfigError::Io(shown, e)),
    };
    let daemon = doc
        .entry("daemon")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let toml::Value::Table(t) = daemon {
        t.insert(key.to_string(), value);
    }
    let text = toml::to_string_pretty(&doc)
        .map_err(|e| ConfigError::Parse(shown.clone(), e.to_string()))?;
    std::fs::write(path, text).map_err(|e| ConfigError::Io(shown, e))
}

/// Load `path` if it exists; defaults otherwise.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::Io(path.display().to_string(), e))?;
    toml::from_str(&text).map_err(|e| ConfigError::Parse(path.display().to_string(), e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_parse() {
        let d = Config::default();
        assert_eq!(d.daemon.listen, "127.0.0.1:7391");
        assert_eq!(d.daemon.idle_lock_minutes, 15);
        let c: Config = toml::from_str("[daemon]\nidle_lock_minutes = 3\n").unwrap();
        assert_eq!(c.daemon.idle_lock_minutes, 3);
        assert_eq!(c.daemon.listen, "127.0.0.1:7391");
        assert!(c.daemon.lock_on_sleep);
        assert!(c.daemon.lock_on_session_lock);
        let c: Config = toml::from_str("[daemon]\nlock_on_sleep = false\n").unwrap();
        assert!(!c.daemon.lock_on_sleep);
        assert!(c.daemon.lock_on_session_lock);
    }
}
