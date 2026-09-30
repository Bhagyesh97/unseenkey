//! `config.toml` next to the vault file. Contains no secret material.

use serde::Deserialize;
use std::path::Path;

/// Whole configuration file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    /// `[daemon]` section.
    pub daemon: DaemonConfig,
}

/// `[daemon]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    /// Loopback address to listen on. Port `0` picks a free port.
    pub listen: String,
    /// Lock the vault after this many minutes without an authenticated request. `0` disables.
    pub idle_lock_minutes: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7391".into(),
            idle_lock_minutes: 15,
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
    }
}
