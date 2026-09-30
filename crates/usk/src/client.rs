//! HTTP client for the local daemon.

use crate::io::{self as uio, CliError, EXIT_LOCKED};
use serde_json::Value;
use std::time::Duration;
use unseenkey_daemon::VaultPaths;

/// A connection to a running daemon.
pub struct Client {
    base: String,
    token: String,
    agent: ureq::Agent,
}

impl Client {
    fn from_files(paths: &VaultPaths) -> Option<Self> {
        let addr = std::fs::read_to_string(&paths.addr).ok()?;
        let token = std::fs::read_to_string(&paths.token).ok()?;
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_millis(500))
            .timeout(Duration::from_secs(30))
            .build();
        let c = Self {
            base: format!("http://{}", addr.trim()),
            token: token.trim().to_string(),
            agent,
        };
        // Stale files from a crashed daemon: probe.
        match c.agent.get(&format!("{}/healthz", c.base)).call() {
            Ok(r) if r.status() == 200 => Some(c),
            _ => None,
        }
    }

    /// Connect to the daemon for `paths`, starting it if needed.
    pub fn connect(paths: &VaultPaths, auto_start: bool) -> Result<Self, CliError> {
        if let Some(c) = Self::from_files(paths) {
            return Ok(c);
        }
        if !auto_start {
            return Err(CliError::general("daemon is not running"));
        }
        if !paths.vault.exists() {
            return Err(CliError::general("no vault found; run `usk init` first"));
        }
        crate::daemon::spawn_detached(paths)?;
        crate::daemon::wait_until(Duration::from_secs(10), || Self::from_files(paths)).ok_or_else(
            || {
                CliError::general(format!(
                    "daemon did not start; see {}",
                    paths.logs.join("uskd.log").display()
                ))
            },
        )
    }

    /// Try to connect without starting anything.
    pub fn try_connect(paths: &VaultPaths) -> Option<Self> {
        Self::from_files(paths)
    }

    fn request(&self, method: &str, path: &str) -> ureq::Request {
        self.agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token))
    }

    fn handle(r: Result<ureq::Response, ureq::Error>) -> Result<Value, CliError> {
        match r {
            Ok(resp) => resp
                .into_json()
                .map_err(|e| CliError::general(format!("bad response: {e}"))),
            Err(ureq::Error::Status(code, resp)) => {
                let body: Value = resp.into_json().unwrap_or(Value::Null);
                let err = body["error"].as_str().unwrap_or("error").to_string();
                let msg = body["message"].as_str().unwrap_or("").to_string();
                let exit = match err.as_str() {
                    "vault_locked" | "wrong_password" => EXIT_LOCKED,
                    _ => 1,
                };
                Err(CliError::with_code(
                    exit,
                    err,
                    format!("{msg} (HTTP {code})"),
                ))
            }
            Err(e) => Err(CliError::general(format!("daemon unreachable: {e}"))),
        }
    }

    /// GET.
    pub fn get(&self, path: &str) -> Result<Value, CliError> {
        Self::handle(self.request("GET", path).call())
    }
    /// POST JSON.
    pub fn post(&self, path: &str, body: Value) -> Result<Value, CliError> {
        Self::handle(self.request("POST", path).send_json(body))
    }
    /// PATCH JSON.
    pub fn patch(&self, path: &str, body: Value) -> Result<Value, CliError> {
        Self::handle(self.request("PATCH", path).send_json(body))
    }
    /// DELETE.
    pub fn delete(&self, path: &str) -> Result<Value, CliError> {
        Self::handle(self.request("DELETE", path).call())
    }

    /// Is the vault locked?
    pub fn is_locked(&self) -> Result<bool, CliError> {
        Ok(self.get("/v1/status")?["locked"].as_bool().unwrap_or(true))
    }

    /// Unlock if needed, prompting for the password (up to three tries on a terminal).
    pub fn ensure_unlocked(&self) -> Result<(), CliError> {
        if !self.is_locked()? {
            return Ok(());
        }
        let tries = if uio::is_tty() { 3 } else { 1 };
        for attempt in 1..=tries {
            let pw = uio::read_secret_line("Vault password: ")?;
            let pw_str = std::str::from_utf8(pw.expose())
                .map_err(|_| CliError::general("password is not valid UTF-8"))?;
            match self.post("/v1/unlock", serde_json::json!({ "password": pw_str })) {
                Ok(_) => return Ok(()),
                Err(e) if e.code == EXIT_LOCKED && attempt < tries => {
                    eprintln!("wrong password, try again");
                }
                Err(e) => return Err(e),
            }
        }
        Err(CliError::with_code(
            EXIT_LOCKED,
            "wrong_password",
            "vault stays locked",
        ))
    }
}
