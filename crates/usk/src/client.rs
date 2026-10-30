//! HTTP client for the local daemon.

use crate::io::{self as uio, CliError, EXIT_LOCKED};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;
use unseenkey_daemon::VaultPaths;

/// A connection to a running daemon.
pub struct Client {
    base: String,
    token: String,
    /// The owner token from the unlock or confirmation this process made.
    /// Memory only: it is what tells the daemon a person, not a program
    /// holding `daemon.token`, is behind a reveal, an approval or a widened
    /// policy. Never written anywhere.
    owner: Mutex<Option<String>>,
    agent: ureq::Agent,
}

impl Client {
    fn from_files(paths: &VaultPaths) -> Option<Self> {
        let addr = std::fs::read_to_string(&paths.addr).ok()?;
        let token = std::fs::read_to_string(&paths.token).ok()?;
        // The daemon only ever writes a loopback address here. Anything else
        // means the file was tampered with, and the password and values this
        // client is about to send must not leave the machine.
        let addr: SocketAddr = addr.trim().parse().ok()?;
        if !addr.ip().is_loopback() {
            return None;
        }
        // Loopback connects are instant when the daemon is healthy; the connect
        // timeout only bounds the stale-file probe. 500 ms proved too tight on a
        // loaded Windows machine right after a daemon spawn.
        // One connection per request: pooling a kept-alive connection to the
        // daemon buys nothing on loopback and turns a server-side close into
        // a spurious "connection aborted" on the next command.
        let agent = ureq::AgentBuilder::new()
            .max_idle_connections(0)
            .timeout_connect(Duration::from_secs(3))
            .timeout(Duration::from_secs(30))
            .build();
        let c = Self {
            base: format!("http://{addr}"),
            token: token.trim().to_string(),
            owner: Mutex::new(None),
            agent,
        };
        // Stale files from a crashed daemon: probe, and with the token. A new
        // daemon binds its port before it writes `daemon.token`, so right
        // after a spawn the address can answer while the token on disk is
        // still the dead daemon's; an unauthenticated probe would hand that
        // token to the first request (a 401 on the first unlock). Treat a
        // refused token as "not ready" so `connect` keeps waiting.
        match c.request("GET", "/v1/status").call() {
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
        let mut r = self
            .agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token));
        if let Some(o) = self
            .owner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            r = r.set(unseenkey_daemon::token::OWNER_HEADER, o);
        }
        r
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

    /// `http://127.0.0.1:<port>` of the connected daemon.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// Is the vault locked?
    pub fn is_locked(&self) -> Result<bool, CliError> {
        Ok(self.get("/v1/status")?["locked"].as_bool().unwrap_or(true))
    }

    /// The owner token held by this client, if an unlock or confirmation
    /// produced one.
    pub fn owner(&self) -> Option<String> {
        self.owner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Use an owner token obtained earlier (the desktop app keeps the one from
    /// its unlock for as long as it runs).
    pub fn set_owner(&self, token: Option<String>) {
        *self.owner.lock().unwrap_or_else(|e| e.into_inner()) = token;
    }

    fn remember_owner(&self, reply: &Value) {
        if let Some(t) = reply["owner_token"].as_str() {
            self.set_owner(Some(t.to_string()));
        }
    }

    /// Prove the owner with the password on an unlocked vault (`POST /v1/confirm`)
    /// and keep the owner token it returns.
    pub fn confirm_with_password(&self, password: &str) -> Result<(), CliError> {
        let r = self.post("/v1/confirm", serde_json::json!({ "password": password }))?;
        self.remember_owner(&r);
        Ok(())
    }

    /// Unlock if needed, prompting for the password (up to three tries on a terminal).
    /// The unlock also yields the owner token, so a command that unlocked
    /// needs no second prompt for an owner-only action.
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
                Ok(r) => {
                    self.remember_owner(&r);
                    return Ok(());
                }
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

    /// Make sure this client can act as the owner: an unlock made here already
    /// did, otherwise ask for the password and confirm it with the daemon.
    /// Revealing a value, approving a request, replacing a policy and the like
    /// go through this, so a program that merely holds `daemon.token` cannot.
    pub fn ensure_owner(&self) -> Result<(), CliError> {
        if self.owner().is_some() {
            return Ok(());
        }
        let tries = if uio::is_tty() { 3 } else { 1 };
        for attempt in 1..=tries {
            let pw = uio::read_secret_line("Vault password (to confirm it is you): ")?;
            let pw_str = std::str::from_utf8(pw.expose())
                .map_err(|_| CliError::general("password is not valid UTF-8"))?;
            match self.confirm_with_password(pw_str) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind == "wrong_password" && attempt < tries => {
                    eprintln!("wrong password, try again");
                }
                Err(e) => return Err(e),
            }
        }
        Err(CliError::with_code(
            EXIT_LOCKED,
            "wrong_password",
            "not confirmed",
        ))
    }
}
