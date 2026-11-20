//! HTTP client for the local daemon.

use crate::io::{self as uio, CliError, EXIT_LOCKED};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use unseenkey_daemon::VaultPaths;

/// Said once per run, and not by the commands that deal with it.
static VERSION_WARNING_DONE: AtomicBool = AtomicBool::new(false);

/// Keep this run from warning about the daemon's version.
pub fn skip_version_warning() {
    VERSION_WARNING_DONE.store(true, Ordering::Relaxed);
}

fn version_numbers(v: &str) -> Vec<u64> {
    v.split('.')
        .map(|part| {
            part.split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0)
        })
        .collect()
}

/// Is the running daemon a newer version than this program?
pub fn daemon_is_newer(daemon: &str, cli: &str) -> bool {
    version_numbers(daemon) > version_numbers(cli)
}

/// What to say when the running daemon is not this version. An update replaces
/// the program on disk while the old daemon keeps running, with its old code,
/// until someone restarts it; a security fix does nothing until then.
pub fn version_warning(daemon: &str, cli: &str) -> Option<String> {
    if daemon == cli {
        return None;
    }
    Some(if version_numbers(daemon) < version_numbers(cli) {
        format!(
            "warning: the Unseenkey service still running is version {daemon}; this usk is {cli}. \
             Fixes in the newer version, security fixes included, do nothing until it restarts. \
             Run: usk daemon restart"
        )
    } else {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        format!(
            "warning: the Unseenkey service running is version {daemon}, newer than this usk ({cli}). \
             This usk may be an old copy: {exe}"
        )
    })
}

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

type Response = ureq::http::Response<ureq::Body>;

/// The reply's JSON, whatever its size, as before: ureq 3 stops at 10 MB
/// unless told otherwise, and a long audit log from the local daemon may be
/// larger than that.
fn read_json(resp: Response) -> Result<Value, ureq::Error> {
    resp.into_body()
        .into_with_config()
        .limit(u64::MAX)
        .read_json()
}

/// What may not stand as it is in a path, and in a query. These are the URL
/// standard's sets, which ureq 2 applied by itself; `#` is added because
/// nothing here has a fragment, so one in a name belongs to the name.
const PATH_UNSAFE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'{')
    .add(b'}');
const QUERY_UNSAFE: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'#').add(b'<').add(b'>');

/// A path as the commands write it (`/v1/handles/stripe env`) in the form a
/// request line takes. Names with spaces or other such characters are
/// ordinary, and what is already encoded stays as it is.
fn wire_path(path: &str) -> String {
    match path.split_once('?') {
        Some((p, q)) => format!(
            "{}?{}",
            utf8_percent_encode(p, PATH_UNSAFE),
            utf8_percent_encode(q, QUERY_UNSAFE)
        ),
        None => utf8_percent_encode(path, PATH_UNSAFE).to_string(),
    }
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
        // A timeout per read and per write, not an overall deadline: a
        // deadline makes ureq set the socket timeout again before every read
        // (what is left of it), and macOS refuses that (EINVAL, "Invalid
        // argument") once the daemon has closed its side, failing a reply
        // that already arrived. A fixed value is set once.
        // A refusal is a reply to read, not an error: `handle` wants its body.
        let agent = ureq::Agent::config_builder()
            .max_idle_connections(0)
            .timeout_connect(Some(Duration::from_secs(3)))
            .timeout_per_read(Some(Duration::from_secs(30)))
            .timeout_per_write(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .build()
            .new_agent();
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
        match c.send("GET", "/v1/status", None) {
            Ok(r) if r.status() == 200 => {
                let status: Value = read_json(r).unwrap_or(Value::Null);
                if let Some(daemon) = status["version"].as_str() {
                    if let Some(words) = version_warning(daemon, env!("CARGO_PKG_VERSION")) {
                        if !VERSION_WARNING_DONE.swap(true, Ordering::Relaxed) {
                            eprintln!("{words}");
                        }
                    }
                }
                Some(c)
            }
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

    /// One request to the daemon, with the session token and, when this
    /// client holds one, the owner token. ureq decides from the method whether
    /// a request may carry a body, so the request is built from the `http`
    /// types and run as it is.
    fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Response, ureq::Error> {
        let mut req = ureq::http::Request::builder()
            .method(method)
            .uri(format!("{}{}", self.base, wire_path(path)))
            .header("Authorization", format!("Bearer {}", self.token));
        if let Some(o) = self
            .owner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            req = req.header(unseenkey_daemon::token::OWNER_HEADER, o.as_str());
        }
        match body {
            Some(v) => self.agent.run(
                req.header("Content-Type", "application/json")
                    .body(v.to_string())?,
            ),
            None => self.agent.run(req.body(())?),
        }
    }

    fn handle(r: Result<Response, ureq::Error>) -> Result<Value, CliError> {
        match r {
            Ok(resp) if resp.status().as_u16() < 400 => {
                read_json(resp).map_err(|e| CliError::general(format!("bad response: {e}")))
            }
            Ok(resp) => {
                let code = resp.status().as_u16();
                let body: Value = read_json(resp).unwrap_or(Value::Null);
                let err = body["error"].as_str().unwrap_or("error").to_string();
                // Not every refusal comes with words: the size limit answers with none.
                let msg = match (body["message"].as_str(), code) {
                    (Some(m), _) if !m.is_empty() => m.to_string(),
                    (_, 413) => "that is too large for the vault".to_string(),
                    _ => "the daemon gave no reason".to_string(),
                };
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
        Self::handle(self.send("GET", path, None))
    }
    /// POST JSON.
    pub fn post(&self, path: &str, body: Value) -> Result<Value, CliError> {
        Self::handle(self.send("POST", path, Some(&body)))
    }
    /// PATCH JSON.
    pub fn patch(&self, path: &str, body: Value) -> Result<Value, CliError> {
        Self::handle(self.send("PATCH", path, Some(&body)))
    }
    /// DELETE.
    pub fn delete(&self, path: &str) -> Result<Value, CliError> {
        Self::handle(self.send("DELETE", path, None))
    }

    /// `http://127.0.0.1:<port>` of the connected daemon.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// Does the MCP endpoint take this caller token? Anything but a clear yes is a no.
    pub fn mcp_token_works(&self, token: &str) -> bool {
        self.agent
            .post(&format!("{}/mcp", self.base))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .send(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
            .is_ok_and(|r| r.status() == 200)
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
        // An unlock also says where the settings now in force came from.
        match reply["settings"].as_str() {
            Some("reset") => eprintln!(
                "warning: this vault's settings were missing or could not be read, so the cautious ones are in force (care strict, lock after 15 minutes, on sleep and on screen lock, AI tools may not add keys). `usk log --kind settings_tampered` says why; set them again with `usk settings` and `usk care`."
            ),
            Some("unsettled") => eprintln!(
                "warning: this vault's settings could not be read or stored this time, so the cautious ones are in force until the next unlock. `usk status` and `usk doctor` may say why."
            ),
            _ => {}
        }
    }

    /// Prove the owner with the password on an unlocked vault (`POST /v1/confirm`)
    /// and keep the owner token it returns.
    pub fn confirm_with_password(&self, password: &str) -> Result<(), CliError> {
        let r = self.post("/v1/confirm", serde_json::json!({ "password": password }))?;
        self.remember_owner(&r);
        Ok(())
    }

    /// Unlock with a password this process already has (a vault it just made),
    /// so the person is not asked again a moment after choosing it.
    pub fn unlock_with(
        &self,
        password: &unseenkey_core::crypto::SecretBytes,
    ) -> Result<(), CliError> {
        let pw = std::str::from_utf8(password.expose())
            .map_err(|_| CliError::general("password is not valid UTF-8"))?;
        let r = self.post("/v1/unlock", serde_json::json!({ "password": pw }))?;
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

#[cfg(test)]
mod tests {
    use super::wire_path;

    #[test]
    fn a_name_with_a_space_makes_a_valid_request_path() {
        assert_eq!(
            wire_path("/v1/handles/stripe env"),
            "/v1/handles/stripe%20env"
        );
        assert_eq!(wire_path("/v1/secrets/a#b/test"), "/v1/secrets/a%23b/test");
        assert_eq!(wire_path("/v1/secrets/caf\u{e9}"), "/v1/secrets/caf%C3%A9");
        // A query keeps its shape, and what is encoded already is left alone.
        assert_eq!(
            wire_path("/v1/audit?kind=use&secret=my key"),
            "/v1/audit?kind=use&secret=my%20key"
        );
        assert_eq!(wire_path("/v1/secrets/a%20b"), "/v1/secrets/a%20b");
        for p in ["/v1/handles/stripe env", "/v1/audit?secret=my key"] {
            let uri = format!("http://127.0.0.1:1{}", wire_path(p));
            assert!(uri.parse::<ureq::http::Uri>().is_ok(), "{uri}");
        }
    }
}
