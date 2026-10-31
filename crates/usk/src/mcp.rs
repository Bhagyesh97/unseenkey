//! `usk mcp`: register MCP clients, write their configs, and bridge stdio to
//! the daemon's `/mcp` endpoint.
//!
//! The protocol lives in the daemon; this bridge forwards one JSON-RPC line per
//! request and writes the reply. Nothing but protocol goes to stdout.

use crate::client::Client;
use crate::io::CliError;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use unseenkey_daemon::VaultPaths;

/// Clients we know how to configure.
pub const CLIENTS: &[&str] = &["claude-code", "claude-desktop", "cursor", "windsurf"];

fn token_path(paths: &VaultPaths, client: &str) -> PathBuf {
    paths.mcp.join(format!("{client}.token"))
}

fn write_token(path: &Path, token: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CliError::general(e.to_string()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| CliError::general(e.to_string()))?;
        f.write_all(token.as_bytes())
            .map_err(|e| CliError::general(e.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, token).map_err(|e| CliError::general(e.to_string()))?;
    }
    Ok(())
}

/// The `mcpServers.unseenkey` entry for a client.
fn server_entry(client: &str) -> Result<Value, CliError> {
    let exe =
        std::env::current_exe().map_err(|e| CliError::general(format!("current exe: {e}")))?;
    Ok(json!({ "command": exe.to_string_lossy(), "args": ["mcp", "--client", client] }))
}

/// Merge our entry into a `{"mcpServers": {...}}` JSON config file.
fn merge_config(path: &Path, client: &str) -> Result<(), CliError> {
    let mut root: Value = match std::fs::read_to_string(path) {
        Ok(t) if !t.trim().is_empty() => serde_json::from_str(&t)
            .map_err(|e| CliError::general(format!("{} is not valid JSON: {e}", path.display())))?,
        _ => json!({}),
    };
    if !root.is_object() {
        return Err(CliError::general(format!(
            "{} is not a JSON object",
            path.display()
        )));
    }
    let servers = root
        .as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| json!({}));
    if !servers.is_object() {
        *servers = json!({});
    }
    servers
        .as_object_mut()
        .unwrap()
        .insert("unseenkey".into(), server_entry(client)?);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CliError::general(e.to_string()))?;
    }
    std::fs::write(
        path,
        serde_json::to_string_pretty(&root).unwrap_or_default(),
    )
    .map_err(|e| CliError::general(format!("cannot write {}: {e}", path.display())))?;
    println!("wrote {} (mcpServers.unseenkey)", path.display());
    Ok(())
}

fn config_path(client: &str, home: Option<&Path>) -> Option<PathBuf> {
    let (base, rest): (Option<PathBuf>, &[&str]) = match client {
        "claude-desktop" => (
            home.map(Path::to_path_buf).or_else(dirs::config_dir),
            &["Claude", "claude_desktop_config.json"],
        ),
        "cursor" => (
            home.map(Path::to_path_buf).or_else(dirs::home_dir),
            &[".cursor", "mcp.json"],
        ),
        "windsurf" => (
            home.map(Path::to_path_buf).or_else(dirs::home_dir),
            &[".codeium", "windsurf", "mcp_config.json"],
        ),
        _ => return None,
    };
    let mut p = base?;
    for r in rest {
        p.push(r);
    }
    Some(p)
}

/// Register `client` with the daemon and write its MCP config. Unlocks the
/// vault first if needed (registrations are audited), and asks for the
/// password again only to replace a client that is already registered.
pub fn install(paths: &VaultPaths, client: &str, home: Option<&Path>) -> Result<(), CliError> {
    let c = Client::connect(paths, true)?;
    c.ensure_unlocked()?;
    install_with(&c, paths, client, home, true)
}

/// [`install`] for a caller that cannot prompt (the desktop app): it passes
/// the owner token it holds, and replacing an existing client fails with
/// `owner_required` when there is none.
pub fn install_as(
    paths: &VaultPaths,
    client: &str,
    home: Option<&Path>,
    owner: Option<String>,
) -> Result<(), CliError> {
    let c = Client::connect(paths, true)?;
    c.set_owner(owner);
    install_with(&c, paths, client, home, false)
}

/// `POST /v1/callers`; on `caller_exists` or `caller_removed`, confirm the
/// owner and register anyway.
fn register(c: &Client, client: &str, prompt: bool) -> Result<Value, CliError> {
    match c.post("/v1/callers", json!({ "name": client })) {
        Err(e) if e.kind == "caller_exists" || e.kind == "caller_removed" => {
            let why = if e.kind == "caller_exists" {
                format!("{client} is already registered; replacing its token")
            } else {
                format!("{client} was disconnected; reconnecting it")
            };
            if prompt {
                if c.owner().is_none() {
                    println!("{why} needs your password.");
                }
                c.ensure_owner()?;
            } else if c.owner().is_none() {
                return Err(CliError::with_code(
                    1,
                    "owner_required",
                    format!("{why} needs the owner; confirm it is you, then try again"),
                ));
            }
            c.post("/v1/callers", json!({ "name": client, "replace": true }))
        }
        other => other,
    }
}

fn install_with(
    c: &Client,
    paths: &VaultPaths,
    client: &str,
    home: Option<&Path>,
    prompt: bool,
) -> Result<(), CliError> {
    if client == "all" {
        for name in CLIENTS {
            install_with(c, paths, name, home, prompt)?;
        }
        return Ok(());
    }
    if !CLIENTS.contains(&client) && !unseenkey_daemon::callers::valid_name(client) {
        return Err(CliError::general(format!(
            "unknown client {client:?}; use one of {} or a custom name (a-z, 0-9, -)",
            CLIENTS.join(", ")
        )));
    }
    let created = register(c, client, prompt)?;
    let token = created["token"]
        .as_str()
        .ok_or_else(|| CliError::general("daemon returned no token"))?;
    let tp = token_path(paths, client);
    write_token(&tp, token)?;
    println!(
        "registered MCP client {client} (identity mcp:{client}); token stored in {}",
        tp.display()
    );

    match client {
        "claude-code" => {
            let exe = std::env::current_exe().map_err(|e| CliError::general(e.to_string()))?;
            let exe_s = exe.to_string_lossy().to_string();
            let status = std::process::Command::new("claude")
                .args([
                    "mcp",
                    "add",
                    "--scope",
                    "user",
                    "unseenkey",
                    "--",
                    &exe_s,
                    "mcp",
                    "--client",
                    "claude-code",
                ])
                .stdin(std::process::Stdio::null())
                .status();
            match status {
                Ok(s) if s.success() => println!("added to Claude Code (user scope): claude mcp list"),
                _ => println!(
                    "could not run `claude mcp add`; run this yourself:\n  claude mcp add --scope user unseenkey -- \"{exe_s}\" mcp --client claude-code"
                ),
            }
        }
        other => {
            let path = config_path(other, home);
            match path {
                Some(p) => merge_config(&p, other)?,
                None => println!(
                    "no known config location for {other}; add this to its MCP settings:\n{}",
                    serde_json::to_string_pretty(
                        &json!({ "mcpServers": { "unseenkey": server_entry(other)? } })
                    )
                    .unwrap_or_default()
                ),
            }
        }
    }
    println!("restart {client} to pick it up. Remove with: usk mcp remove {client}");
    Ok(())
}

/// Forget a client: daemon registry, token file (configs are left for the user).
pub fn remove(paths: &VaultPaths, client: &str) -> Result<(), CliError> {
    if let Some(c) = Client::try_connect(paths) {
        let _ = c.delete(&format!("/v1/callers/{client}"));
    }
    let _ = std::fs::remove_file(token_path(paths, client));
    println!("removed MCP client {client}; it stays disconnected until you run `usk mcp install {client}`. You can also delete the unseenkey entry from its MCP config (or disable the plugin)");
    Ok(())
}

/// List registered clients.
pub fn clients(paths: &VaultPaths, json_out: bool) -> Result<(), CliError> {
    let c = Client::connect(paths, true)?;
    let list = c.get("/v1/callers")?;
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&list).unwrap_or_default()
        );
        return Ok(());
    }
    let items = list.as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        println!("No MCP clients. Register one with `usk mcp install cursor` (or claude-code, claude-desktop, windsurf).");
        return Ok(());
    }
    for i in items {
        println!(
            "{:<16} {}  token file: {}",
            i["name"].as_str().unwrap_or(""),
            i["caller"].as_str().unwrap_or(""),
            if token_path(paths, i["name"].as_str().unwrap_or("")).exists() {
                "present"
            } else {
                "missing"
            }
        );
    }
    Ok(())
}

/// The folder the MCP client is working in: `USK_PROJECT_DIR` if set, then
/// `CLAUDE_PROJECT_DIR` (Claude Code), then the folder the client started
/// this bridge in. The daemon scopes the client to the project covering it.
fn client_dir() -> Option<String> {
    ["USK_PROJECT_DIR", "CLAUDE_PROJECT_DIR"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
        .or_else(|| {
            std::env::current_dir()
                .ok()
                .map(|d| d.display().to_string())
        })
}

fn read_token(paths: &VaultPaths, client: &str) -> Option<String> {
    std::fs::read_to_string(token_path(paths, client))
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Why a bridge has no caller token. Until it has one it answers the
/// handshake itself, gives the reason as the result of every tool call, and
/// tries again before each message.
enum Waiting {
    /// Registering needs an unlocked vault (every registration is audited).
    Locked,
    /// The name is registered and this bridge has no token for it.
    Taken,
    /// The owner disconnected this name.
    Removed,
    /// No vault on this machine.
    NoVault,
    /// The daemon would not start, or refused for another reason.
    Failed(String),
}

impl Waiting {
    fn explain(&self, client: &str) -> String {
        match self {
            Waiting::Locked => "Unseenkey is locked, so this AI tool is not connected to it yet. Ask the user to unlock it (open the Unseenkey app, or run `usk unlock`), then try again.".into(),
            Waiting::Taken => format!("An AI tool named \"{client}\" is already connected to Unseenkey, and this one has no token for it. Ask the user to run `usk mcp install {client}` to reconnect it."),
            Waiting::Removed => format!("The user disconnected this AI tool from Unseenkey. If they want it back, they can run `usk mcp install {client}`."),
            Waiting::NoVault => "Unseenkey is not set up on this computer. Ask the user to install it (https://unseenkey.com) and run `usk init`, then try again.".into(),
            Waiting::Failed(e) => format!("This AI tool could not connect to Unseenkey: {e}. Ask the user to open the Unseenkey app, then try again."),
        }
    }
}

/// Register `client` with the session token and keep its token (0600). A new
/// name gets what an AI tool's first use of a key gets anyway; an existing or
/// disconnected name is never taken over from here, that needs the owner.
fn self_register(paths: &VaultPaths, client: &str) -> Result<String, Waiting> {
    if !paths.vault.exists() {
        return Err(Waiting::NoVault);
    }
    let c = Client::connect(paths, true).map_err(|e| Waiting::Failed(e.message))?;
    match c.post("/v1/callers", json!({ "name": client })) {
        Ok(v) => {
            let token = v["token"]
                .as_str()
                .ok_or_else(|| Waiting::Failed("the daemon returned no token".into()))?;
            write_token(&token_path(paths, client), token)
                .map_err(|e| Waiting::Failed(e.message))?;
            eprintln!("unseenkey: registered MCP client {client}");
            Ok(token.to_string())
        }
        Err(e) => Err(match e.kind.as_str() {
            "vault_locked" => Waiting::Locked,
            "caller_exists" => Waiting::Taken,
            "caller_removed" => Waiting::Removed,
            _ => Waiting::Failed(e.message),
        }),
    }
}

/// The answer to `msg` from a bridge without a token: the handshake and the
/// lists as the daemon would give them (the reason added to the
/// instructions), and `why` for everything else. `None` for notifications.
fn waiting_reply(msg: &Value, why: &str) -> Option<Value> {
    if let Value::Array(batch) = msg {
        let replies: Vec<Value> = batch.iter().filter_map(|m| waiting_reply(m, why)).collect();
        return (!replies.is_empty()).then_some(Value::Array(replies));
    }
    let id = msg.get("id")?.clone();
    let method = msg["method"].as_str().unwrap_or("");
    let result = match unseenkey_daemon::mcp::static_result(method, false) {
        Some(mut r) => {
            if let Some(text) = r["instructions"].as_str() {
                r["instructions"] = json!(format!("{text} {why}"));
            }
            r
        }
        None if method == "tools/call" => {
            json!({ "content": [{ "type": "text", "text": why }], "isError": true })
        }
        None => {
            return Some(
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": why } }),
            )
        }
    };
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

/// stdio ⇄ `/mcp` bridge. Runs until stdin closes.
///
/// With no token file it registers `client` itself ([`self_register`]), so
/// an MCP config or plugin that runs `usk mcp --client <name>` needs no
/// `usk mcp install` first. Until that works it keeps the client's session
/// alive and says what the user has to do.
pub fn bridge(paths: &VaultPaths, client: &str) -> Result<(), CliError> {
    if !CLIENTS.contains(&client) && !unseenkey_daemon::callers::valid_name(client) {
        return Err(CliError::general(format!(
            "invalid client name {client:?}: use a-z, 0-9 and -"
        )));
    }
    let mut token = read_token(paths, client);
    let mut url: Option<String> = None;
    let dir = client_dir().map(|d| unseenkey_core::projects::encode_dir(&d));
    // Long enough for an approval to be answered; read and write timeouts
    // rather than a deadline, see `Client`.
    let agent = ureq::AgentBuilder::new()
        .timeout_read(std::time::Duration::from_secs(600))
        .timeout_write(std::time::Duration::from_secs(600))
        .build();
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let parsed = serde_json::from_str::<Value>(&line).ok();
        let req_id = parsed.as_ref().and_then(|v| v.get("id").cloned());
        // A second try only after a 401: the token was replaced or removed.
        let mut out = None;
        for _ in 0..2 {
            if token.is_none() {
                // `usk mcp install` or another session may have written it.
                token = read_token(paths, client);
            }
            if token.is_none() {
                match self_register(paths, client) {
                    Ok(t) => token = Some(t),
                    Err(w) => {
                        let why = w.explain(client);
                        out = match &parsed {
                            Some(msg) => waiting_reply(msg, &why).map(|v| v.to_string()),
                            None => req_id.clone().map(|id| {
                                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32700, "message": "parse error" } }).to_string()
                            }),
                        };
                        break;
                    }
                }
            }
            let Some(tok) = token.clone() else { break };
            if url.is_none() {
                match Client::connect(paths, true) {
                    Ok(c) => url = Some(format!("{}/mcp", c.base_url())),
                    Err(e) => {
                        out = req_id.clone().map(|id| {
                            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": format!("unseenkey daemon unreachable: {}", e.message) } }).to_string()
                        });
                        break;
                    }
                }
            }
            let mut req = agent
                .post(url.as_deref().unwrap_or_default())
                .set("Authorization", &format!("Bearer {tok}"))
                .set("Content-Type", "application/json");
            if let Some(d) = &dir {
                req = req.set(unseenkey_daemon::mcp::PROJECT_DIR_HEADER, d);
            }
            out = match req.send_string(&line) {
                Ok(r) if r.status() == 202 => None,
                Ok(r) => Some(r.into_string().unwrap_or_default()),
                Err(ureq::Error::Status(401, _)) => {
                    // Kept if the second try is refused as well.
                    out = req_id.clone().map(|id| {
                        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": format!("Unseenkey refused this AI tool's token. Ask the user to run `usk mcp install {client}`.") } }).to_string()
                    });
                    token = None;
                    continue;
                }
                Err(ureq::Error::Status(_, r)) => Some(r.into_string().unwrap_or_default()),
                Err(e) => {
                    // The daemon may have restarted on another port.
                    url = None;
                    req_id.clone().map(|id| {
                        json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": format!("unseenkey daemon unreachable: {e}") } }).to_string()
                    })
                }
            };
            break;
        }
        if let Some(text) = out {
            if text.trim().is_empty() {
                continue;
            }
            if writeln!(stdout, "{}", text.trim()).is_err() {
                break;
            }
            let _ = stdout.flush();
        }
    }
    Ok(())
}
