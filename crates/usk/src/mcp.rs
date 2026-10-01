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

/// Register `client` with the daemon and write its MCP config.
pub fn install(paths: &VaultPaths, client: &str, home: Option<&Path>) -> Result<(), CliError> {
    if client == "all" {
        for c in CLIENTS {
            install(paths, c, home)?;
        }
        return Ok(());
    }
    if !CLIENTS.contains(&client) && !unseenkey_daemon::callers::valid_name(client) {
        return Err(CliError::general(format!(
            "unknown client {client:?}; use one of {} or a custom name (a-z, 0-9, -)",
            CLIENTS.join(", ")
        )));
    }
    let c = Client::connect(paths, true)?;
    let created = c.post("/v1/callers", json!({ "name": client }))?;
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
    println!("removed MCP client {client}; delete the mcpServers.unseenkey entry from its config if you no longer want it");
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

/// stdio ⇄ `/mcp` bridge. Runs until stdin closes.
pub fn bridge(paths: &VaultPaths, client: &str) -> Result<(), CliError> {
    let token = std::fs::read_to_string(token_path(paths, client))
        .map(|t| t.trim().to_string())
        .map_err(|_| {
            CliError::general(format!(
                "no token for MCP client {client:?}; run `usk mcp install {client}`"
            ))
        })?;
    let c = Client::connect(paths, true)?;
    let url = format!("{}/mcp", c.base_url());
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(600))
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
        let req_id = serde_json::from_str::<Value>(&line)
            .ok()
            .and_then(|v| v.get("id").cloned());
        let resp = agent
            .post(&url)
            .set("Authorization", &format!("Bearer {token}"))
            .set("Content-Type", "application/json")
            .send_string(&line);
        let out = match resp {
            Ok(r) if r.status() == 202 => None,
            Ok(r) => Some(r.into_string().unwrap_or_default()),
            Err(ureq::Error::Status(_, r)) => Some(r.into_string().unwrap_or_default()),
            Err(e) => req_id.map(|id| {
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": format!("unseenkey daemon unreachable: {e}") } }).to_string()
            }),
        };
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
