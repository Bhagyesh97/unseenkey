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

/// The name the Claude Code plugin's bridge registers under.
const PLUGIN_CLIENT: &str = "claude-code-plugin";

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

/// How a person knows this client.
fn display_name(client: &str) -> &str {
    match client {
        "claude-code" => "Claude Code",
        "claude-desktop" => "Claude Desktop",
        "cursor" => "Cursor",
        "windsurf" => "Windsurf",
        other => other,
    }
}

/// A program on `PATH`. npm installs CLIs on Windows as `.cmd` files, which
/// `Command::new("claude")` does not find by the bare name.
fn find_program(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let extensions: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ".com"]
    } else {
        &[""]
    };
    std::env::split_paths(&path).find_map(|dir| {
        extensions
            .iter()
            .map(|e| dir.join(format!("{name}{e}")))
            .find(|p| p.is_file())
    })
}

/// The path a config should run: `on_path` if it leads to this same program.
/// On Linux `current_exe` follows links, so under Homebrew it names a versioned
/// folder that the next upgrade deletes; the link on `PATH` stays.
fn stable_exe(exe: &Path, on_path: Option<PathBuf>) -> PathBuf {
    let same = |p: &Path| match (std::fs::canonicalize(p), std::fs::canonicalize(exe)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    on_path
        .filter(|p| same(p))
        .unwrap_or_else(|| exe.to_path_buf())
}

fn config_exe() -> Result<PathBuf, CliError> {
    let exe =
        std::env::current_exe().map_err(|e| CliError::general(format!("current exe: {e}")))?;
    Ok(stable_exe(&exe, find_program("usk")))
}

/// What a client runs. `--vault` only for a vault the bridge would not find by
/// itself, and never for the desktop app, which starts the bridge only when
/// its arguments start with `mcp`.
fn bridge_args(paths: &VaultPaths, client: &str, cli: bool) -> Vec<String> {
    let mut args = Vec::new();
    if cli && VaultPaths::default_vault_file().as_deref() != Some(paths.vault.as_path()) {
        args.push("--vault".to_string());
        args.push(paths.vault.display().to_string());
    }
    args.extend(["mcp", "--client", client].map(String::from));
    args
}

/// The `mcpServers.unseenkey` entry for a client.
fn server_entry(exe: &Path, args: &[String]) -> Value {
    json!({ "command": exe.to_string_lossy(), "args": args })
}

/// A client's config as it stands, without changing anything. A file that
/// cannot be edited safely is an error here, before a token is replaced.
fn read_config(path: &Path, entry: &Value) -> Result<Value, CliError> {
    let refuse = |why: String| {
        let by_hand = json!({ "mcpServers": { "unseenkey": entry } });
        CliError::general(format!(
            "{} cannot be edited safely: {why}. It was left as it was. Fix the file, or add this to it yourself:\n{}",
            path.display(),
            serde_json::to_string_pretty(&by_hand).unwrap_or_default()
        ))
    };
    let root: Value = match std::fs::read_to_string(path) {
        Ok(t) if !t.trim().is_empty() => {
            serde_json::from_str(&t).map_err(|e| refuse(format!("it is not valid JSON ({e})")))?
        }
        _ => json!({}),
    };
    if !root.is_object() {
        return Err(refuse("it is not a JSON object".into()));
    }
    if root.get("mcpServers").is_some_and(|s| !s.is_object()) {
        return Err(refuse("its mcpServers is not a JSON object".into()));
    }
    Ok(root)
}

/// Add our entry to a config [`read_config`] accepted. Replaces the file in
/// one step, so a crash cannot leave the client's settings half written.
fn write_config(path: &Path, mut root: Value, entry: Value) -> Result<(), CliError> {
    root.as_object_mut()
        .unwrap()
        .entry("mcpServers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .unwrap()
        .insert("unseenkey".into(), entry);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CliError::general(e.to_string()))?;
    }
    let cannot =
        |e: std::io::Error| CliError::general(format!("cannot write {}: {e}", path.display()));
    let tmp = path.with_extension("usk-tmp");
    std::fs::write(
        &tmp,
        serde_json::to_string_pretty(&root).unwrap_or_default(),
    )
    .map_err(cannot)?;
    std::fs::rename(&tmp, path).map_err(cannot)
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

/// The clients installed on this machine that we know how to configure.
fn detect(home: Option<&Path>) -> Vec<&'static str> {
    let in_home = |rest: &[&str]| {
        home.map(Path::to_path_buf)
            .or_else(dirs::home_dir)
            .is_some_and(|h| rest.iter().fold(h, |p, r| p.join(r)).is_dir())
    };
    let desktop = home
        .map(Path::to_path_buf)
        .or_else(dirs::config_dir)
        .is_some_and(|d| d.join("Claude").is_dir());
    let mut found = Vec::new();
    if find_program("claude").is_some() {
        found.push("claude-code");
    }
    if desktop {
        found.push("claude-desktop");
    }
    if in_home(&[".cursor"]) || find_program("cursor").is_some() {
        found.push("cursor");
    }
    if in_home(&[".codeium", "windsurf"]) || find_program("windsurf").is_some() {
        found.push("windsurf");
    }
    found
}

/// `usk mcp install`: from nothing to a connected AI tool in one command.
/// With no `client` it connects every tool it finds. On a terminal it also
/// makes the vault if there is none and offers to add the first key; a program
/// never gets a vault it did not ask for with `new_vault`.
pub fn install(
    paths: &VaultPaths,
    client: Option<&str>,
    home: Option<&Path>,
    new_vault: bool,
) -> Result<(), CliError> {
    let tty = crate::io::is_tty();
    let mut names: Vec<String> = match client {
        Some("all") => CLIENTS.iter().map(|s| s.to_string()).collect(),
        Some(c) => vec![c.to_string()],
        None => detect(home).iter().map(|s| s.to_string()).collect(),
    };
    if names.is_empty() {
        return Err(CliError::general(format!(
            "no AI tool found on this computer. Install one, or name it: usk mcp install <{}>",
            CLIENTS.join("|")
        )));
    }
    let fresh_password = if paths.vault.exists() {
        None
    } else if new_vault || tty {
        println!("No vault yet, so let's make one first.\n");
        let pw = crate::cli::create_vault(paths)?;
        println!();
        Some(pw)
    } else {
        return Err(CliError::general(
            "no vault found; run `usk init` first, or pass --new-vault to make one here",
        ));
    };
    let c = Client::connect(paths, true)?;
    match &fresh_password {
        Some(pw) => c.unlock_with(pw)?,
        None => c.ensure_unlocked()?,
    }

    // The plugin brings the same tools; both would show Claude Code two sets.
    let has_plugin = c.get("/v1/callers").is_ok_and(|list| {
        list.as_array().is_some_and(|items| {
            items
                .iter()
                .any(|i| i["name"].as_str() == Some(PLUGIN_CLIENT))
        })
    });
    if has_plugin && names.iter().any(|n| n == "claude-code") {
        if client.is_none() {
            println!("Claude Code: already connected through the Unseenkey plugin");
            names.retain(|n| n != "claude-code");
        } else {
            println!("The Unseenkey plugin also connects Claude Code. Keep one of the two, or it gets the tools twice.");
        }
    }

    let mut connected = Vec::new();
    let mut failed = Vec::new();
    for name in &names {
        match install_one(&c, paths, name, home, true) {
            Ok(()) => connected.push(display_name(name).to_string()),
            Err(e) => {
                eprintln!("{}: {}", display_name(name), e.message);
                failed.push(display_name(name).to_string());
            }
        }
    }
    if !connected.is_empty() {
        next_steps(&c, paths, &connected, tty);
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(CliError::general(format!(
            "could not connect {}",
            failed.join(", ")
        )))
    }
}

/// What to do now that the tools are connected.
fn next_steps(c: &Client, paths: &VaultPaths, connected: &[String], tty: bool) {
    let no_keys = c
        .get("/v1/secrets")
        .is_ok_and(|list| list.as_array().is_some_and(Vec::is_empty));
    let mut still_no_keys = no_keys;
    if no_keys && tty {
        println!();
        let name = crate::io::read_line(
            "Your vault has no keys yet. Name your first key (like openai), or press Enter to skip: ",
        )
        .unwrap_or_default();
        if !name.is_empty() {
            match crate::cli::add_first_key(paths, name) {
                Ok(()) => still_no_keys = false,
                Err(e) => eprintln!("{}", e.message),
            }
        }
    }
    println!();
    if still_no_keys {
        println!("Add a key:  usk add openai   (any name; you paste the key at a hidden prompt)");
    }
    println!(
        "Restart {}, then ask: \"What API keys can you use through Unseenkey?\"",
        connected.join(" and ")
    );
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
    install_one(&c, paths, client, home, false)
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

/// Add the server to Claude Code. An entry that is already there may name an
/// old path; it is ours, so it is replaced. `Err` is the command to run by hand.
fn add_to_claude_code(exe: &Path, args: &[String]) -> Result<(), String> {
    let by_hand = format!(
        "claude mcp add --scope user unseenkey -- \"{}\" {}",
        exe.display(),
        args.join(" ")
    );
    let claude = find_program("claude").ok_or_else(|| by_hand.clone())?;
    let add = || {
        std::process::Command::new(&claude)
            .args(["mcp", "add", "--scope", "user", "unseenkey", "--"])
            .arg(exe)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .is_ok_and(|o| o.status.success())
    };
    if add() {
        return Ok(());
    }
    let _ = std::process::Command::new(&claude)
        .args(["mcp", "remove", "--scope", "user", "unseenkey"])
        .stdin(std::process::Stdio::null())
        .output();
    if add() {
        Ok(())
    } else {
        Err(by_hand)
    }
}

/// Run the bridge just as the client will and ask it for its tools.
fn bridge_answers(exe: &Path, args: &[String]) -> Result<(), String> {
    let mut child = std::process::Command::new(exe)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", exe.display()))?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list"}}"#)
        .map_err(|e| e.to_string())?;
    drop(stdin);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(Ok(o)) if String::from_utf8_lossy(&o.stdout).contains("call_api") => Ok(()),
        Ok(Ok(o)) => Err(format!(
            "it did not list its tools: {}",
            String::from_utf8_lossy(&o.stdout).trim()
        )),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("it did not answer within 10 seconds".into()),
    }
}

/// Connect one client. Safe to repeat: a client whose token still works keeps
/// it and needs no password. `cli` is false for the desktop app, which has its
/// own words for the result and runs the bridge from its own executable.
fn install_one(
    c: &Client,
    paths: &VaultPaths,
    client: &str,
    home: Option<&Path>,
    cli: bool,
) -> Result<(), CliError> {
    if !CLIENTS.contains(&client) && !unseenkey_daemon::callers::valid_name(client) {
        return Err(CliError::general(format!(
            "unknown client {client:?}; use one of {} or a custom name (a-z, 0-9, -)",
            CLIENTS.join(", ")
        )));
    }
    let exe = if cli {
        config_exe()?
    } else {
        std::env::current_exe().map_err(|e| CliError::general(format!("current exe: {e}")))?
    };
    let args = bridge_args(paths, client, cli);
    let entry = server_entry(&exe, &args);
    let config = config_path(client, home);
    let current = config
        .as_ref()
        .map(|p| read_config(p, &entry))
        .transpose()?;

    let keeps_token = read_token(paths, client).is_some_and(|t| c.mcp_token_works(&t));
    if !keeps_token {
        let created = register(c, client, cli)?;
        let token = created["token"]
            .as_str()
            .ok_or_else(|| CliError::general("daemon returned no token"))?;
        write_token(&token_path(paths, client), token)?;
    }

    let name = display_name(client);
    let state = if keeps_token {
        "already connected"
    } else {
        "connected"
    };
    match (client, config, current) {
        ("claude-code", _, _) => match add_to_claude_code(&exe, &args) {
            Ok(()) => println!("{name}: {state}"),
            Err(by_hand) => {
                return Err(CliError::general(format!(
                    "the `claude` command did not work. Run this yourself:\n  {by_hand}"
                )))
            }
        },
        (_, Some(path), Some(root)) => {
            write_config(&path, root, entry)?;
            println!("{name}: {state} ({})", path.display());
        }
        _ => println!(
            "{name}: {state}. No known config location; add this to its MCP settings:\n{}",
            serde_json::to_string_pretty(&json!({ "mcpServers": { "unseenkey": entry } }))
                .unwrap_or_default()
        ),
    }
    if cli {
        bridge_answers(&exe, &args)
            .map_err(|why| CliError::general(format!("set up, but the check failed: {why}")))?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_config_runs_the_link_on_path_not_the_versioned_folder() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("Cellar").join("0.1.9");
        std::fs::create_dir_all(&real).unwrap();
        let exe = real.join("usk");
        std::fs::write(&exe, "").unwrap();
        let link = dir.path().join("usk");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        assert_eq!(stable_exe(&exe, Some(link.clone())), link);
    }

    #[test]
    fn a_config_runs_this_program_when_path_leads_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let (exe, other) = (dir.path().join("usk"), dir.path().join("other"));
        std::fs::write(&exe, "").unwrap();
        std::fs::write(&other, "").unwrap();
        assert_eq!(stable_exe(&exe, Some(other)), exe);
        assert_eq!(stable_exe(&exe, None), exe);
    }

    #[test]
    fn a_config_that_cannot_be_edited_is_refused_with_the_entry_to_add() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        let entry = json!({ "command": "usk", "args": ["mcp", "--client", "cursor"] });
        for bad in ["{ // a comment\n}", "[]", r#"{"mcpServers": []}"#] {
            std::fs::write(&path, bad).unwrap();
            let e = read_config(&path, &entry).unwrap_err();
            assert!(e.message.contains("left as it was"), "{}", e.message);
            assert!(e.message.contains("--client"), "{}", e.message);
            assert_eq!(std::fs::read_to_string(&path).unwrap(), bad);
        }
        std::fs::write(
            &path,
            r#"{"mcpServers": {"other": {"command": "x"}}, "theme": 1}"#,
        )
        .unwrap();
        let root = read_config(&path, &entry).unwrap();
        write_config(&path, root, entry).unwrap();
        let after: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(after["theme"], 1);
        assert_eq!(after["mcpServers"]["other"]["command"], "x");
        assert_eq!(after["mcpServers"]["unseenkey"]["command"], "usk");
        assert!(!path.with_extension("usk-tmp").exists());
    }
}
