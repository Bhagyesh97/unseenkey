//! Unseenkey desktop (Tauri 2).
//!
//! The webview never speaks HTTP. Every call goes through a Tauri command on
//! this Rust side, which holds the daemon session token and forwards to the
//! loopback management API, starting the daemon when needed. Daemon events
//! (SSE) are pumped into Tauri events so the UI can show approval prompts live.

mod hello;

use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::VaultPaths;
use usk::client::Client;

struct AppData {
    paths: VaultPaths,
    /// Serialises daemon start-ups so two commands do not spawn two daemons.
    connect_lock: Mutex<()>,
    /// The owner token from this app's unlock or confirmation. It stays in
    /// this process: it is what lets the app reveal, approve and change
    /// policies while a program that merely reads `daemon.token` cannot.
    owner: Mutex<Option<String>>,
}

impl AppData {
    fn owner(&self) -> Option<String> {
        self.owner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn set_owner(&self, token: Option<String>) {
        *self.owner.lock().unwrap_or_else(|e| e.into_inner()) = token;
    }
    /// Keep the owner token an unlock or confirmation reply carries.
    fn remember_owner(&self, reply: &Value) {
        if let Some(t) = reply["owner_token"].as_str() {
            self.set_owner(Some(t.to_string()));
        }
    }
}

fn paths() -> Result<VaultPaths, String> {
    let vault = usk::daemon::vault_path(std::env::var_os("USK_VAULT").map(Into::into))
        .map_err(|e| e.message)?;
    Ok(VaultPaths::from_vault_file(&vault))
}

fn client(data: &AppData) -> Result<Client, String> {
    let _g = data.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
    let c = Client::connect(&data.paths, true).map_err(|e| format!("{}: {}", e.kind, e.message))?;
    c.set_owner(data.owner());
    Ok(c)
}

fn err_string(e: usk::io::CliError) -> String {
    format!("{}: {}", e.kind, e.message)
}

/// Confirm the owner through Windows Hello, when it is enrolled: the daemon
/// gets the KEK Hello derives and answers with an owner token. `Ok(false)`
/// when Hello is not available for this vault; the UI then asks for the
/// password instead.
fn confirm_with_hello(data: &AppData, c: &Client) -> Result<bool, String> {
    if !hello::available() {
        return Ok(false);
    }
    let status = c.get("/v1/status").map_err(err_string)?;
    let vault_id = status["vault_id"].as_str().unwrap_or_default().to_string();
    let methods = c.get("/v1/unlock-methods").map_err(err_string)?;
    let Some(m) = methods
        .as_array()
        .into_iter()
        .flatten()
        .rev()
        .find(|m| m["kind"] == hello::KIND)
        .cloned()
    else {
        return Ok(false);
    };
    let salt = unb64_32(m["salt"].as_str().unwrap_or_default())?;
    let kek = hello::derive_kek(&vault_id, &salt)?;
    let r = c
        .post(
            "/v1/confirm",
            json!({ "wrap_id": m["id"], "kek": b64(kek.expose()) }),
        )
        .map_err(err_string)?;
    data.remember_owner(&r);
    c.set_owner(data.owner());
    Ok(true)
}

/// Confirm the owner with the vault password (the UI's fallback when Windows
/// Hello is not enrolled or was dismissed).
#[tauri::command(async)]
fn confirm_owner(state: tauri::State<'_, AppData>, password: String) -> Result<(), String> {
    let c = client(&state)?;
    c.confirm_with_password(&password).map_err(err_string)?;
    state.set_owner(c.owner());
    Ok(())
}

#[tauri::command(async)]
fn status(state: tauri::State<'_, AppData>) -> Result<Value, String> {
    let daemon = Client::try_connect(&state.paths).and_then(|c| c.get("/v1/status").ok());
    let exists = state.paths.vault.exists()
        && SqliteStorage::open(&state.paths.vault)
            .ok()
            .and_then(|s| Vault::open(s, SystemClock).ok())
            .is_some();
    Ok(json!({
        "vault_path": state.paths.vault.display().to_string(),
        "vault_exists": exists,
        "daemon": daemon,
        "app_version": env!("CARGO_PKG_VERSION"),
    }))
}

#[tauri::command(async)]
fn create_vault(state: tauri::State<'_, AppData>, password: String) -> Result<Value, String> {
    if password.len() < 12 {
        return Err("invalid: password must be at least 12 characters".into());
    }
    std::fs::create_dir_all(&state.paths.dir).map_err(|e| format!("io: {e}"))?;
    let storage = SqliteStorage::open(&state.paths.vault).map_err(|e| e.to_string())?;
    let (v, kit) = Vault::create(
        storage,
        SystemClock,
        &SecretBytes::from(password.as_str()),
        Argon2Profile::DESKTOP,
    )
    .map_err(|e| e.to_string())?;
    let vault_id = v.vault_id().to_hex();
    let words: Vec<String> = kit.words().iter().map(|w| w.to_string()).collect();
    drop(v);
    drop(kit);
    // Start the daemon and unlock it with the same password so the first screen
    // after the recovery phrase is the secrets list, not another prompt.
    let c = client(&state)?;
    let r = c
        .post("/v1/unlock", json!({ "password": password }))
        .map_err(err_string)?;
    state.remember_owner(&r);
    Ok(json!({ "vault_id": vault_id, "words": words }))
}

#[tauri::command(async)]
fn unlock(state: tauri::State<'_, AppData>, password: String) -> Result<(), String> {
    let c = client(&state)?;
    let r = c
        .post("/v1/unlock", json!({ "password": password }))
        .map_err(err_string)?;
    state.remember_owner(&r);
    Ok(())
}

/// Stop whatever daemon serves the vault and start this app's own. Used when
/// the running one is another version (an older install, a developer build
/// that an MCP client started first). The vault comes back locked.
#[tauri::command(async)]
fn restart_daemon(state: tauri::State<'_, AppData>) -> Result<(), String> {
    let _g = state.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = Client::try_connect(&state.paths) {
        let _ = c.post("/v1/shutdown", json!({}));
        let gone = usk::daemon::wait_until(std::time::Duration::from_secs(10), || {
            Client::try_connect(&state.paths).is_none().then_some(())
        });
        if gone.is_none() {
            return Err("error: the running service did not stop; quit it from its tray icon or restart the computer".into());
        }
    }
    Client::connect(&state.paths, true)
        .map(|_| ())
        .map_err(err_string)
}

#[tauri::command(async)]
fn lock(state: tauri::State<'_, AppData>) -> Result<(), String> {
    state.set_owner(None);
    if let Some(c) = Client::try_connect(&state.paths) {
        c.post("/v1/lock", json!({})).map_err(err_string)?;
    }
    Ok(())
}

/// Generic management call: the UI is our own code, so it may use the same
/// routes the CLI uses. Only `/v1/…` paths are allowed. A route that needs the
/// owner is retried once after confirming through Windows Hello; without
/// Hello the `owner_required` error reaches the UI, which asks for the
/// password and calls `confirm_owner`.
#[tauri::command(async)]
fn api(
    state: tauri::State<'_, AppData>,
    method: String,
    path: String,
    body: Option<Value>,
) -> Result<Value, String> {
    if !path.starts_with("/v1/") {
        return Err("invalid: only /v1 routes".into());
    }
    let c = client(&state)?;
    let call = |c: &Client| match method.as_str() {
        "GET" => c.get(&path),
        "POST" => c.post(&path, body.clone().unwrap_or(json!({}))),
        "PATCH" => c.patch(&path, body.clone().unwrap_or(json!({}))),
        "DELETE" => c.delete(&path),
        _ => Err(usk::io::CliError::general("invalid: method")),
    };
    if !matches!(method.as_str(), "GET" | "POST" | "PATCH" | "DELETE") {
        return Err("invalid: method".into());
    }
    match call(&c) {
        Err(e) if e.kind == "owner_required" => {
            if confirm_with_hello(&state, &c)? {
                call(&c).map_err(err_string)
            } else {
                Err(err_string(e))
            }
        }
        r => r.map_err(err_string),
    }
}

#[tauri::command(async)]
fn presets() -> Vec<Value> {
    unseenkey_core::presets::all()
        .map(|p| {
            json!({
                "id": p.id, "display": p.display, "upstreams": p.upstreams, "docs": p.docs,
                "camouflage": !p.handle_formats.is_empty(),
                "category": p.category, "testable": p.verify.is_some(),
                "policies": p.policies.iter().map(|pp| json!({
                    "id": pp.id, "display": pp.display, "recommended": pp.recommended,
                    "explanation": p.policy(&pp.id).map(|pol| unseenkey_core::policy::explain(&pol)).unwrap_or_default(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

#[tauri::command(async)]
fn install_mcp(state: tauri::State<'_, AppData>, client: String) -> Result<String, String> {
    if !usk::mcp::CLIENTS.contains(&client.as_str()) {
        return Err(format!("invalid: unknown client {client}"));
    }
    // The installer talks to the daemon (registers the caller) and writes the
    // client's config file; it prints to stdout, which the app has no use for.
    let _g = state.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
    usk::mcp::install(&state.paths, &client, None).map_err(err_string)?;
    Ok(format!(
        "Registered {client} and wrote its MCP config. Restart {client}, then ask it to list your unseenkey secrets."
    ))
}

#[tauri::command(async)]
fn guard_scan(path: String) -> Result<Vec<Value>, String> {
    let text = std::fs::read_to_string(&path).map_err(|e| format!("io: {e}"))?;
    let entries = unseenkey_core::import::parse_dotenv(&text);
    Ok(entries
        .iter()
        .filter(|e| e.looks_secret)
        .map(|e| {
            let fixable = e
                .detection
                .and_then(|d| unseenkey_core::presets::get(d.provider))
                .is_some()
                && !core::str::from_utf8(e.value.expose())
                    .is_ok_and(|s| unseenkey_core::presets::is_handle(s.trim()));
            json!({ "line": e.line, "key": e.key, "detected": e.detection.map(|d| d.display), "fixable": fixable })
        })
        .collect())
}

/// The env files in a project folder that exist, most common first.
#[tauri::command(async)]
fn env_files(dir: String) -> Vec<String> {
    [
        ".env",
        ".env.local",
        ".env.development",
        ".env.development.local",
        ".env.production",
    ]
    .iter()
    .map(|f| std::path::Path::new(&dir).join(f))
    .filter(|p| p.is_file())
    .map(|p| p.display().to_string())
    .collect()
}

#[tauri::command(async)]
fn guard_fix(
    state: tauri::State<'_, AppData>,
    path: String,
    project: Option<String>,
) -> Result<String, String> {
    let _g = state.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
    usk::guard::fix_for(
        &state.paths,
        std::path::Path::new(&path),
        false,
        project.as_deref(),
    )
    .map_err(err_string)?;
    Ok(format!(
        "Rewrote {path}: real keys moved into the vault and replaced with handles."
    ))
}

/// Host the daemon in this process. Used when the app re-executes itself as
/// `--vault <path> daemon run --detached` (see `main.rs`).
pub fn run_daemon(args: &[String]) -> Result<(), usk::io::CliError> {
    let mut vault = std::env::var_os("USK_VAULT").map(std::path::PathBuf::from);
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--vault" {
            vault = args.get(i + 1).map(std::path::PathBuf::from);
            i += 1;
        }
        i += 1;
    }
    let vault = usk::daemon::vault_path(vault)?;
    let paths = VaultPaths::from_vault_file(&vault);
    let opts = usk::daemon::resolve_options(&paths, None, None)?;
    usk::daemon::run(opts, &paths, true)
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64_32(s: &str) -> Result<[u8; 32], String> {
    use base64::Engine as _;
    let v = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| "invalid: salt is not base64".to_string())?;
    v.try_into().map_err(|_| "invalid: salt length".to_string())
}

/// Device unlock methods on the vault plus whether this machine can use them.
#[tauri::command(async)]
fn device_unlock_status(state: tauri::State<'_, AppData>) -> Result<Value, String> {
    let methods = match Client::try_connect(&state.paths) {
        Some(c) => c.get("/v1/unlock-methods").map_err(err_string)?,
        None => json!([]),
    };
    let enrolled = methods
        .as_array()
        .map(|a| a.iter().any(|m| m["kind"] == hello::KIND))
        .unwrap_or(false);
    Ok(json!({
        "available": hello::available(),
        "enrolled": enrolled,
        "methods": methods,
    }))
}

/// Enroll Windows Hello for this vault (vault must be unlocked). Replaces any
/// earlier Hello enrollment.
#[tauri::command(async)]
fn device_unlock_enroll(state: tauri::State<'_, AppData>) -> Result<String, String> {
    if !hello::available() {
        return Err("unsupported: Windows Hello is not set up on this computer".into());
    }
    let c = client(&state)?;
    let status = c.get("/v1/status").map_err(err_string)?;
    if status["locked"].as_bool().unwrap_or(true) {
        return Err("locked: unlock the vault first".into());
    }
    let vault_id = status["vault_id"].as_str().unwrap_or_default().to_string();
    hello::create_key(&vault_id)?;
    let salt = unseenkey_core::crypto::random_array::<32>();
    let kek = hello::derive_kek(&vault_id, &salt)?;
    // One Hello wrap per vault: drop stale ones first.
    let existing = c.get("/v1/unlock-methods").map_err(err_string)?;
    for m in existing.as_array().into_iter().flatten() {
        if m["kind"] == hello::KIND {
            if let Some(id) = m["id"].as_str() {
                let _ = c.delete(&format!("/v1/unlock-methods/{id}"));
            }
        }
    }
    let label = hello::device_label();
    c.post(
        "/v1/unlock-methods",
        json!({ "kind": hello::KIND, "label": label, "salt": b64(&salt), "kek": b64(kek.expose()) }),
    )
    .map_err(err_string)?;
    Ok(label)
}

/// Unlock with Windows Hello.
#[tauri::command(async)]
fn device_unlock(state: tauri::State<'_, AppData>) -> Result<(), String> {
    let c = client(&state)?;
    let status = c.get("/v1/status").map_err(err_string)?;
    let vault_id = status["vault_id"].as_str().unwrap_or_default().to_string();
    let methods = c.get("/v1/unlock-methods").map_err(err_string)?;
    let m = methods
        .as_array()
        .into_iter()
        .flatten()
        .rev()
        .find(|m| m["kind"] == hello::KIND)
        .cloned()
        .ok_or_else(|| "not_found: Windows Hello is not enabled for this vault".to_string())?;
    let salt = unb64_32(m["salt"].as_str().unwrap_or_default())?;
    let kek = hello::derive_kek(&vault_id, &salt)?;
    let r = c
        .post(
            "/v1/unlock",
            json!({ "wrap_id": m["id"], "kek": b64(kek.expose()) }),
        )
        .map_err(err_string)?;
    state.remember_owner(&r);
    Ok(())
}

/// Remove the Windows Hello enrollment (vault must be unlocked).
#[tauri::command(async)]
fn device_unlock_remove(state: tauri::State<'_, AppData>) -> Result<(), String> {
    let c = client(&state)?;
    let status = c.get("/v1/status").map_err(err_string)?;
    let vault_id = status["vault_id"].as_str().unwrap_or_default().to_string();
    let methods = c.get("/v1/unlock-methods").map_err(err_string)?;
    for m in methods.as_array().into_iter().flatten() {
        if m["kind"] == hello::KIND {
            if let Some(id) = m["id"].as_str() {
                c.delete(&format!("/v1/unlock-methods/{id}"))
                    .map_err(err_string)?;
            }
        }
    }
    hello::delete_key(&vault_id);
    Ok(())
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Follow the daemon's SSE stream and re-emit events to the UI; reconnect forever.
fn event_pump(app: AppHandle, paths: VaultPaths) {
    std::thread::spawn(move || loop {
        let Some(c) = Client::try_connect(&paths) else {
            std::thread::sleep(Duration::from_secs(3));
            continue;
        };
        let url = format!("{}/v1/events", c.base_url());
        let token = std::fs::read_to_string(&paths.token).unwrap_or_default();
        let resp = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(2))
            .build()
            .get(&url)
            .set("Authorization", &format!("Bearer {}", token.trim()))
            .call();
        let Ok(resp) = resp else {
            std::thread::sleep(Duration::from_secs(3));
            continue;
        };
        let reader = std::io::BufReader::new(resp.into_reader());
        use std::io::BufRead;
        for line in reader.lines() {
            let Ok(line) = line else { break };
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<Value>(data.trim()) else {
                continue;
            };
            if v["event"] == "locked" {
                // Every owner token died with the lock.
                app.state::<AppData>().set_owner(None);
            }
            if v["event"] == "approval_requested" {
                let title = format!(
                    "{} wants to use {}",
                    v["caller"].as_str().unwrap_or("an agent"),
                    v["secret"].as_str().unwrap_or("a secret")
                );
                let body = v["scope"].as_str().unwrap_or("").to_string();
                let _ = app.notification().builder().title(title).body(body).show();
                show_main(&app);
            } else if v["event"] == "anomaly" {
                let label = v["label"].as_str().unwrap_or("a handle");
                let title = if v["kind"] == "canary" {
                    format!("Canary tripped: {label}")
                } else {
                    format!("Unusual activity on {label}")
                };
                let body = format!(
                    "{}. Response: {}.",
                    v["detail"].as_str().unwrap_or(""),
                    v["response"].as_str().unwrap_or("")
                );
                let _ = app.notification().builder().title(title).body(body).show();
                show_main(&app);
            }
            let _ = app.emit("usk://event", v);
        }
        std::thread::sleep(Duration::from_secs(1));
    });
}

/// Build and run the app.
pub fn run() {
    let paths = paths().expect("vault location");
    // Providers the owner added as `<vault dir>/presets/<id>.toml`.
    let _ = unseenkey_core::presets::load_user_dir(&paths.presets);
    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .manage(AppData {
            paths: paths.clone(),
            connect_lock: Mutex::new(()),
            owner: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            status,
            create_vault,
            unlock,
            lock,
            api,
            confirm_owner,
            presets,
            install_mcp,
            guard_scan,
            guard_fix,
            env_files,
            restart_daemon,
            device_unlock_status,
            device_unlock_enroll,
            device_unlock,
            device_unlock_remove
        ])
        .setup(move |app| {
            let open = MenuItem::with_id(app, "open", "Open Unseenkey", true, None::<&str>)?;
            let lock_item = MenuItem::with_id(app, "lock", "Lock vault", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &lock_item, &quit])?;
            let tray_paths = paths.clone();
            TrayIconBuilder::new()
                .icon(app.default_window_icon().cloned().expect("window icon"))
                .tooltip("Unseenkey")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "open" => show_main(app),
                    "lock" => {
                        // Menu events run on the main thread; keep the HTTP call off it.
                        let paths = tray_paths.clone();
                        std::thread::spawn(move || {
                            if let Some(c) = Client::try_connect(&paths) {
                                let _ = c.post("/v1/lock", json!({}));
                            }
                        });
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main(tray.app_handle());
                    }
                })
                .build(app)?;
            event_pump(app.handle().clone(), paths.clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the app in the tray; Quit is in the tray menu.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Unseenkey");
}
