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
}

fn paths() -> Result<VaultPaths, String> {
    let vault = usk::daemon::vault_path(std::env::var_os("USK_VAULT").map(Into::into))
        .map_err(|e| e.message)?;
    Ok(VaultPaths::from_vault_file(&vault))
}

fn client(data: &AppData) -> Result<Client, String> {
    let _g = data.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
    Client::connect(&data.paths, true).map_err(|e| format!("{}: {}", e.kind, e.message))
}

fn err_string(e: usk::io::CliError) -> String {
    format!("{}: {}", e.kind, e.message)
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
    c.post("/v1/unlock", json!({ "password": password }))
        .map_err(err_string)?;
    Ok(json!({ "vault_id": vault_id, "words": words }))
}

#[tauri::command(async)]
fn unlock(state: tauri::State<'_, AppData>, password: String) -> Result<(), String> {
    let c = client(&state)?;
    c.post("/v1/unlock", json!({ "password": password }))
        .map(|_| ())
        .map_err(err_string)
}

#[tauri::command(async)]
fn lock(state: tauri::State<'_, AppData>) -> Result<(), String> {
    if let Some(c) = Client::try_connect(&state.paths) {
        c.post("/v1/lock", json!({})).map_err(err_string)?;
    }
    Ok(())
}

/// Generic management call: the UI is our own code, so it may use the same
/// routes the CLI uses. Only `/v1/…` paths are allowed.
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
    let r = match method.as_str() {
        "GET" => c.get(&path),
        "POST" => c.post(&path, body.unwrap_or(json!({}))),
        "PATCH" => c.patch(&path, body.unwrap_or(json!({}))),
        "DELETE" => c.delete(&path),
        _ => return Err("invalid: method".into()),
    };
    r.map_err(err_string)
}

#[tauri::command(async)]
fn presets() -> Vec<Value> {
    unseenkey_core::presets::all()
        .map(|p| {
            json!({
                "id": p.id, "display": p.display, "upstreams": p.upstreams, "docs": p.docs,
                "camouflage": !p.handle_formats.is_empty(),
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

#[tauri::command(async)]
fn guard_fix(state: tauri::State<'_, AppData>, path: String) -> Result<String, String> {
    let _g = state.connect_lock.lock().unwrap_or_else(|e| e.into_inner());
    usk::guard::fix(&state.paths, std::path::Path::new(&path), false).map_err(err_string)?;
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
    c.post(
        "/v1/unlock",
        json!({ "wrap_id": m["id"], "kek": b64(kek.expose()) }),
    )
    .map(|_| ())
    .map_err(err_string)
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
        .plugin(tauri_plugin_process::init())
        .manage(AppData {
            paths: paths.clone(),
            connect_lock: Mutex::new(()),
        })
        .invoke_handler(tauri::generate_handler![
            status,
            create_vault,
            unlock,
            lock,
            api,
            presets,
            install_mcp,
            guard_scan,
            guard_fix,
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
