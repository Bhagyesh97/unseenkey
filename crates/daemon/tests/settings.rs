//! The owner's settings live in the vault, not in `config.toml`.
//!
//! Any program running as the user can edit `config.toml` and restart the
//! daemon. If the care level, the idle lock, the sleep and screen locks or the
//! MCP store switch came from that file, such a program could loosen them
//! without the owner. They are a record in the vault: written on the owner's
//! word, read back on every unlock.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, Running, ServeOptions};

const PW: &str = "settings-test-password";

/// What a daemon is started with: flags, environment and `config.toml`.
#[derive(Clone, Copy)]
struct Start {
    care: &'static str,
    idle_lock_minutes: u64,
    lock_on_sleep: bool,
    lock_on_session_lock: bool,
    mcp_allow_store: bool,
}

/// As loose as it gets.
const LOOSE: Start = Start {
    care: "relaxed",
    idle_lock_minutes: 0,
    lock_on_sleep: false,
    lock_on_session_lock: false,
    mcp_allow_store: true,
};

struct Env {
    daemon: Running,
    base: String,
    token: String,
    owner: String,
    agent: ureq::Agent,
}

fn read(r: Result<ureq::Response, ureq::Error>) -> (u16, Value) {
    let (code, text) = match r {
        Ok(resp) => (resp.status(), resp.into_string().unwrap_or_default()),
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_string().unwrap_or_default()),
        Err(e) => panic!("transport: {e}"),
    };
    (
        code,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

impl Env {
    fn mgmt(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let req = self
            .agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("X-Usk-Owner", &self.owner);
        read(match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        })
    }

    fn unlock(&mut self) {
        let (code, unlocked) = self.mgmt("POST", "/v1/unlock", Some(json!({ "password": PW })));
        assert_eq!(code, 200, "{unlocked}");
        self.owner = unlocked["owner_token"].as_str().unwrap().to_string();
    }

    fn lock(&self) {
        let (code, b) = self.mgmt("POST", "/v1/lock", None);
        assert_eq!(code, 200, "{b}");
    }

    /// The five owner settings as the status shows them.
    fn settings(&self) -> Value {
        let (code, s) = self.mgmt("GET", "/v1/status", None);
        assert_eq!(code, 200, "{s}");
        json!({
            "care": s["care"],
            "idle_lock_minutes": s["idle_lock_minutes"],
            "lock_on_sleep": s["lock_on_sleep"],
            "lock_on_session_lock": s["lock_on_session_lock"],
            "mcp_allow_store": s["mcp_allow_store"],
        })
    }

    fn events(&self, kind: &str) -> Vec<Value> {
        let (code, list) = self.mgmt("GET", &format!("/v1/audit?kind={kind}"), None);
        assert_eq!(code, 200, "{list}");
        list.as_array().unwrap().clone()
    }

    fn patch(&self, body: Value) -> (u16, Value) {
        self.mgmt("PATCH", "/v1/settings", Some(body))
    }
}

fn new_vault() -> PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    // Leak the tempdir so the vault outlives the test body.
    std::mem::forget(dir);
    drop(
        Vault::create(
            SqliteStorage::open(&vault).unwrap(),
            SystemClock,
            &SecretBytes::from(PW),
            Argon2Profile::MINIMUM,
        )
        .unwrap(),
    );
    vault
}

fn config_path(vault: &Path) -> PathBuf {
    vault.parent().unwrap().join("config.toml")
}

/// Start a daemon the way `usk daemon run` would with this `config.toml`:
/// the file is written, and the values it resolves to are passed in.
async fn start(vault: &Path, with: Start) -> Env {
    std::fs::write(
        config_path(vault),
        format!(
            "[daemon]\ncare = \"{}\"\nidle_lock_minutes = {}\nlock_on_sleep = {}\nlock_on_session_lock = {}\n\n[mcp]\nallow_store = {}\n",
            with.care,
            with.idle_lock_minutes,
            with.lock_on_sleep,
            with.lock_on_session_lock,
            with.mcp_allow_store
        ),
    )
    .unwrap();
    let daemon = serve(ServeOptions {
        vault_path: vault.to_path_buf(),
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: with.idle_lock_minutes,
        write_runtime_files: false,
        upstream_overrides: vec![],
        mcp_allow_store: with.mcp_allow_store,
        lock_on_sleep: with.lock_on_sleep,
        lock_on_session_lock: with.lock_on_session_lock,
    })
    .await
    .unwrap();
    Env {
        base: format!("http://{}", daemon.addr),
        token: daemon.token().to_string(),
        owner: String::new(),
        agent: ureq::AgentBuilder::new()
            .max_idle_connections(0)
            .timeout_read(Duration::from_secs(20))
            .timeout_write(Duration::from_secs(20))
            .redirects(0)
            .build(),
        daemon,
    }
}

fn shown(with: Start) -> Value {
    json!({
        "care": with.care,
        "idle_lock_minutes": with.idle_lock_minutes,
        "lock_on_sleep": with.lock_on_sleep,
        "lock_on_session_lock": with.lock_on_session_lock,
        "mcp_allow_store": with.mcp_allow_store,
    })
}

/// A vault from before settings lived in it keeps what the owner had: the
/// first unlock takes the values over, once, and says so in the log.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_unlock_takes_over_what_the_daemon_started_with() {
    let vault = new_vault();
    let had = Start {
        care: "relaxed",
        idle_lock_minutes: 45,
        lock_on_sleep: false,
        lock_on_session_lock: false,
        mcp_allow_store: true,
    };
    let mut env = start(&vault, had).await;
    env.unlock();
    assert_eq!(env.settings(), shown(had));
    let adopted = env.events("settings_adopted");
    assert_eq!(adopted.len(), 1, "{adopted:?}");
    assert_eq!(adopted[0]["body"]["care"], "relaxed");
    assert_eq!(adopted[0]["body"]["idle_lock_minutes"], 45);
    assert_eq!(adopted[0]["body"]["mcp_allow_store"], true);

    // Once: the next unlock reads the record.
    env.lock();
    env.unlock();
    assert_eq!(env.settings(), shown(had));
    assert_eq!(env.events("settings_adopted").len(), 1);
    assert!(env.events("settings_tampered").is_empty());
    env.daemon.shutdown().await;
}

/// The attack: edit `config.toml`, restart the daemon, wait for the owner to
/// unlock. Nothing loosens.
#[tokio::test(flavor = "multi_thread")]
async fn a_looser_config_and_a_restart_change_nothing() {
    let vault = new_vault();
    let owners = Start {
        care: "strict",
        idle_lock_minutes: 5,
        lock_on_sleep: true,
        lock_on_session_lock: true,
        mcp_allow_store: false,
    };
    let mut env = start(&vault, owners).await;
    env.unlock();
    assert_eq!(env.settings(), shown(owners));
    env.daemon.shutdown().await;

    let mut env = start(&vault, LOOSE).await;
    env.unlock();
    assert_eq!(env.settings(), shown(owners));
    assert_eq!(env.events("settings_adopted").len(), 1);
    assert!(env.events("settings_tampered").is_empty());
    env.daemon.shutdown().await;
}

/// `PATCH /v1/settings` changes all five, writes the vault and leaves
/// `config.toml` alone; a restart with other values keeps the owner's.
#[tokio::test(flavor = "multi_thread")]
async fn a_changed_setting_is_kept_in_the_vault() {
    let vault = new_vault();
    let mut env = start(&vault, LOOSE).await;
    env.unlock();
    let config_before = std::fs::read_to_string(config_path(&vault)).unwrap();

    let (code, b) = env.patch(json!({
        "care": "strict",
        "idle_lock_minutes": 10,
        "lock_on_sleep": true,
        "lock_on_session_lock": true,
        "mcp_allow_store": false,
    }));
    assert_eq!(code, 200, "{b}");
    let owners = json!({
        "care": "strict",
        "idle_lock_minutes": 10,
        "lock_on_sleep": true,
        "lock_on_session_lock": true,
        "mcp_allow_store": false,
    });
    assert_eq!(env.settings(), owners);
    for (key, want) in owners.as_object().unwrap() {
        assert_eq!(&b[key], want, "{key} in the reply: {b}");
    }
    assert_eq!(
        std::fs::read_to_string(config_path(&vault)).unwrap(),
        config_before,
        "config.toml is not where settings go"
    );
    let changed = env.events("settings_changed");
    let last = &changed.last().expect("a settings_changed event")["body"];
    assert_eq!(last["care"], "strict", "{changed:?}");
    assert_eq!(last["mcp_allow_store"], false, "{changed:?}");

    // One at a time leaves the others alone.
    let (code, b) = env.patch(json!({ "mcp_allow_store": true }));
    assert_eq!(code, 200, "{b}");
    let mut owners = owners;
    owners["mcp_allow_store"] = json!(true);
    assert_eq!(env.settings(), owners);

    // Only the owner: the session token alone is not enough.
    let (code, e) = read(
        env.agent
            .request("PATCH", &format!("{}/v1/settings", env.base))
            .set("Authorization", &format!("Bearer {}", env.token))
            .send_json(json!({ "lock_on_sleep": false })),
    );
    assert_eq!(code, 403, "{e}");
    assert_eq!(env.settings(), owners);
    env.daemon.shutdown().await;

    let mut env = start(&vault, LOOSE).await;
    env.unlock();
    assert_eq!(env.settings(), owners);
    env.daemon.shutdown().await;
}

fn sql(vault: &Path, sql: &str) -> usize {
    let conn = rusqlite::Connection::open(vault).unwrap();
    conn.busy_timeout(Duration::from_secs(10)).unwrap();
    conn.execute(sql, []).unwrap()
}

const CAUTIOUS: Start = Start {
    care: "strict",
    idle_lock_minutes: 15,
    lock_on_sleep: true,
    lock_on_session_lock: true,
    mcp_allow_store: false,
};

/// Deleting the record does not bring `config.toml` back: the log remembers
/// that the vault had settings, so their absence is tampering. The daemon
/// takes the cautious values and says so.
#[tokio::test(flavor = "multi_thread")]
async fn a_removed_settings_record_is_not_replaced_from_config() {
    let vault = new_vault();
    let mut env = start(&vault, LOOSE).await;
    env.unlock();
    assert_eq!(env.settings(), shown(LOOSE));
    env.daemon.shutdown().await;

    assert!(sql(&vault, "DELETE FROM records WHERE kind = 'setting'") >= 1);
    let mut env = start(&vault, LOOSE).await;
    env.unlock();
    assert_eq!(env.settings(), shown(CAUTIOUS));
    let tampered = env.events("settings_tampered");
    assert_eq!(tampered.len(), 1, "{tampered:?}");
    assert_eq!(tampered[0]["body"]["reason"], "record_missing");
    assert_eq!(env.events("settings_adopted").len(), 1);

    // The cautious values are the record now; the owner changes them from there.
    env.lock();
    env.unlock();
    assert_eq!(env.settings(), shown(CAUTIOUS));
    assert_eq!(env.events("settings_tampered").len(), 1);
    let (code, b) = env.patch(json!({ "care": "balanced" }));
    assert_eq!(code, 200, "{b}");
    assert_eq!(env.settings()["care"], "balanced");
    env.daemon.shutdown().await;
}

/// A record that no longer decrypts is treated the same way.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_settings_record_is_not_replaced_from_config() {
    let vault = new_vault();
    let mut env = start(&vault, LOOSE).await;
    env.unlock();
    env.daemon.shutdown().await;

    assert!(
        sql(
            &vault,
            "UPDATE records SET ciphertext = zeroblob(64) WHERE kind = 'setting'"
        ) >= 1
    );
    let mut env = start(&vault, LOOSE).await;
    env.unlock();
    assert_eq!(env.settings(), shown(CAUTIOUS));
    let tampered = env.events("settings_tampered");
    assert_eq!(tampered.len(), 1, "{tampered:?}");
    assert_eq!(tampered[0]["body"]["reason"], "record_unreadable");
    env.daemon.shutdown().await;
}

/// Removing the record and the log entry that says the vault had one does
/// not make it a first time again: a log with a hole cannot vouch for that.
#[tokio::test(flavor = "multi_thread")]
async fn a_hole_in_the_log_does_not_bring_config_back() {
    let vault = new_vault();
    let mut env = start(&vault, CAUTIOUS).await;
    env.unlock();
    env.daemon.shutdown().await;

    assert!(sql(&vault, "DELETE FROM records WHERE kind = 'setting'") >= 1);
    assert_eq!(
        sql(&vault, "DELETE FROM audit WHERE kind = 'settings_adopted'"),
        1
    );
    let mut env = start(&vault, LOOSE).await;
    env.unlock();
    assert_eq!(env.settings(), shown(CAUTIOUS));
    assert!(env.events("settings_adopted").is_empty());
    let tampered = env.events("settings_tampered");
    assert_eq!(tampered.len(), 1, "{tampered:?}");
    assert_eq!(tampered[0]["body"]["reason"], "log_damaged");
    env.daemon.shutdown().await;
}
