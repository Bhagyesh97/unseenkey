//! What the daemon does when the audit log cannot be written.
//!
//! A second connection puts a trigger on the `audit` table that fails every
//! append, while the rest of the vault file keeps working. That is the worst
//! case for the broker: the key can be read and the use counted, and only the
//! record is missing.

use axum::routing::any;
use axum::Router;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, Running, ServeOptions};

const PW: &str = "audit-test-password";
const OPENAI_KEY: &str = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";

struct Env {
    daemon: Running,
    base: String,
    token: String,
    owner: String,
    agent: ureq::Agent,
    /// Requests the mock upstream received.
    hits: Arc<AtomicUsize>,
    vault: PathBuf,
}

fn read(r: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> (u16, Value) {
    let (code, text) = match r {
        Ok(resp) => (
            resp.status().as_u16(),
            resp.into_body().read_to_string().unwrap_or_default(),
        ),
        Err(e) => panic!("transport: {e}"),
    };
    (
        code,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

impl Env {
    fn mgmt(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let req = ureq::http::Request::builder()
            .method(method)
            .uri(format!("{}{}", self.base, path))
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("X-Usk-Owner", &self.owner);
        read(match body {
            Some(b) => self.agent.run(
                req.header("Content-Type", "application/json")
                    .body(b.to_string())
                    .unwrap(),
            ),
            None => self.agent.run(req.body(()).unwrap()),
        })
    }

    fn proxy(&self, method: &str, path: &str, handle: &str) -> (u16, Value) {
        read(
            self.agent.run(
                ureq::http::Request::builder()
                    .method(method)
                    .uri(format!("{}{}", self.base, path))
                    .header("Authorization", format!("Bearer {handle}"))
                    .body(())
                    .unwrap(),
            ),
        )
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn lost(&self) -> u64 {
        let (code, status) = self.mgmt("GET", "/v1/status", None);
        assert_eq!(code, 200, "{status}");
        status["audit_lost"]
            .as_u64()
            .unwrap_or_else(|| panic!("status has no audit_lost: {status}"))
    }

    fn uses(&self, handle_id: &str) -> u64 {
        self.mgmt("GET", &format!("/v1/handles/{handle_id}"), None)
            .1["use_count"]
            .as_u64()
            .unwrap()
    }

    /// Run SQL on the vault file from outside the daemon.
    fn sql(&self, sql: &str) {
        let conn = rusqlite::Connection::open(&self.vault).unwrap();
        conn.busy_timeout(Duration::from_secs(10)).unwrap();
        conn.execute_batch(sql).unwrap();
    }

    fn break_audit(&self) {
        self.sql(
            "CREATE TRIGGER test_audit_down BEFORE INSERT ON audit
             BEGIN SELECT RAISE(ABORT, 'audit store is down (test)'); END;",
        );
    }

    fn mend_audit(&self) {
        self.sql("DROP TRIGGER test_audit_down;");
    }
}

async fn setup() -> Env {
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app = Router::new().fallback(any(move || {
            let seen = seen.clone();
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                axum::Json(json!({ "ok": true }))
            }
        }));
        axum::serve(listener, app).await.unwrap();
    });

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
    let daemon = serve(ServeOptions {
        vault_path: vault.clone(),
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: false,
        upstream_overrides: vec![("api.openai.com".into(), format!("http://{mock}"))],
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap();
    let mut env = Env {
        base: format!("http://{}", daemon.addr),
        token: daemon.token().to_string(),
        owner: String::new(),
        agent: ureq::Agent::config_builder()
            .max_idle_connections(0)
            .timeout_per_read(Some(Duration::from_secs(20)))
            .timeout_per_write(Some(Duration::from_secs(20)))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .new_agent(),
        daemon,
        hits,
        vault,
    };
    let (code, unlocked) = env.mgmt("POST", "/v1/unlock", Some(json!({ "password": PW })));
    assert_eq!(code, 200, "{unlocked}");
    env.owner = unlocked["owner_token"].as_str().unwrap().to_string();
    let (code, made) = env.mgmt(
        "POST",
        "/v1/secrets",
        Some(json!({ "name": "openai", "value": OPENAI_KEY })),
    );
    assert_eq!(code, 201, "{made}");
    let (code, set) = env.mgmt(
        "PATCH",
        "/v1/secrets/openai",
        Some(json!({ "allow_injection": true })),
    );
    assert_eq!(code, 200, "{set}");
    env
}

fn handle(env: &Env, label: &str, preset_policy: Option<&str>) -> (String, String) {
    let mut body = json!({ "secret": "openai", "label": label });
    if let Some(p) = preset_policy {
        body["preset_policy"] = json!(p);
    }
    let (code, h) = env.mgmt("POST", "/v1/handles", Some(body));
    assert_eq!(code, 201, "{h}");
    (
        h["handle"].as_str().unwrap().to_string(),
        h["id"].as_str().unwrap().to_string(),
    )
}

/// A value leaves the vault only after the log says so.
#[tokio::test(flavor = "multi_thread")]
async fn no_value_is_handed_out_when_it_cannot_be_logged() {
    let env = setup().await;
    let reveal = |env: &Env| {
        env.mgmt(
            "POST",
            "/v1/secrets/openai/reveal",
            Some(json!({ "confirm": true, "reason": "test" })),
        )
    };
    let inject = |env: &Env| {
        env.mgmt(
            "POST",
            "/v1/secrets/openai/inject",
            Some(json!({ "var": "OPENAI_API_KEY", "command": "tool" })),
        )
    };
    let (code, body) = reveal(&env);
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["value"], OPENAI_KEY);

    env.break_audit();
    for (what, (code, body)) in [("reveal", reveal(&env)), ("inject", inject(&env))] {
        assert_eq!(code, 500, "{what}: {body}");
        assert_eq!(body["error"], "audit_failure", "{what}");
        assert!(!body.to_string().contains(OPENAI_KEY), "{what}");
    }
    // Nothing happened, so nothing is missing from the log.
    assert_eq!(env.lost(), 0);

    env.mend_audit();
    let (code, body) = reveal(&env);
    assert_eq!(code, 200, "{body}");
    let (code, body) = inject(&env);
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["value"], OPENAI_KEY);
    let (_, reveals) = env.mgmt("GET", "/v1/audit?kind=reveal", None);
    assert_eq!(reveals.as_array().unwrap().len(), 2, "{reveals}");
    env.daemon.shutdown().await;
}

/// The request during which the log breaks cannot be taken back; the next
/// one is not sent, and the log says what is missing once it works again.
#[tokio::test(flavor = "multi_thread")]
async fn the_broker_stops_sending_while_the_log_is_broken() {
    let env = setup().await;
    let (free, free_id) = handle(&env, "free", None);
    let (chat, _) = handle(&env, "chat only", Some("openai:chat"));
    let (code, body) = env.proxy("GET", "/p/openai/v1/models", &free);
    assert_eq!(code, 200, "{body}");
    assert_eq!((env.hits(), env.uses(&free_id), env.lost()), (1, 1, 0));

    env.break_audit();
    // Sent, then not recorded: the answer is withheld and the loss counted.
    let (code, body) = env.proxy("GET", "/p/openai/v1/models", &free);
    assert_eq!(code, 500, "{body}");
    assert_eq!(body["error"], "audit_failure");
    assert_eq!((env.hits(), env.uses(&free_id), env.lost()), (2, 2, 1));
    // From here on nothing goes out, and no use is counted.
    for _ in 0..3 {
        let (code, body) = env.proxy("GET", "/p/openai/v1/models", &free);
        assert_eq!(code, 500, "{body}");
        assert_eq!(body["error"], "audit_failure");
    }
    assert_eq!((env.hits(), env.uses(&free_id), env.lost()), (2, 2, 1));
    // A refusal stays a refusal; its record is lost and counted.
    let (code, body) = env.proxy("DELETE", "/p/openai/v1/files/file_1", &chat);
    assert_eq!(code, 403, "{body}");
    assert_ne!(body["error"], "audit_failure");
    assert_eq!((env.hits(), env.lost()), (2, 2));

    env.mend_audit();
    let (code, body) = env.proxy("GET", "/p/openai/v1/models", &free);
    assert_eq!(code, 200, "{body}");
    assert_eq!((env.hits(), env.uses(&free_id)), (3, 3));
    // The log names its own gap, before the first event after it.
    let (_, all) = env.mgmt("GET", "/v1/audit?limit=5", None);
    let (_, gaps) = env.mgmt("GET", "/v1/audit?kind=audit_gap", None);
    let gaps = gaps.as_array().unwrap();
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    assert_eq!(gaps[0]["body"]["lost"], 2, "{all}");
    // What was lost since the daemon started stays on the status.
    assert_eq!(env.lost(), 2);
    env.daemon.shutdown().await;
}
