//! "Allow always" decisions live in the handle record: they survive a daemon
//! restart, can be forgotten, and are wiped by a policy change.

use axum::routing::any;
use axum::Router;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::policy::{ApprovalMode, Rule};
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, Running, ServeOptions};

const PW: &str = "remembered-test-password";
const STRIPE_KEY: &str = "sk_live_51Habcdefghijklmnop";

struct C {
    base: String,
    token: String,
    owner: std::sync::Mutex<Option<String>>,
    agent: ureq::Agent,
}

impl C {
    fn new(r: &Running) -> Arc<Self> {
        Arc::new(Self {
            base: format!("http://{}", r.addr),
            token: r.token().to_string(),
            owner: std::sync::Mutex::new(None),
            agent: ureq::Agent::config_builder()
                .max_idle_connections(0)
                .timeout_per_read(Some(Duration::from_secs(20)))
                .timeout_per_write(Some(Duration::from_secs(20)))
                .max_redirects(0)
                .http_status_as_error(false)
                .build()
                .new_agent(),
        })
    }
    fn mgmt(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut req = ureq::http::Request::builder()
            .method(method)
            .uri(format!("{}{}", self.base, path))
            .header("Authorization", &format!("Bearer {}", self.token));
        if let Some(o) = self.owner.lock().unwrap().as_ref() {
            req = req.header("X-Usk-Owner", o);
        }
        let r = match body {
            Some(b) => self.agent.run(
                req.header("Content-Type", "application/json")
                    .body(b.to_string())
                    .unwrap(),
            ),
            None => self.agent.run(req.body(()).unwrap()),
        };
        let (code, v) = match r {
            Ok(resp) => {
                let code = resp.status().as_u16();
                (code, resp.into_body().read_json().unwrap_or(Value::Null))
            }
            Err(e) => panic!("transport: {e}"),
        };
        if code == 200 && path == "/v1/unlock" {
            *self.owner.lock().unwrap() = v["owner_token"].as_str().map(str::to_string);
        }
        (code, v)
    }
    /// A brokered call with the handle; returns the status.
    fn brokered(&self, handle: &str, method: &str, path: &str) -> (u16, Value) {
        let r = self.agent.run(
            ureq::http::Request::builder()
                .method(method)
                .uri(format!("{}/p/stripe{}", self.base, path))
                .header("Authorization", format!("Bearer {handle}"))
                .body("")
                .unwrap(),
        );
        match r {
            Ok(resp) => {
                let code = resp.status().as_u16();
                (code, resp.into_body().read_json().unwrap_or(Value::Null))
            }
            Err(e) => panic!("transport: {e}"),
        }
    }
    fn pending(&self) -> Vec<Value> {
        self.mgmt("GET", "/v1/approvals", None)
            .1
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
}

async fn mock_upstream() -> SocketAddr {
    let app = Router::new().route(
        "/{*rest}",
        any(|| async { ([("content-type", "application/json")], "{\"ok\":true}") }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

async fn start(path: &std::path::Path, mock: SocketAddr) -> Running {
    serve(ServeOptions {
        vault_path: path.to_path_buf(),
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: false,
        upstream_overrides: vec![("api.stripe.com".into(), format!("http://{mock}"))],
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap()
}

/// Run a gated call on a blocking thread and answer it from here.
async fn gated_call(c: &Arc<C>, handle: &str, decision: &str, remember: bool) -> (u16, Value) {
    let c2 = c.clone();
    let h = handle.to_string();
    let waiting = tokio::task::spawn_blocking(move || c2.brokered(&h, "POST", "/v1/customers"));
    for _ in 0..100 {
        if !c.pending().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!c.pending().is_empty(), "no approval was requested");
    let (code, d) = c.mgmt(
        "POST",
        "/v1/approvals/latest",
        Some(json!({ "decision": decision, "remember": remember })),
    );
    assert_eq!(code, 200, "{d}");
    waiting.await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remembered_approvals_survive_restart_until_forgotten_or_policy_changes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    drop(
        Vault::create(
            SqliteStorage::open(&path).unwrap(),
            SystemClock,
            &SecretBytes::from(PW),
            Argon2Profile::MINIMUM,
        )
        .unwrap(),
    );
    let mock = mock_upstream().await;

    // Daemon A: secret, a handle whose policy gates POST /v1/customers.
    let a = start(&path, mock).await;
    let c = C::new(&a);
    assert_eq!(
        c.mgmt("POST", "/v1/unlock", Some(json!({ "password": PW })))
            .0,
        200
    );
    assert_eq!(
        c.mgmt(
            "POST",
            "/v1/secrets",
            Some(json!({ "name": "stripe", "value": STRIPE_KEY }))
        )
        .0,
        201
    );
    let mut policy = unseenkey_core::presets::policy_ref("stripe:payments").unwrap();
    policy.approval.mode = ApprovalMode::Paths;
    policy.approval.paths = vec![Rule::parse("POST /v1/customers").unwrap()];
    policy.approval.timeout_seconds = 5;
    let (code, created) = c.mgmt(
        "POST",
        "/v1/handles",
        Some(json!({ "secret": "stripe", "label": "agent", "policy": serde_json::from_str::<Value>(&policy.to_json()).unwrap() })),
    );
    assert_eq!(code, 201, "{created}");
    let handle = created["handle"].as_str().unwrap().to_string();
    let id = created["id"].as_str().unwrap().to_string();

    // Ungated path: straight through. Gated path: approve once with "remember".
    assert_eq!(c.brokered(&handle, "GET", "/v1/customers").0, 200);
    let (code, body) = gated_call(&c, &handle, "allow", true).await;
    assert_eq!(code, 200, "{body}");
    let (_, view) = c.mgmt("GET", &format!("/v1/handles/{id}"), None);
    assert_eq!(view["remembered"], json!(["POST /v1/customers"]));
    // No prompt the second time.
    assert_eq!(c.brokered(&handle, "POST", "/v1/customers").0, 200);
    assert!(c.pending().is_empty());

    // Restart: the decision is still there.
    a.shutdown().await;
    let b = start(&path, mock).await;
    let c = C::new(&b);
    assert_eq!(
        c.mgmt("POST", "/v1/unlock", Some(json!({ "password": PW })))
            .0,
        200
    );
    assert_eq!(
        c.mgmt("GET", &format!("/v1/handles/{id}"), None).1["remembered"],
        json!(["POST /v1/customers"])
    );
    assert_eq!(c.brokered(&handle, "POST", "/v1/customers").0, 200);
    assert!(c.pending().is_empty());

    // Forget a rule that was never remembered: nothing happens. Forget the real one: it asks again.
    let (code, r) = c.mgmt(
        "POST",
        &format!("/v1/handles/{id}/forget"),
        Some(json!({ "rule": "DELETE /v1/x" })),
    );
    assert_eq!(code, 200);
    assert_eq!(r["removed"], 0);
    let (code, r) = c.mgmt("POST", &format!("/v1/handles/{id}/forget"), None);
    assert_eq!(code, 200);
    assert_eq!(r["removed"], 1);
    assert_eq!(
        c.mgmt("GET", &format!("/v1/handles/{id}"), None).1["remembered"],
        json!([])
    );
    let (code, body) = gated_call(&c, &handle, "deny", false).await;
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "approval_denied");

    // Remember again, then a policy change wipes it.
    let (code, _) = gated_call(&c, &handle, "allow", true).await;
    assert_eq!(code, 200);
    assert_eq!(
        c.mgmt("GET", &format!("/v1/handles/{id}"), None).1["remembered"],
        json!(["POST /v1/customers"])
    );
    let (code, _) = c.mgmt(
        "PATCH",
        &format!("/v1/handles/{id}"),
        Some(json!({ "policy": serde_json::from_str::<Value>(&policy.to_json()).unwrap() })),
    );
    assert_eq!(code, 200);
    assert_eq!(
        c.mgmt("GET", &format!("/v1/handles/{id}"), None).1["remembered"],
        json!([])
    );
    let (code, _) = gated_call(&c, &handle, "allow", false).await;
    assert_eq!(code, 200);

    // Audit trail.
    let (_, events) = c.mgmt("GET", "/v1/audit?since=1&limit=500", None);
    let kinds: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"approval_forgotten"));
    assert!(events
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "approval_decided" && e["body"]["remembered"] == true));
    b.shutdown().await;
}
