//! Caps, canaries and what unusual activity does to a handle.
//!
//! A cap is a hard stop on a handle. A canary is a handle that never works:
//! any use is an incident. A burst of policy refusals on one handle is an
//! incident too. The owner picks the response per handle: alert, throttle,
//! approve, pause or lock; `resume` puts the handle back.

use axum::routing::any;
use axum::Router;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, Running, ServeOptions};

const PW: &str = "anomaly-test-password";
const STRIPE_KEY: &str = "sk_live_51Habcdefghijklmnop";

struct C {
    base: String,
    token: String,
    agent: ureq::Agent,
}

impl C {
    fn new(r: &Running) -> Arc<Self> {
        Arc::new(Self {
            base: format!("http://{}", r.addr),
            token: r.token().to_string(),
            agent: ureq::AgentBuilder::new()
                .max_idle_connections(0)
                .timeout(Duration::from_secs(20))
                .redirects(0)
                .build(),
        })
    }
    fn mgmt(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let req = self
            .agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token));
        let r = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match r {
            Ok(resp) => {
                let code = resp.status();
                (code, resp.into_json().unwrap_or(Value::Null))
            }
            Err(ureq::Error::Status(code, resp)) => (code, resp.into_json().unwrap_or(Value::Null)),
            Err(e) => panic!("transport: {e}"),
        }
    }
    fn brokered(&self, handle: &str, method: &str, path: &str) -> (u16, Value) {
        let r = self
            .agent
            .request(method, &format!("{}/p/stripe{}", self.base, path))
            .set("Authorization", &format!("Bearer {handle}"))
            .send_string("");
        match r {
            Ok(resp) => {
                let code = resp.status();
                (code, resp.into_json().unwrap_or(Value::Null))
            }
            Err(ureq::Error::Status(code, resp)) => (code, resp.into_json().unwrap_or(Value::Null)),
            Err(e) => panic!("transport: {e}"),
        }
    }
    fn unlock(&self) {
        let (code, body) = self.mgmt("POST", "/v1/unlock", Some(json!({ "password": PW })));
        assert_eq!(code, 200, "{body}");
    }
    fn locked(&self) -> bool {
        self.mgmt("GET", "/v1/status", None).1["locked"]
            .as_bool()
            .unwrap()
    }
    /// Create a handle on `stripe`; returns (handle string, id).
    fn handle(&self, extra: Value) -> (String, String) {
        let mut body = json!({ "secret": "stripe" });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let (code, created) = self.mgmt("POST", "/v1/handles", Some(body));
        assert_eq!(code, 201, "{created}");
        (
            created["handle"].as_str().unwrap().to_string(),
            created["id"].as_str().unwrap().to_string(),
        )
    }
    fn view(&self, id: &str) -> Value {
        let (code, v) = self.mgmt("GET", &format!("/v1/handles/{id}"), None);
        assert_eq!(code, 200, "{v}");
        v
    }
    /// Audit events of `kind` whose body names handle `id`.
    fn events(&self, kind: &str, id: &str) -> Vec<Value> {
        let (code, list) = self.mgmt("GET", &format!("/v1/audit?kind={kind}&limit=1000"), None);
        assert_eq!(code, 200, "{list}");
        list.as_array()
            .unwrap()
            .iter()
            .filter(|e| e["body"]["handle"] == id || e["body"]["id"] == id)
            .cloned()
            .collect()
    }
    fn pending(&self) -> Vec<Value> {
        self.mgmt("GET", "/v1/approvals", None)
            .1
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
    /// Ten refusals in a row: the burst threshold.
    fn burst(&self, handle: &str) {
        for i in 0..10 {
            let (code, body) = self.brokered(handle, "POST", "/v1/customers");
            assert_eq!(code, 403, "refusal {i}: {body}");
            assert_eq!(body["error"], "policy_denied", "refusal {i}: {body}");
        }
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

/// A fresh vault with one Stripe secret, unlocked, behind a mock upstream.
async fn setup() -> (tempfile::TempDir, Running, Arc<C>) {
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
    let r = serve(ServeOptions {
        vault_path: path,
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: false,
        upstream_overrides: vec![("api.stripe.com".into(), format!("http://{mock}"))],
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap();
    let c = C::new(&r);
    c.unlock();
    let (code, body) = c.mgmt(
        "POST",
        "/v1/secrets",
        Some(json!({ "name": "stripe", "value": STRIPE_KEY })),
    );
    assert_eq!(code, 201, "{body}");
    (dir, r, c)
}

/// A gated call answered from here.
async fn gated_call(c: &Arc<C>, handle: &str, decision: &str) -> (u16, Value) {
    let c2 = c.clone();
    let h = handle.to_string();
    let waiting = tokio::task::spawn_blocking(move || c2.brokered(&h, "GET", "/v1/customers"));
    for _ in 0..100 {
        if !c.pending().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let pending = c.pending();
    assert!(!pending.is_empty(), "no approval was requested");
    assert!(
        pending[0]["scope"]
            .as_str()
            .unwrap()
            .contains("approval mode after unusual activity"),
        "{}",
        pending[0]
    );
    let (code, d) = c.mgmt(
        "POST",
        "/v1/approvals/latest",
        Some(json!({ "decision": decision, "remember": false })),
    );
    assert_eq!(code, 200, "{d}");
    waiting.await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn caps_are_hard_stops_and_do_not_count_as_probing() {
    let (_dir, r, c) = setup().await;

    // A daily cap replaces the policy's own limit and stops the handle dead.
    let (h, id) = c
        .handle(json!({ "label": "daily", "preset_policy": "stripe:read-only", "cap_per_day": 3 }));
    assert_eq!(c.view(&id)["policy"]["limits"]["requests_per_day"], 3);
    for _ in 0..3 {
        assert_eq!(c.brokered(&h, "GET", "/v1/customers").0, 200);
    }
    let (code, body) = c.brokered(&h, "GET", "/v1/customers");
    assert_eq!(code, 429, "{body}");
    assert_eq!(body["error"], "rate_limited");
    // Running into a cap a dozen times is the cap working, not an incident.
    for _ in 0..12 {
        assert_eq!(c.brokered(&h, "GET", "/v1/customers").0, 429);
    }
    assert_eq!(c.view(&id)["status"]["state"], "normal");
    assert!(c.events("anomaly", &id).is_empty());

    let (h, id) = c.handle(
        json!({ "label": "minute", "preset_policy": "stripe:read-only", "cap_per_minute": 2 }),
    );
    assert_eq!(c.view(&id)["policy"]["limits"]["requests_per_minute"], 2);
    assert_eq!(c.brokered(&h, "GET", "/v1/customers").0, 200);
    assert_eq!(c.brokered(&h, "GET", "/v1/customers").0, 200);
    assert_eq!(c.brokered(&h, "GET", "/v1/customers").0, 429);

    // Zero is not a cap.
    let (code, body) = c.mgmt(
        "POST",
        "/v1/handles",
        Some(json!({ "secret": "stripe", "label": "zero", "cap_per_day": 0 })),
    );
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["error"], "invalid_cap");

    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_canary_never_works_and_locks_the_vault_when_used() {
    let (_dir, r, c) = setup().await;

    let (h, id) = c.handle(json!({ "label": "tripwire", "canary": true }));
    let view = c.view(&id);
    assert_eq!(view["canary"], true);
    assert_eq!(view["on_anomaly"], "lock");
    assert_eq!(
        view["policy"]["allow"],
        json!([]),
        "a canary can do nothing"
    );
    assert!(!c.locked());

    // From outside it is an unknown handle; inside, the vault is now locked.
    let (code, body) = c.brokered(&h, "GET", "/v1/customers");
    assert_eq!(code, 401, "{body}");
    assert_eq!(body["error"], "unknown_handle");
    assert!(c.locked(), "a tripped canary locks the vault");

    c.unlock();
    let tripped = c.events("canary_tripped", &id);
    assert_eq!(tripped.len(), 1, "{tripped:?}");
    assert_eq!(tripped[0]["body"]["response"], "lock");
    assert!(tripped[0]["body"]["detail"]
        .as_str()
        .unwrap()
        .contains("tripwire"));
    let view = c.view(&id);
    assert_eq!(view["last_anomaly"]["kind"], "canary");
    assert_eq!(
        view["status"]["state"], "normal",
        "locking changes nothing on the handle"
    );
    // The lock itself is in the log with its reason.
    let (_, locks) = c.mgmt("GET", "/v1/audit?kind=lock", None);
    assert!(locks
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["body"]["reason"] == "canary"));

    // A quieter canary: alert only.
    let (h, id) = c.handle(json!({ "label": "quiet", "canary": true, "on_anomaly": "alert" }));
    assert_eq!(c.brokered(&h, "GET", "/v1/customers").0, 401);
    assert!(!c.locked());
    assert_eq!(c.events("canary_tripped", &id).len(), 1);
    assert_eq!(
        c.events("canary_tripped", &id)[0]["body"]["response"],
        "alert"
    );

    // The creation event says what it is.
    let created = c.events("handle_created", &id);
    assert_eq!(created.len(), 1);
    assert_eq!(created[0]["body"]["canary"], true);

    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_of_refusals_throttles_the_handle_until_resumed() {
    let (_dir, r, c) = setup().await;
    let (h, id) = c.handle(json!({ "label": "agent", "preset_policy": "stripe:read-only" }));
    assert_eq!(c.view(&id)["on_anomaly"], "throttle", "the default");

    // Nine refusals: nothing yet. The tenth within a minute: an incident.
    for _ in 0..9 {
        assert_eq!(c.brokered(&h, "POST", "/v1/customers").0, 403);
    }
    assert_eq!(c.view(&id)["status"]["state"], "normal");
    assert_eq!(c.brokered(&h, "POST", "/v1/customers").0, 403);
    let view = c.view(&id);
    assert_eq!(view["status"]["state"], "throttled", "{view}");
    assert!(
        view["status"]["until"].as_i64().unwrap() > view["last_anomaly"]["at"].as_i64().unwrap()
    );
    assert_eq!(view["last_anomaly"]["kind"], "denial_burst");
    assert_eq!(view["last_anomaly"]["response"], "throttle");
    let events = c.events("anomaly", &id);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(
        events[0]["body"]["detail"],
        "10 requests refused by policy within a minute"
    );

    // Throttled: six allowed requests a minute, then 429s that are not refusals.
    for i in 0..6 {
        let (code, body) = c.brokered(&h, "GET", "/v1/customers");
        assert_eq!(code, 200, "request {i}: {body}");
    }
    let (code, body) = c.brokered(&h, "GET", "/v1/customers");
    assert_eq!(code, 429, "{body}");
    assert_eq!(body["error"], "throttled");
    assert_eq!(c.events("anomaly", &id).len(), 1, "no second incident");

    // Resume: back to normal at once, and the detector starts afresh.
    let (code, view) = c.mgmt("POST", &format!("/v1/handles/{id}/resume"), Some(json!({})));
    assert_eq!(code, 200, "{view}");
    assert_eq!(view["status"]["state"], "normal");
    assert!(view["last_anomaly"].is_null());
    assert_eq!(c.brokered(&h, "GET", "/v1/customers").0, 200);
    assert_eq!(c.events("handle_resumed", &id).len(), 1);
    c.burst(&h);
    assert_eq!(c.view(&id)["status"]["state"], "throttled");
    assert_eq!(c.events("anomaly", &id).len(), 2);

    // Resuming a normal handle is a no-op.
    let (code, _) = c.mgmt("POST", &format!("/v1/handles/{id}/resume"), Some(json!({})));
    assert_eq!(code, 200);
    let (code, _) = c.mgmt("POST", &format!("/v1/handles/{id}/resume"), Some(json!({})));
    assert_eq!(code, 200);
    assert_eq!(c.events("handle_resumed", &id).len(), 2);

    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pause_approve_alert_and_lock_responses() {
    let (_dir, r, c) = setup().await;

    // Pause: refuses everything until resumed.
    let (h, id) = c.handle(
        json!({ "label": "paused", "preset_policy": "stripe:read-only", "on_anomaly": "pause" }),
    );
    c.burst(&h);
    assert_eq!(c.view(&id)["status"]["state"], "paused");
    let (code, body) = c.brokered(&h, "GET", "/v1/customers");
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "handle_paused");
    // Those refusals are consequences, not probing: still one incident.
    for _ in 0..12 {
        assert_eq!(c.brokered(&h, "GET", "/v1/customers").0, 403);
    }
    assert_eq!(c.events("anomaly", &id).len(), 1);
    c.mgmt("POST", &format!("/v1/handles/{id}/resume"), Some(json!({})));
    assert_eq!(c.brokered(&h, "GET", "/v1/customers").0, 200);

    // Approve: every request waits for the owner, until resumed.
    let (h, id) = c.handle(
        json!({ "label": "approve", "preset_policy": "stripe:read-only", "on_anomaly": "approve" }),
    );
    c.burst(&h);
    assert_eq!(c.view(&id)["status"]["state"], "approval_required");
    let (code, body) = gated_call(&c, &h, "allow").await;
    assert_eq!(code, 200, "{body}");
    // Allowing once does not remember: the next one asks again.
    let (code, body) = gated_call(&c, &h, "deny").await;
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "approval_denied");
    c.mgmt("POST", &format!("/v1/handles/{id}/resume"), Some(json!({})));
    assert_eq!(c.brokered(&h, "GET", "/v1/customers").0, 200);
    assert!(c.pending().is_empty());

    // Alert: recorded and reported, nothing else changes; one incident an hour.
    let (h, id) = c.handle(
        json!({ "label": "alert", "preset_policy": "stripe:read-only", "on_anomaly": "alert" }),
    );
    c.burst(&h);
    assert_eq!(c.view(&id)["status"]["state"], "normal");
    assert_eq!(c.view(&id)["last_anomaly"]["response"], "alert");
    assert_eq!(c.brokered(&h, "GET", "/v1/customers").0, 200);
    c.burst(&h);
    assert_eq!(
        c.events("anomaly", &id).len(),
        1,
        "cool-down: no second incident"
    );

    // The response can be changed afterwards.
    let (code, view) = c.mgmt(
        "PATCH",
        &format!("/v1/handles/{id}"),
        Some(json!({ "on_anomaly": "pause" })),
    );
    assert_eq!(code, 200, "{view}");
    assert_eq!(view["on_anomaly"], "pause");
    assert_eq!(
        view["policy_explanation"],
        c.view(&id)["policy_explanation"],
        "the policy is untouched"
    );

    // Lock: the whole vault.
    let (h, id) = c.handle(
        json!({ "label": "lock", "preset_policy": "stripe:read-only", "on_anomaly": "lock" }),
    );
    c.burst(&h);
    assert!(c.locked());
    c.unlock();
    let view = c.view(&id);
    assert_eq!(view["status"]["state"], "normal");
    assert_eq!(view["last_anomaly"]["response"], "lock");
    let (_, locks) = c.mgmt("GET", "/v1/audit?kind=lock", None);
    assert!(locks
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["body"]["reason"] == "anomaly"));

    r.shutdown().await;
}
