//! OAuth2 refresh through the broker: a handle stands in for an access token,
//! the daemon trades the stored refresh token for real ones and keeps them to
//! itself.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{any, post};
use axum::Router;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, Running, ServeOptions};

const PW: &str = "oauth-test-password";
const API: &str = "api.example.test";
const AUTH: &str = "auth.example.test";
const TOKEN_URL: &str = "https://auth.example.test/oauth/token";

#[derive(Default)]
struct Mock {
    /// Each call to the token endpoint: its form fields and Authorization header.
    token_calls: Vec<(HashMap<String, String>, Option<String>)>,
    /// Authorization header of each API call.
    api_calls: Vec<String>,
    /// Scripted token responses; a default success when empty.
    script: VecDeque<Value>,
}

type Shared = Arc<Mutex<Mock>>;

fn decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

async fn token(State(m): State<Shared>, req: Request) -> axum::response::Response {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, 1 << 16)
        .await
        .unwrap_or_default();
    let form: HashMap<String, String> = String::from_utf8_lossy(&body)
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (decode(k), decode(v)))
        .collect();
    let authz = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let mut m = m.lock().unwrap();
    m.token_calls.push((form, authz));
    let n = m.token_calls.len();
    let mut answer = m.script.pop_front().unwrap_or_else(
        || json!({ "access_token": format!("at-default-{n}-abcdefghij"), "expires_in": 3600, "token_type": "Bearer" }),
    );
    let status = answer
        .as_object_mut()
        .and_then(|o| o.remove("__status"))
        .and_then(|v| v.as_u64())
        .unwrap_or(200) as u16;
    (
        StatusCode::from_u16(status).unwrap(),
        [("content-type", "application/json")],
        answer.to_string(),
    )
        .into_response()
}

async fn api(State(m): State<Shared>, req: Request) -> axum::response::Response {
    let authz = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    m.lock().unwrap().api_calls.push(authz.clone());
    // Echo the credential back, as a careless API might: the caller must not see it.
    (
        [("content-type", "application/json")],
        json!({ "ok": true, "you_sent": authz }).to_string(),
    )
        .into_response()
}

struct T {
    daemon: Running,
    base: String,
    token: String,
    owner: std::sync::Mutex<Option<String>>,
    agent: ureq::Agent,
    mock: Shared,
}

fn outcome(r: Result<ureq::Response, ureq::Error>) -> (u16, Value) {
    match r {
        Ok(resp) => {
            let code = resp.status();
            (code, resp.into_json().unwrap_or(Value::Null))
        }
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_json().unwrap_or(Value::Null)),
        Err(e) => panic!("transport: {e}"),
    }
}

impl T {
    fn mgmt(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut req = self
            .agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token));
        if let Some(o) = self.owner.lock().unwrap().as_ref() {
            req = req.set("X-Usk-Owner", o);
        }
        let (code, v) = outcome(match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        });
        if code == 200 && path == "/v1/unlock" {
            *self.owner.lock().unwrap() = v["owner_token"].as_str().map(str::to_string);
        }
        (code, v)
    }
    /// An API call the way an SDK makes it: the handle where the access token goes.
    fn call(&self, handle: &str) -> (u16, Value) {
        outcome(
            self.agent
                .get(&format!(
                    "{}/p/generic/@{API}/v1/files?pageSize=1",
                    self.base
                ))
                .set("Authorization", &format!("Bearer {handle}"))
                .call(),
        )
    }
    fn script(&self, answer: Value) {
        self.mock.lock().unwrap().script.push_back(answer);
    }
    fn token_calls(&self) -> usize {
        self.mock.lock().unwrap().token_calls.len()
    }
    fn last_token_call(&self) -> (HashMap<String, String>, Option<String>) {
        self.mock
            .lock()
            .unwrap()
            .token_calls
            .last()
            .cloned()
            .unwrap()
    }
    fn api_calls(&self) -> Vec<String> {
        self.mock.lock().unwrap().api_calls.clone()
    }
    fn relock(&self) {
        assert_eq!(self.mgmt("POST", "/v1/lock", Some(json!({}))).0, 200);
        assert_eq!(
            self.mgmt("POST", "/v1/unlock", Some(json!({ "password": PW })))
                .0,
            200
        );
    }
    fn handle(&self, body: Value) -> String {
        let (code, h) = self.mgmt("POST", "/v1/handles", Some(body));
        assert_eq!(code, 201, "{h}");
        h["handle"].as_str().unwrap().to_string()
    }
}

async fn setup() -> T {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    std::mem::forget(dir);
    drop(
        Vault::create(
            SqliteStorage::open(&path).unwrap(),
            SystemClock,
            &SecretBytes::from(PW),
            Argon2Profile::MINIMUM,
        )
        .unwrap(),
    );
    let mock: Shared = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/oauth/token", post(token))
        .fallback(any(api))
        .with_state(mock.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let daemon = serve(ServeOptions {
        vault_path: path,
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: false,
        upstream_overrides: [API, AUTH]
            .iter()
            .map(|h| (h.to_string(), format!("http://{addr}")))
            .collect(),
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap();
    let t = T {
        base: format!("http://{}", daemon.addr),
        token: daemon.token().to_string(),
        owner: std::sync::Mutex::new(None),
        agent: ureq::AgentBuilder::new()
            .max_idle_connections(0)
            .timeout_read(Duration::from_secs(20))
            .timeout_write(Duration::from_secs(20))
            .redirects(0)
            .build(),
        daemon,
        mock,
    };
    assert_eq!(
        t.mgmt("POST", "/v1/unlock", Some(json!({ "password": PW })))
            .0,
        200
    );
    t
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_cache_rotation_and_failure() {
    let t = setup().await;
    // Pasted the way OAuth tooling writes it (Google's "authorized_user" file shape).
    let pasted = json!({
        "type": "authorized_user", "client_id": "cid-123", "client_secret": "csecret-abcdefghijkl",
        "refresh_token": "rt-1-abcdefghijklmnop", "token_uri": TOKEN_URL
    })
    .to_string();
    let (code, c) = t.mgmt(
        "POST",
        "/v1/secrets",
        Some(json!({ "name": "drive", "value": pasted, "upstreams": [API] })),
    );
    assert_eq!(code, 201, "{c}");
    assert_eq!(c["type"], "oauth2_client");
    // The token endpoint is somewhere the secret goes, so it is on the list.
    assert_eq!(c["upstreams"], json!([API, AUTH]));
    let (_, r) = t.mgmt(
        "POST",
        "/v1/secrets/drive/reveal",
        Some(json!({ "confirm": true })),
    );
    assert_eq!(r["value"], "rt-1-abcdefghijklmnop");
    assert_eq!(r["fields"]["client_id"], "cid-123");
    assert_eq!(r["fields"]["token_url"], TOKEN_URL);

    let handle = t.handle(json!({ "secret": "drive", "label": "sdk" }));

    // First call: one refresh, then the API sees the access token, the caller does not.
    t.script(json!({ "access_token": "at-1-abcdefghijklmnop", "expires_in": 3600 }));
    let (code, body) = t.call(&handle);
    assert_eq!(code, 200, "{body}");
    assert_eq!(t.token_calls(), 1);
    let (form, authz) = t.last_token_call();
    assert_eq!(form["grant_type"], "refresh_token");
    assert_eq!(form["refresh_token"], "rt-1-abcdefghijklmnop");
    assert_eq!(form["client_id"], "cid-123");
    assert_eq!(form["client_secret"], "csecret-abcdefghijkl");
    assert_eq!(authz, None);
    assert_eq!(
        t.api_calls().last().unwrap(),
        "Bearer at-1-abcdefghijklmnop"
    );
    let text = body.to_string();
    assert!(
        !text.contains("at-1-abcdefghijklmnop"),
        "access token leaked to the caller: {text}"
    );
    assert!(text.contains("[REDACTED:usk:drive.access_token]"), "{text}");
    assert!(!text.contains(&handle));

    // Cached: no second trip to the token endpoint.
    assert_eq!(t.call(&handle).0, 200);
    assert_eq!(t.token_calls(), 1);

    // Locking forgets access tokens.
    t.relock();
    t.script(json!({ "access_token": "at-2-abcdefghijklmnop", "expires_in": 61 }));
    assert_eq!(t.call(&handle).0, 200);
    assert_eq!(t.token_calls(), 2);
    assert_eq!(
        t.api_calls().last().unwrap(),
        "Bearer at-2-abcdefghijklmnop"
    );

    // Expiry (61 s minus the 60 s safety margin): refreshed again. This time the
    // provider rotates the refresh token, and the new one is stored.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    t.script(json!({ "access_token": "at-3-abcdefghijklmnop", "expires_in": 61, "refresh_token": "rt-2-abcdefghijklmnop" }));
    assert_eq!(t.call(&handle).0, 200);
    assert_eq!(t.token_calls(), 3);
    let (_, r) = t.mgmt(
        "POST",
        "/v1/secrets/drive/reveal",
        Some(json!({ "confirm": true })),
    );
    assert_eq!(r["value"], "rt-2-abcdefghijklmnop");
    assert_eq!(
        r["fields"]["client_id"], "cid-123",
        "the rest of the secret is kept"
    );
    let (_, events) = t.mgmt("GET", "/v1/audit?since=1&kind=secret_updated", None);
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["body"]["reason"] == "oauth_rotation"),
        "{events}"
    );

    // The provider refuses: the caller gets the provider's reason, the API is
    // not called, and the refusal is not cached.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let api_before = t.api_calls().len();
    t.script(json!({ "__status": 400, "error": "invalid_grant", "error_description": "Token has been expired or revoked." }));
    let (code, body) = t.call(&handle);
    assert_eq!(code, 502, "{body}");
    assert_eq!(body["error"], "oauth_refresh_failed");
    assert!(
        body["message"].as_str().unwrap().contains("invalid_grant"),
        "{body}"
    );
    assert_eq!(
        t.last_token_call().0["refresh_token"],
        "rt-2-abcdefghijklmnop",
        "the rotated token is the one in use"
    );
    assert_eq!(t.api_calls().len(), api_before);
    assert_eq!(t.call(&handle).0, 200);
    assert_eq!(t.token_calls(), 5);

    // A handle narrowed to the API host still works: where the secret refreshes
    // is the secret's business, not the handle's.
    let narrow = t.handle(json!({
        "secret": "drive", "label": "narrow",
        "policy": { "allow": ["GET /v1/**"], "upstreams": [API] }
    }));
    assert_eq!(t.call(&narrow).0, 200);
    assert_eq!(t.token_calls(), 5);
    // ...and cannot reach the token endpoint itself.
    let (code, body) = outcome(
        t.agent
            .get(&format!("{}/p/generic/@{AUTH}/oauth/token", t.base))
            .set("Authorization", &format!("Bearer {narrow}"))
            .call(),
    );
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "host_not_allowed");

    // Take the token host off the secret: refreshing is refused outright.
    assert_eq!(
        t.mgmt(
            "PATCH",
            "/v1/secrets/drive",
            Some(json!({ "upstreams": [API] }))
        )
        .0,
        200
    );
    t.relock();
    let (code, body) = t.call(&handle);
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "host_not_allowed");
    assert_eq!(
        t.token_calls(),
        5,
        "nothing was sent to a host off the list"
    );
    t.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_shapes() {
    let t = setup().await;
    // The CLI's shape: refresh token as the value, the rest as fields; a public
    // client (no secret) that authenticates... not at all, and asks for a scope.
    let (code, c) = t.mgmt(
        "POST",
        "/v1/secrets",
        Some(json!({
            "name": "public", "type": "oauth2_client", "value": "rt-public-abcdefghijkl",
            "fields": { "client_id": "pub-1", "token_url": TOKEN_URL, "scope": "files.read offline_access" },
            "upstreams": [API]
        })),
    );
    assert_eq!(code, 201, "{c}");
    let h = t.handle(json!({ "secret": "public", "label": "p" }));
    assert_eq!(t.call(&h).0, 200);
    let (form, authz) = t.last_token_call();
    assert_eq!(form["client_id"], "pub-1");
    assert_eq!(form["scope"], "files.read offline_access");
    assert!(!form.contains_key("client_secret"));
    assert_eq!(authz, None);

    // A confidential client that must authenticate with HTTP Basic.
    let (code, c) = t.mgmt(
        "POST",
        "/v1/secrets",
        Some(json!({
            "name": "basic", "type": "oauth2_client", "value": "rt-basic-abcdefghijkl",
            "fields": { "client_id": "cid", "client_secret": "s3cret-abcdefghijkl", "token_url": TOKEN_URL, "token_auth": "basic" },
            "upstreams": [API, AUTH]
        })),
    );
    assert_eq!(code, 201, "{c}");
    let h = t.handle(json!({ "secret": "basic", "label": "b" }));
    assert_eq!(t.call(&h).0, 200);
    let (form, authz) = t.last_token_call();
    let expected = base64::engine::general_purpose::STANDARD.encode("cid:s3cret-abcdefghijkl");
    assert_eq!(authz.as_deref(), Some(format!("Basic {expected}").as_str()));
    assert!(!form.contains_key("client_secret") && !form.contains_key("client_id"));

    // Incomplete or unusable clients are refused when added, with the reason.
    let bad = |body: Value| t.mgmt("POST", "/v1/secrets", Some(body));
    let (code, b) = bad(
        json!({ "name": "x1", "type": "oauth2_client", "value": "rt", "fields": { "client_id": "c" }, "upstreams": [API] }),
    );
    assert_eq!(
        (code, b["error"].as_str()),
        (400, Some("oauth_client_incomplete")),
        "{b}"
    );
    let (code, b) = bad(
        json!({ "name": "x2", "type": "oauth2_client", "value": "rt", "fields": { "client_id": "c", "token_url": "http://auth.example.test/token" }, "upstreams": [API] }),
    );
    assert_eq!(
        (code, b["error"].as_str()),
        (400, Some("invalid_token_url")),
        "{b}"
    );
    let (code, b) = bad(
        json!({ "name": "x3", "type": "oauth2_client", "value": "rt", "fields": { "client_id": "c", "token_url": TOKEN_URL } }),
    );
    assert_eq!(
        (code, b["error"].as_str()),
        (400, Some("upstream_required")),
        "{b}"
    );
    let (code, b) = bad(json!({ "name": "x4", "type": "oauth2_client", "value": "just a token" }));
    assert_eq!(
        (code, b["error"].as_str()),
        (400, Some("oauth_client_incomplete")),
        "{b}"
    );
    // Google's own file needs nothing added: its token endpoint and API hosts are known.
    let google = json!({ "type": "authorized_user", "client_id": "g.apps.googleusercontent.com", "client_secret": "GOCSPX-abcdefghijkl", "refresh_token": "1//0abcdefghijklmnop" }).to_string();
    let (code, c) = bad(json!({ "name": "gcloud", "value": google }));
    assert_eq!(code, 201, "{c}");
    assert_eq!(c["type"], "oauth2_client");
    assert_eq!(c["upstreams"], json!(["*.googleapis.com"]));
    t.daemon.shutdown().await;
}
