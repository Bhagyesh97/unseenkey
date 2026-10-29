//! "Paste and done": recognise a key without sending it anywhere, fill in its
//! provider and hosts, and test it with one read-only request.

use axum::extract::Request;
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, Running, ServeOptions};

const PW: &str = "keytest-password";
const GOOD_XAI: &str = "xai-goodgoodgoodgoodgoodgoodgoodgoodgoodgoodgood";
const BAD_XAI: &str = "xai-badbadbadbadbadbadbadbadbadbadbadbadbadbadb";
const DEEPGRAM: &str = "0123456789abcdef0123456789abcdef01234567";

/// Plays both providers: 200 for the right credential in the right place, 401 otherwise.
async fn provider(req: Request) -> axum::response::Response {
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let ok = match req.uri().path() {
        "/v1/models" => auth == format!("Bearer {GOOD_XAI}"),
        "/v1/projects" => auth == format!("Token {DEEPGRAM}"),
        _ => false,
    };
    let code = if ok {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::UNAUTHORIZED
    };
    (
        code,
        [("content-type", "application/json")],
        json!({ "seen_auth_len": auth.len() }).to_string(),
    )
        .into_response()
}

struct C {
    base: String,
    token: String,
    agent: ureq::Agent,
}

impl C {
    fn call(r: Result<ureq::Response, ureq::Error>) -> (u16, Value) {
        match r {
            Ok(resp) => {
                let code = resp.status();
                (code, resp.into_json().unwrap_or(Value::Null))
            }
            Err(ureq::Error::Status(code, resp)) => (code, resp.into_json().unwrap_or(Value::Null)),
            Err(e) => panic!("transport: {e}"),
        }
    }
    fn post(&self, path: &str, body: Value) -> (u16, Value) {
        Self::call(
            self.agent
                .post(&format!("{}{}", self.base, path))
                .set("Authorization", &format!("Bearer {}", self.token))
                .send_json(body),
        )
    }
    fn get(&self, path: &str) -> (u16, Value) {
        Self::call(
            self.agent
                .get(&format!("{}{}", self.base, path))
                .set("Authorization", &format!("Bearer {}", self.token))
                .call(),
        )
    }
}

async fn setup() -> (tempfile::TempDir, Running, C) {
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(any(provider)))
            .await
            .unwrap()
    });
    let r = serve(ServeOptions {
        vault_path: path,
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: false,
        upstream_overrides: vec![
            ("api.x.ai".into(), format!("http://{mock}")),
            ("api.deepgram.com".into(), format!("http://{mock}")),
        ],
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap();
    let c = C {
        base: format!("http://{}", r.addr),
        token: r.token().to_string(),
        agent: ureq::AgentBuilder::new()
            .max_idle_connections(0)
            .timeout(Duration::from_secs(20))
            .build(),
    };
    assert_eq!(c.post("/v1/unlock", json!({ "password": PW })).0, 200);
    (dir, r, c)
}

#[tokio::test(flavor = "multi_thread")]
async fn recognising_a_key_sends_it_nowhere() {
    let (_dir, r, c) = setup().await;
    let (code, b) = c.post("/v1/detect", json!({ "value": GOOD_XAI }));
    assert_eq!(code, 200, "{b}");
    assert_eq!(b["recognised"]["provider"], "xai");
    assert_eq!(b["recognised"]["how"], "shape");
    assert_eq!(b["recognised"]["testable"], true);
    // No shape: the name decides.
    let (_, b) = c.post(
        "/v1/detect",
        json!({ "value": DEEPGRAM, "name": "DEEPGRAM_API_KEY" }),
    );
    assert_eq!(
        (
            b["recognised"]["provider"].as_str(),
            b["recognised"]["how"].as_str()
        ),
        (Some("deepgram"), Some("name"))
    );
    // The shape beats the name.
    let (_, b) = c.post(
        "/v1/detect",
        json!({ "value": GOOD_XAI, "name": "deepgram" }),
    );
    assert_eq!(b["recognised"]["provider"], "xai");
    // Nothing to go on.
    let (_, b) = c.post(
        "/v1/detect",
        json!({ "value": DEEPGRAM, "name": "db password" }),
    );
    assert!(b["recognised"].is_null(), "{b}");
    // And nothing was stored.
    assert_eq!(c.get("/v1/secrets").1.as_array().unwrap().len(), 0);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn paste_save_and_test() {
    let (_dir, r, c) = setup().await;

    // A key with its own prefix: provider and hosts fill in by themselves.
    let (code, s) = c.post("/v1/secrets", json!({ "name": "grok", "value": GOOD_XAI }));
    assert_eq!(code, 201, "{s}");
    assert_eq!(s["provider"], "xai");
    assert_eq!(s["upstreams"], json!(["api.x.ai"]));
    assert_eq!(s["detected"]["how"], "shape");
    let (code, t) = c.post("/v1/secrets/grok/test", json!({}));
    assert_eq!(code, 200, "{t}");
    assert_eq!(
        (
            t["tested"].as_bool(),
            t["ok"].as_bool(),
            t["status"].as_u64()
        ),
        (Some(true), Some(true), Some(200)),
        "{t}"
    );
    assert!(t["message"].as_str().unwrap().contains("accepted"), "{t}");

    // An opaque key named after its provider: the name fills it in, and the
    // test uses the provider's own scheme (`Authorization: Token …`).
    let (code, s) = c.post(
        "/v1/secrets",
        json!({ "name": "deepgram", "value": DEEPGRAM }),
    );
    assert_eq!(code, 201, "{s}");
    assert_eq!(
        (s["provider"].as_str(), s["detected"]["how"].as_str()),
        (Some("deepgram"), Some("name")),
        "{s}"
    );
    let (_, t) = c.post("/v1/secrets/deepgram/test", json!({}));
    assert_eq!(t["ok"], true, "{t}");

    // A refused key says so in plain words.
    let (_, _) = c.post(
        "/v1/secrets",
        json!({ "name": "old-grok", "value": BAD_XAI }),
    );
    let (_, t) = c.post("/v1/secrets/old-grok/test", json!({}));
    assert_eq!(
        (t["ok"].as_bool(), t["status"].as_u64()),
        (Some(false), Some(401)),
        "{t}"
    );
    assert!(t["message"].as_str().unwrap().contains("refused"), "{t}");

    // No provider: nothing is sent.
    let (_, _) = c.post(
        "/v1/secrets",
        json!({ "name": "mystery", "value": DEEPGRAM, "upstreams": ["api.example.com"] }),
    );
    let (_, t) = c.post("/v1/secrets/mystery/test", json!({}));
    assert_eq!(t["tested"], false, "{t}");

    // Tests are audited, and the key never appears in the log.
    let (_, log) = c.get("/v1/audit?kind=key_tested&limit=100");
    let log = log.as_array().unwrap();
    assert_eq!(log.len(), 3, "{log:?}");
    let text = serde_json::to_string(log).unwrap();
    assert!(!text.contains(GOOD_XAI) && !text.contains(DEEPGRAM));
    r.shutdown().await;
}

/// A provider with its own Authorization scheme also works through the broker:
/// the SDK sends `Token <handle>`, the provider receives `Token <key>`.
#[tokio::test(flavor = "multi_thread")]
async fn a_custom_scheme_works_through_the_broker() {
    let (_dir, r, c) = setup().await;
    assert_eq!(
        c.post(
            "/v1/secrets",
            json!({ "name": "deepgram", "value": DEEPGRAM })
        )
        .0,
        201
    );
    let (code, h) = c.post(
        "/v1/handles",
        json!({ "secret": "deepgram", "label": "app" }),
    );
    assert_eq!(code, 201, "{h}");
    let handle = h["handle"].as_str().unwrap();
    let (code, body) = C::call(
        c.agent
            .get(&format!("{}/p/deepgram/v1/projects", c.base))
            .set("Authorization", &format!("Token {handle}"))
            .call(),
    );
    assert_eq!(code, 200, "{body}");
    r.shutdown().await;
}
