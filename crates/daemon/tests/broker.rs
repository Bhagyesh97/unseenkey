//! Broker end-to-end tests against a mock upstream.
//!
//! The mock speaks HTTP on loopback. The daemon maps the logical hosts
//! (`api.openai.com`, `api.stripe.com`) to it via `upstream_overrides`, so the
//! host lock still sees the real host names.

use axum::body::Bytes;
use axum::extract::Request;
use axum::response::sse::{Event as SseEvent, Sse};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, Running, ServeOptions};

const PW: &str = "broker-test-password";
const OPENAI_KEY: &str = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
const STRIPE_KEY: &str = "sk_live_51Habcdefghijklmnop";
const OTHER_SECRET: &str = "xoxb-1234567890-abcdefghijklmnop";

/// Mock upstream: echoes method, path, query, headers and body as JSON;
/// `/stream` returns SSE that includes the received Authorization header
/// (to prove response scrubbing); `/redirect` returns a 302.
async fn echo(req: Request) -> axum::response::Response {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map(str::to_string);
    let headers: serde_json::Map<String, Value> = parts
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                Value::String(v.to_str().unwrap_or("").to_string()),
            )
        })
        .collect();
    let body = axum::body::to_bytes(body, 1 << 20)
        .await
        .unwrap_or_default();
    let auth = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if path == "/stream" {
        let events = vec![
            Ok::<_, Infallible>(SseEvent::default().data(json!({"delta": "Hello"}).to_string())),
            Ok(SseEvent::default().data(json!({"delta": " world", "echo": auth}).to_string())),
            Ok(SseEvent::default().data("[DONE]")),
        ];
        return Sse::new(tokio_stream::iter(events)).into_response();
    }
    if path == "/redirect" {
        return (
            axum::http::StatusCode::FOUND,
            [("location", "https://evil.example/steal")],
            "",
        )
            .into_response();
    }
    let status = if path.ends_with("/teapot") { 418 } else { 200 };
    (
        axum::http::StatusCode::from_u16(status).unwrap(),
        [
            ("content-type", "application/json"),
            ("set-cookie", "session=abc"),
            ("x-echo-key", "key-was-here"),
        ],
        json!({
            "method": parts.method.as_str(),
            "path": path,
            "query": query,
            "headers": headers,
            "body": String::from_utf8_lossy(&body),
            // The real credential is scrubbed from the echoed headers on the way
            // back, so report its shape separately to prove injection happened.
            "auth_len": auth.len(),
            "auth_prefix": auth.chars().take(12).collect::<String>(),
        })
        .to_string(),
    )
        .into_response()
}

async fn mock_upstream() -> SocketAddr {
    let app = Router::new().fallback(any(echo));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

struct Env {
    daemon: Running,
    base: String,
    token: String,
    agent: ureq::Agent,
    mock: SocketAddr,
}

impl Env {
    fn mgmt(&self, method: &str, path: &str) -> ureq::Request {
        self.agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token))
    }
    fn call(r: Result<ureq::Response, ureq::Error>) -> (u16, Value, Vec<(String, String)>) {
        match r {
            Ok(resp) => {
                let code = resp.status();
                let hdrs = resp
                    .headers_names()
                    .into_iter()
                    .map(|n| (n.clone(), resp.header(&n).unwrap_or("").to_string()))
                    .collect();
                let body = resp.into_string().unwrap_or_default();
                (
                    code,
                    serde_json::from_str(&body).unwrap_or(Value::String(body)),
                    hdrs,
                )
            }
            Err(ureq::Error::Status(code, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                (
                    code,
                    serde_json::from_str(&body).unwrap_or(Value::String(body)),
                    vec![],
                )
            }
            Err(e) => panic!("transport: {e}"),
        }
    }
    fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let (c, b, _) = Self::call(self.mgmt("POST", path).send_json(body));
        (c, b)
    }
    fn get(&self, path: &str) -> (u16, Value) {
        let (c, b, _) = Self::call(self.mgmt("GET", path).call());
        (c, b)
    }
    /// Proxy request with the handle where an SDK would put it.
    fn proxy(
        &self,
        method: &str,
        path: &str,
        auth: (&str, &str),
        body: Option<Value>,
    ) -> (u16, Value, Vec<(String, String)>) {
        let req = self
            .agent
            .request(method, &format!("{}{}", self.base, path))
            .set(auth.0, auth.1);
        Self::call(match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        })
    }
}

async fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    // Leak the tempdir so the vault outlives the test body.
    std::mem::forget(dir);
    {
        let (_v, _kit) = Vault::create(
            SqliteStorage::open(&path).unwrap(),
            SystemClock,
            &SecretBytes::from(PW),
            Argon2Profile::MINIMUM,
        )
        .unwrap();
    }
    let mock = mock_upstream().await;
    let daemon = serve(ServeOptions {
        vault_path: path,
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: false,
        upstream_overrides: vec![
            ("api.openai.com".into(), format!("http://{mock}")),
            ("api.stripe.com".into(), format!("http://{mock}")),
            ("127.0.0.1".into(), format!("http://{mock}")),
        ],
        mcp_allow_store: false,
    })
    .await
    .unwrap();
    let env = Env {
        base: format!("http://{}", daemon.addr),
        token: daemon.token().to_string(),
        // No client-side redirects: the broker must return upstream 3xx untouched.
        agent: ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .redirects(0)
            .build(),
        daemon,
        mock,
    };
    assert_eq!(env.post("/v1/unlock", json!({ "password": PW })).0, 200);
    for (name, value) in [
        ("openai", OPENAI_KEY),
        ("stripe-live", STRIPE_KEY),
        ("slack", OTHER_SECRET),
    ] {
        let (code, _) = env.post("/v1/secrets", json!({ "name": name, "value": value }));
        assert_eq!(code, 201, "{name}");
    }
    env
}

fn create_handle(
    env: &Env,
    secret: &str,
    label: &str,
    preset_policy: Option<&str>,
) -> (String, String) {
    let mut body = json!({ "secret": secret, "label": label });
    if let Some(p) = preset_policy {
        body["preset_policy"] = json!(p);
    }
    let (code, h) = env.post("/v1/handles", body);
    assert_eq!(code, 201, "{h}");
    (
        h["handle"].as_str().unwrap().to_string(),
        h["id"].as_str().unwrap().to_string(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn openai_sdk_style_request_is_injected_and_audited() {
    let env = setup().await;
    let (handle, hid) = create_handle(&env, "openai", "cursor", Some("openai:chat"));
    assert!(handle.starts_with("usk_h_"));

    let (code, body, hdrs) = env.proxy(
        "POST",
        "/p/openai/v1/chat/completions?stream=false",
        ("Authorization", &format!("Bearer {handle}")),
        Some(json!({ "model": "gpt-x", "messages": [] })),
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(body["method"], "POST");
    assert_eq!(body["path"], "/v1/chat/completions");
    assert_eq!(body["query"], "stream=false");
    // The real key reached the upstream (right length and prefix); the handle did not;
    // and the echo of the key was scrubbed before reaching us.
    assert_eq!(
        body["auth_len"],
        ("Bearer ".len() + OPENAI_KEY.len()) as u64
    );
    assert_eq!(body["auth_prefix"], "Bearer sk-pr");
    assert_eq!(
        body["headers"]["authorization"],
        "Bearer [REDACTED:usk:openai]"
    );
    assert!(!body.to_string().contains(&handle));
    assert!(!body.to_string().contains(OPENAI_KEY));
    assert_eq!(
        body["headers"]["host"],
        format!("127.0.0.1:{}", env.mock.port())
    );
    assert!(body["headers"].get("cookie").is_none());
    // Response hygiene: Set-Cookie dropped, other headers kept, handle id reported.
    assert!(!hdrs
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("set-cookie")));
    assert!(hdrs
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("x-echo-key") && v == "key-was-here"));
    assert!(hdrs
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("x-usk-handle-id") && *v == hid));

    // Audit: a `use` event with status 200, before the response was returned.
    let (_, events) = env.get("/v1/audit?kind=use");
    let uses = events.as_array().unwrap();
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0]["body"]["status"], 200);
    assert_eq!(uses[0]["body"]["path"], "/v1/chat/completions");
    assert_eq!(uses[0]["body"]["secret"], "openai");
    assert!(!events.to_string().contains(OPENAI_KEY));
    let (_, verify) = env.get("/v1/audit/verify");
    assert_eq!(verify["ok"], true);
    let (_, h) = env.get(&format!("/v1/handles/{hid}"));
    assert_eq!(h["use_count"], 1);
    env.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_and_host_lock_are_enforced() {
    let env = setup().await;
    let (handle, _) = create_handle(&env, "stripe-live", "dev", Some("stripe:payments"));
    let auth = ("Authorization", format!("Bearer {handle}"));

    // Allowed by stripe:payments.
    let (code, _, _) = env.proxy("GET", "/p/stripe/v1/customers", (auth.0, &auth.1), None);
    assert_eq!(code, 200);
    // Denied by the deny list: refunds.
    let (code, body, _) = env.proxy(
        "POST",
        "/p/stripe/v1/refunds",
        (auth.0, &auth.1),
        Some(json!({})),
    );
    assert_eq!(code, 403);
    assert_eq!(body["error"], "policy_denied");
    assert!(body["message"].as_str().unwrap().contains("refunds"));
    // Not in the allow list: DELETE.
    let (code, _, _) = env.proxy(
        "DELETE",
        "/p/stripe/v1/customers/cus_1",
        (auth.0, &auth.1),
        None,
    );
    assert_eq!(code, 403);
    // Wrong provider route for this secret: the host lock refuses (stripe key to api.openai.com).
    let (code, body, _) = env.proxy("GET", "/p/openai/v1/models", (auth.0, &auth.1), None);
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "host_not_allowed");
    // Generic route with an arbitrary upstream is also refused for this secret.
    let (code, body, _) = Env::call(
        env.agent
            .request("GET", &format!("{}/p/generic/v1/x", env.base))
            .set("X-Usk-Handle", &handle)
            .set("X-Usk-Upstream", "https://evil.example")
            .call(),
    );
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "host_not_allowed");

    let (_, denies) = env.get("/v1/audit?kind=deny");
    assert!(denies.as_array().unwrap().len() >= 3);
    env.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_revoked_and_expired_handles() {
    let env = setup().await;
    let (code, body, _) = env.proxy(
        "GET",
        "/p/openai/v1/models",
        (
            "Authorization",
            "Bearer usk_h_00000000000000000000000000000000",
        ),
        None,
    );
    assert_eq!(code, 401);
    assert_eq!(body["error"], "unknown_handle");
    let (code, body, _) = env.proxy(
        "GET",
        "/p/openai/v1/models",
        ("Authorization", "Bearer garbage"),
        None,
    );
    assert_eq!(code, 401, "{body}");
    let (code, body, _) = Env::call(
        env.agent
            .request("GET", &format!("{}/p/openai/v1/models", env.base))
            .call(),
    );
    assert_eq!(code, 401, "{body}");
    assert_eq!(body["error"], "unknown_handle");
    let (code, body, _) = env.proxy(
        "GET",
        "/p/nope/v1/models",
        ("Authorization", "Bearer x"),
        None,
    );
    assert_eq!(code, 404, "{body}");

    let (handle, hid) = create_handle(&env, "openai", "temp", Some("openai:chat"));
    let auth = format!("Bearer {handle}");
    assert_eq!(
        env.proxy("GET", "/p/openai/v1/models", ("Authorization", &auth), None)
            .0,
        200
    );
    let (code, _, _) = Env::call(env.mgmt("DELETE", &format!("/v1/handles/{hid}")).call());
    assert_eq!(code, 200);
    let (code, body, _) = env.proxy("GET", "/p/openai/v1/models", ("Authorization", &auth), None);
    assert_eq!(code, 401);
    assert_eq!(body["error"], "handle_revoked");
    // Label can be reused after revocation; expiry in the past is refused.
    let (code, h) = env.post(
        "/v1/handles",
        json!({ "secret": "openai", "label": "temp", "expires_in_days": 0 }),
    );
    assert_eq!(code, 201, "{h}");
    let (code, body, _) = env.proxy(
        "GET",
        "/p/openai/v1/models",
        (
            "Authorization",
            &format!("Bearer {}", h["handle"].as_str().unwrap()),
        ),
        None,
    );
    assert_eq!(code, 401, "{body}");
    assert_eq!(body["error"], "handle_expired");
    env.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn egress_guard_blocks_other_secrets_in_requests() {
    let env = setup().await;
    let (handle, _) = create_handle(&env, "openai", "agent", Some("openai:chat"));
    let auth = format!("Bearer {handle}");
    // An agent tries to send the Slack token (a different stored secret) through the OpenAI route.
    let (code, body, _) = env.proxy(
        "POST",
        "/p/openai/v1/chat/completions",
        ("Authorization", &auth),
        Some(json!({ "messages": [{ "content": format!("here is a token {OTHER_SECRET}") }] })),
    );
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "egress_blocked");
    assert!(body["message"].as_str().unwrap().contains("slack"));
    // Base64-encoded form is caught too.
    let b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(STRIPE_KEY)
    };
    let (code, body, _) = env.proxy(
        "POST",
        "/p/openai/v1/chat/completions",
        ("Authorization", &auth),
        Some(json!({ "blob": b64 })),
    );
    assert_eq!(code, 403, "{body}");
    assert!(body["message"].as_str().unwrap().contains("stripe-live"));
    // In a header as well.
    let (code, body, _) = Env::call(
        env.agent
            .request("GET", &format!("{}/p/openai/v1/models", env.base))
            .set("Authorization", &auth)
            .set("X-Debug", STRIPE_KEY)
            .call(),
    );
    assert_eq!(code, 403, "{body}");
    let (_, blocked) = env.get("/v1/audit?kind=egress_blocked");
    assert_eq!(blocked.as_array().unwrap().len(), 3);
    assert!(!blocked.to_string().contains(OTHER_SECRET));
    env.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn responses_are_scrubbed_including_streams() {
    let env = setup().await;
    let (handle, _) = create_handle(&env, "openai", "s", Some("openai:no-admin"));
    let auth = format!("Bearer {handle}");
    // The echo upstream reflects the injected key in the JSON body and in a header.
    let (code, body, hdrs) = env.proxy(
        "POST",
        "/p/openai/v1/anything",
        ("Authorization", &auth),
        Some(json!({ "x": 1 })),
    );
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        body["headers"]["authorization"],
        "Bearer [REDACTED:usk:openai]"
    );
    assert!(!body.to_string().contains(OPENAI_KEY));
    assert!(!hdrs.iter().any(|(_, v)| v.contains(OPENAI_KEY)));
    // SSE stream.
    let resp = env
        .agent
        .request("POST", &format!("{}/p/openai/stream", env.base))
        .set("Authorization", &auth)
        .call()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let text = resp.into_string().unwrap();
    assert!(text.contains("data: {\"delta\":\"Hello\"}"), "{text}");
    assert!(text.contains("[REDACTED:usk:openai]"), "{text}");
    assert!(!text.contains(OPENAI_KEY));
    assert!(text.contains("[DONE]"));
    // Redirects are not followed and the upstream's status comes back.
    let (code, _, hdrs) = env.proxy("GET", "/p/openai/redirect", ("Authorization", &auth), None);
    assert_eq!(code, 302);
    assert!(hdrs
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("location") && v.contains("evil.example")));
    // Upstream status codes pass through.
    let (code, _, _) = env.proxy("GET", "/p/openai/teapot", ("Authorization", &auth), None);
    assert_eq!(code, 418);
    env.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn generic_template_route_and_rate_limits() {
    let env = setup().await;
    // A generic secret locked to the loopback mock.
    let (code, _) = env.post("/v1/secrets", json!({ "name": "example", "value": "tok_abcdefghijklmnop", "provider": "generic", "upstreams": ["127.0.0.1"] }));
    assert_eq!(code, 201);
    let mut policy = unseenkey_core::policy::Policy::allow_all();
    policy.limits.requests_per_minute = Some(2);
    let (code, h) = env.post("/v1/handles", json!({ "secret": "example", "label": "tmpl", "policy": serde_json::from_str::<Value>(&policy.to_json()).unwrap() }));
    assert_eq!(code, 201, "{h}");
    let handle = h["handle"].as_str().unwrap().to_string();
    let call = || {
        Env::call(
            env.agent
                .request("POST", &format!("{}/p/generic/api/v2/things", env.base))
                .set("X-Usk-Handle", &handle)
                .set(
                    "X-Usk-Upstream",
                    &format!("http://127.0.0.1:{}", env.mock.port()),
                )
                .set("X-Api-Token", "{{usk:example}}")
                .send_string("{\"key\":\"{{usk:example}}\"}"),
        )
    };
    let (code, body, _) = call();
    assert_eq!(code, 200, "{body}");
    assert_eq!(
        body["headers"]["x-api-token"], "[REDACTED:usk:example]",
        "injected then scrubbed on echo"
    );
    assert_eq!(body["body"], "{\"key\":\"[REDACTED:usk:example]\"}");
    assert!(body["headers"].get("x-usk-upstream").is_none());
    assert!(body["headers"].get("x-usk-handle").is_none());
    let (code, _, _) = call();
    assert_eq!(code, 200);
    let (code, body, _) = call();
    assert_eq!(code, 429, "{body}");
    assert_eq!(body["error"], "rate_limited");
    // Unknown placeholder names are refused, never forwarded blank (fresh handle: the
    // one above is now rate-limited, and limits are checked before substitution).
    let (code, h2) = env.post(
        "/v1/handles",
        json!({ "secret": "example", "label": "tmpl2" }),
    );
    assert_eq!(code, 201, "{h2}");
    let handle2 = h2["handle"].as_str().unwrap().to_string();
    let (code, body, _) = Env::call(
        env.agent
            .request("GET", &format!("{}/p/generic/x", env.base))
            .set("X-Usk-Handle", &handle2)
            .set(
                "X-Usk-Upstream",
                &format!("http://127.0.0.1:{}", env.mock.port()),
            )
            .set("X-Other", "{{usk:stripe-live}}")
            .call(),
    );
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "unknown_placeholder");
    env.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn locked_vault_and_browser_origin_on_proxy_routes() {
    let env = setup().await;
    let (handle, _) = create_handle(&env, "openai", "x", None);
    let auth = format!("Bearer {handle}");
    let (code, body, _) = Env::call(
        env.agent
            .request("GET", &format!("{}/p/openai/v1/models", env.base))
            .set("Authorization", &auth)
            .set("Origin", "https://evil.example")
            .call(),
    );
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "browser_origin_rejected");
    assert_eq!(env.post("/v1/lock", json!({})).0, 200);
    let (code, body, _) = env.proxy("GET", "/p/openai/v1/models", ("Authorization", &auth), None);
    assert_eq!(code, 401, "{body}");
    assert_eq!(body["error"], "vault_locked");
    env.daemon.shutdown().await;
}

#[allow(dead_code)]
fn _bytes_in_scope(_: Bytes) {}
#[allow(dead_code)]
fn _arc_in_scope(_: Arc<()>) {}
