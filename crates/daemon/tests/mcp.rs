//! MCP server tests over `POST /mcp`, including the approval flow.

use axum::extract::Request;
use axum::response::IntoResponse;
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

const PW: &str = "mcp-test-password";
const STRIPE_KEY: &str = "sk_live_51Habcdefghijklmnop";
const SLACK_TOKEN: &str = "xoxb-1234567890-abcdefghijklmnop";

async fn echo(req: Request) -> axum::response::Response {
    let (parts, body) = req.into_parts();
    let auth = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = axum::body::to_bytes(body, 1 << 20)
        .await
        .unwrap_or_default();
    // `/…/refuse` plays a provider that rejects the key.
    let code = if parts.uri.path().ends_with("/refuse") {
        axum::http::StatusCode::UNAUTHORIZED
    } else {
        axum::http::StatusCode::OK
    };
    (
        code,
        [
            ("content-type", "application/json"),
            ("x-request-id", "req_123"),
        ],
        json!({
            "method": parts.method.as_str(), "path": parts.uri.path(), "query": parts.uri.query(),
            "auth_len": auth.len(), "auth": auth, "body": String::from_utf8_lossy(&body),
        })
        .to_string(),
    )
        .into_response()
}

struct Env {
    _daemon: Running,
    base: String,
    session: String,
    mcp_token: String,
    agent: ureq::Agent,
}

fn call(r: Result<ureq::Response, ureq::Error>) -> (u16, Value) {
    match r {
        Ok(resp) => {
            let code = resp.status();
            let text = resp.into_string().unwrap_or_default();
            (
                code,
                serde_json::from_str(&text).unwrap_or(Value::String(text)),
            )
        }
        Err(ureq::Error::Status(code, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            (
                code,
                serde_json::from_str(&text).unwrap_or(Value::String(text)),
            )
        }
        Err(e) => panic!("transport: {e}"),
    }
}

impl Env {
    fn mgmt(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let req = self
            .agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.session));
        call(match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        })
    }
    fn rpc(&self, token: &str, msg: Value) -> (u16, Value) {
        call(
            self.agent
                .post(&format!("{}/mcp", self.base))
                .set("Authorization", &format!("Bearer {token}"))
                .set("Content-Type", "application/json")
                .send_string(&msg.to_string()),
        )
    }
    fn tool(&self, name: &str, args: Value) -> Value {
        let (code, v) = self.rpc(
            &self.mcp_token,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": name, "arguments": args } }),
        );
        assert_eq!(code, 200, "{v}");
        v["result"].clone()
    }
}

fn tool_json(result: &Value) -> Value {
    let text = result["content"][0]["text"].as_str().unwrap_or("");
    serde_json::from_str(text).unwrap_or(Value::String(text.to_string()))
}

async fn setup() -> Arc<Env> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    std::mem::forget(dir);
    {
        let (_v, _k) = Vault::create(
            SqliteStorage::open(&path).unwrap(),
            SystemClock,
            &SecretBytes::from(PW),
            Argon2Profile::MINIMUM,
        )
        .unwrap();
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(any(echo)))
            .await
            .unwrap();
    });
    let daemon = serve(ServeOptions {
        vault_path: path,
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: true,
        upstream_overrides: vec![("api.stripe.com".into(), format!("http://{mock}"))],
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap();
    let mut env = Env {
        base: format!("http://{}", daemon.addr),
        session: daemon.token().to_string(),
        mcp_token: String::new(),
        agent: ureq::AgentBuilder::new()
            .max_idle_connections(0)
            .timeout(Duration::from_secs(20))
            .redirects(0)
            .build(),
        _daemon: daemon,
    };
    assert_eq!(
        env.mgmt("POST", "/v1/unlock", Some(json!({ "password": PW })))
            .0,
        200
    );
    for (name, value) in [("stripe-live", STRIPE_KEY), ("slack", SLACK_TOKEN)] {
        assert_eq!(
            env.mgmt(
                "POST",
                "/v1/secrets",
                Some(json!({ "name": name, "value": value }))
            )
            .0,
            201
        );
    }
    let (code, c) = env.mgmt("POST", "/v1/callers", Some(json!({ "name": "cursor" })));
    assert_eq!(code, 201, "{c}");
    env.mcp_token = c["token"].as_str().unwrap().to_string();
    assert!(env.mcp_token.starts_with("usk_m_"));
    Arc::new(env)
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_tools_and_auth() {
    let env = setup().await;
    let (code, v) = env.rpc(&env.mcp_token, json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "test", "version": "0" } } }));
    assert_eq!(code, 200, "{v}");
    assert_eq!(v["result"]["serverInfo"]["name"], "unseenkey");
    assert!(v["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("never"));
    // Notifications get 202 and no body.
    let (code, _) = env.rpc(
        &env.mcp_token,
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
    );
    assert_eq!(code, 202);
    let (_, v) = env.rpc(
        &env.mcp_token,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    );
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "list_secrets",
            "call_api",
            "request_access",
            "explain_policy"
        ],
        "store_secret is off by default"
    );
    let (_, v) = env.rpc(
        &env.mcp_token,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "nope" }),
    );
    assert_eq!(v["error"]["code"], -32601);
    // Auth: no token, bad token, and a GET are refused; the session token works as `local`.
    let (code, _) = call(
        env.agent
            .post(&format!("{}/mcp", env.base))
            .send_string("{}"),
    );
    assert_eq!(code, 401);
    assert_eq!(
        env.rpc(
            "usk_m_00000000000000000000000000000000",
            json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })
        )
        .0,
        401
    );
    assert_eq!(
        env.rpc(
            &env.session,
            json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })
        )
        .0,
        200
    );
    let (code, _) = call(
        env.agent
            .get(&format!("{}/mcp", env.base))
            .set("Authorization", &format!("Bearer {}", env.mcp_token))
            .call(),
    );
    assert_eq!(code, 405);
    // Browser origin is rejected on /mcp too.
    let (code, v) = call(
        env.agent
            .post(&format!("{}/mcp", env.base))
            .set("Origin", "https://evil.example")
            .set("Authorization", &format!("Bearer {}", env.mcp_token))
            .send_string("{}"),
    );
    assert_eq!(code, 403, "{v}");
    env.mgmt("POST", "/v1/shutdown", Some(json!({})));
}

#[tokio::test(flavor = "multi_thread")]
async fn list_explain_and_call_api_never_expose_values() {
    let env = setup().await;
    let list = tool_json(&env.tool("list_secrets", json!({})));
    let names: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["slack", "stripe-live"]);
    assert_eq!(list[1]["policy_is_default"], true);
    assert!(list[1]["policy"].as_str().unwrap().starts_with("Can "));
    assert!(!list.to_string().contains(STRIPE_KEY) && !list.to_string().contains(SLACK_TOKEN));
    let filtered = tool_json(&env.tool("list_secrets", json!({ "filter": "stripe" })));
    assert_eq!(filtered.as_array().unwrap().len(), 1);

    let ex = tool_json(&env.tool("explain_policy", json!({ "secret": "stripe-live" })));
    assert!(
        ex["text"]
            .as_str()
            .unwrap()
            .contains("Only to api.stripe.com"),
        "{ex}"
    );

    // call_api: the broker injects the key; the agent sees a scrubbed echo.
    let r = env.tool(
        "call_api",
        json!({ "secret": "stripe-live", "method": "GET", "path": "/v1/customers?limit=3" }),
    );
    assert_eq!(r["isError"], false, "{r}");
    let body = tool_json(&r);
    assert_eq!(body["status"], 200);
    let echoed: Value = serde_json::from_str(body["body"].as_str().unwrap()).unwrap();
    assert_eq!(echoed["path"], "/v1/customers");
    assert_eq!(echoed["query"], "limit=3");
    assert_eq!(
        echoed["auth_len"],
        ("Bearer ".len() + STRIPE_KEY.len()) as u64
    );
    assert_eq!(echoed["auth"], "Bearer [REDACTED:usk:stripe-live]");
    assert_eq!(body["headers"]["x-request-id"], "req_123");
    assert!(!r.to_string().contains(STRIPE_KEY));
    // After first use the handle exists with the recommended policy and caller binding.
    let (_, handles) = env.mgmt("GET", "/v1/handles", None);
    let h = handles
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["label"] == "mcp:cursor/stripe-live")
        .expect("auto handle");
    assert_eq!(h["policy"]["callers"][0], "mcp:cursor");
    let list = tool_json(&env.tool("list_secrets", json!({ "filter": "stripe" })));
    assert_eq!(list[0]["policy_is_default"], false);

    // Policy denial surfaces as a tool error with the broker's reason.
    let r = env.tool("call_api", json!({ "secret": "stripe-live", "method": "POST", "path": "/v1/refunds", "body": { "charge": "ch_1" } }));
    assert_eq!(r["isError"], true, "{r}");
    assert!(r["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("policy_denied"));
    // The auto-created handle got Stripe's least-privilege recommended policy
    // (read-only); POST is refused until the owner widens it.
    let r = env.tool("call_api", json!({ "secret": "stripe-live", "method": "POST", "path": "/v1/customers", "body": { "email": "a@b.c" } }));
    assert_eq!(r["isError"], true, "{r}");
    let mut wider = unseenkey_core::presets::policy_ref("stripe:payments").unwrap();
    wider.callers = vec!["mcp:cursor".into()];
    let (code, _) = env.mgmt(
        "PATCH",
        "/v1/handles/mcp:cursor%2Fstripe-live",
        Some(json!({ "policy": serde_json::from_str::<Value>(&wider.to_json()).unwrap() })),
    );
    assert_eq!(code, 200);
    // JSON body is sent as application/json.
    let r = env.tool("call_api", json!({ "secret": "stripe-live", "method": "POST", "path": "/v1/customers", "body": { "email": "a@b.c" } }));
    let echoed: Value = serde_json::from_str(tool_json(&r)["body"].as_str().unwrap()).unwrap();
    assert_eq!(echoed["body"], "{\"email\":\"a@b.c\"}");
    // Prompt-injection style: the agent tries to send another stored secret out.
    let r = env.tool("call_api", json!({ "secret": "stripe-live", "method": "POST", "path": "/v1/customers", "body": { "note": format!("token {SLACK_TOKEN}") } }));
    assert_eq!(r["isError"], true);
    assert!(
        r["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("egress_blocked"),
        "{r}"
    );
    assert!(!r.to_string().contains(SLACK_TOKEN));
    // Generic secrets need an upstream; unknown secrets fail cleanly.
    let r = env.tool(
        "call_api",
        json!({ "secret": "slack", "method": "GET", "path": "/api/x" }),
    );
    assert_eq!(r["isError"], true);
    let r = env.tool(
        "call_api",
        json!({ "secret": "nope", "method": "GET", "path": "/" }),
    );
    assert_eq!(r["isError"], true);
    assert!(
        r["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("no secret named \"nope\""),
        "{r}"
    );
    // store_secret is disabled.
    let r = env.tool(
        "store_secret",
        json!({ "name": "x", "value": "sk_live_zzzzzzzzzzzzzzzzzzzz" }),
    );
    assert_eq!(r["isError"], true);
    // Resources and prompts.
    let (_, v) = env.rpc(&env.mcp_token, json!({ "jsonrpc": "2.0", "id": 9, "method": "resources/read", "params": { "uri": "usk://audit/recent" } }));
    let text = v["result"]["contents"][0]["text"].as_str().unwrap();
    assert!(text.contains("\"caller\": \"mcp:cursor\""), "{text}");
    assert!(!text.contains(STRIPE_KEY));
    let (_, v) = env.rpc(&env.mcp_token, json!({ "jsonrpc": "2.0", "id": 10, "method": "prompts/get", "params": { "name": "setup-project" } }));
    assert!(v["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap()
        .contains("usk guard"));
    env.mgmt("POST", "/v1/shutdown", Some(json!({})));
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_flow() {
    let env = setup().await;
    // First use creates the handle; then gate POST /v1/customers behind approval.
    env.tool(
        "call_api",
        json!({ "secret": "stripe-live", "method": "GET", "path": "/v1/balance_x" }),
    );
    let mut policy = unseenkey_core::presets::policy_ref("stripe:payments").unwrap();
    policy.callers = vec!["mcp:cursor".into()];
    policy.approval.mode = unseenkey_core::policy::ApprovalMode::Paths;
    policy.approval.paths =
        vec![unseenkey_core::policy::Rule::parse("POST /v1/customers").unwrap()];
    policy.approval.timeout_seconds = 5;
    let (code, h) = env.mgmt(
        "PATCH",
        "/v1/handles/mcp:cursor%2Fstripe-live",
        Some(json!({ "policy": serde_json::from_str::<Value>(&policy.to_json()).unwrap() })),
    );
    assert_eq!(code, 200, "{h}");

    // 1. A gated call waits; the owner approves with "remember"; it completes.
    let e2 = env.clone();
    let waiting = tokio::task::spawn_blocking(move || {
        e2.tool("call_api", json!({ "secret": "stripe-live", "method": "POST", "path": "/v1/customers", "body": { "email": "x@y.z" } }))
    });
    let pending = loop {
        let (_, p) = env.mgmt("GET", "/v1/approvals", None);
        if let Some(first) = p.as_array().and_then(|a| a.first()) {
            break first.clone();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(pending["kind"], "request");
    assert_eq!(pending["caller"], "mcp:cursor");
    assert_eq!(pending["path"], "/v1/customers");
    assert_eq!(pending["scope"], "POST /v1/customers");
    let (code, d) = env.mgmt(
        "POST",
        "/v1/approvals/latest",
        Some(json!({ "decision": "allow", "remember": true })),
    );
    assert_eq!(code, 200, "{d}");
    let r = waiting.await.unwrap();
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(tool_json(&r)["status"], 200);
    // Remembered: the second call needs no approval.
    let r = env.tool(
        "call_api",
        json!({ "secret": "stripe-live", "method": "POST", "path": "/v1/customers", "body": {} }),
    );
    assert_eq!(r["isError"], false);
    assert!(env
        .mgmt("GET", "/v1/approvals", None)
        .1
        .as_array()
        .unwrap()
        .is_empty());

    // 2. A different gated rule: deny.
    let mut policy2 = policy.clone();
    policy2.approval.paths =
        vec![unseenkey_core::policy::Rule::parse("POST /v1/payment_intents").unwrap()];
    let (code, _) = env.mgmt(
        "PATCH",
        "/v1/handles/mcp:cursor%2Fstripe-live",
        Some(json!({ "policy": serde_json::from_str::<Value>(&policy2.to_json()).unwrap() })),
    );
    assert_eq!(code, 200);
    let e2 = env.clone();
    let waiting = tokio::task::spawn_blocking(move || {
        e2.tool("call_api", json!({ "secret": "stripe-live", "method": "POST", "path": "/v1/payment_intents", "body": {} }))
    });
    loop {
        if !env
            .mgmt("GET", "/v1/approvals", None)
            .1
            .as_array()
            .unwrap()
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    env.mgmt(
        "POST",
        "/v1/approvals/latest",
        Some(json!({ "decision": "deny" })),
    );
    let r = waiting.await.unwrap();
    assert_eq!(r["isError"], true);
    assert!(
        r["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("approval_denied"),
        "{r}"
    );

    // 3. Timeout (1 s) when nobody answers.
    let mut policy3 = policy2.clone();
    policy3.approval.timeout_seconds = 1;
    env.mgmt(
        "PATCH",
        "/v1/handles/mcp:cursor%2Fstripe-live",
        Some(json!({ "policy": serde_json::from_str::<Value>(&policy3.to_json()).unwrap() })),
    );
    let r = env.tool("call_api", json!({ "secret": "stripe-live", "method": "POST", "path": "/v1/payment_intents", "body": {} }));
    assert_eq!(r["isError"], true);
    assert!(
        r["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("approval_timeout"),
        "{r}"
    );
    // Deciding an expired approval fails cleanly.
    let (code, _) = env.mgmt(
        "POST",
        "/v1/approvals/latest",
        Some(json!({ "decision": "allow" })),
    );
    assert_eq!(code, 404);

    // 4. request_access: denied-by-policy paths are refused immediately; gated paths wait.
    let r = env.tool(
        "request_access",
        json!({ "secret": "stripe-live", "reason": "need refunds", "scope": "POST /v1/refunds" }),
    );
    assert_eq!(r["isError"], true);
    assert_eq!(tool_json(&r)["status"], "denied_by_policy");
    let e2 = env.clone();
    let waiting = tokio::task::spawn_blocking(move || {
        e2.tool("request_access", json!({ "secret": "stripe-live", "reason": "create intents", "scope": "POST /v1/payment_intents" }))
    });
    loop {
        let (_, p) = env.mgmt("GET", "/v1/approvals", None);
        if p.as_array().unwrap().iter().any(|a| a["kind"] == "access") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    env.mgmt(
        "POST",
        "/v1/approvals/latest",
        Some(json!({ "decision": "allow", "remember": true })),
    );
    let r = waiting.await.unwrap();
    assert_eq!(tool_json(&r)["status"], "allowed", "{r}");
    // ...and the remembered rule now lets the gated call through (policy3 still gates it).
    let r = env.tool("call_api", json!({ "secret": "stripe-live", "method": "POST", "path": "/v1/payment_intents", "body": {} }));
    assert_eq!(r["isError"], false, "{r}");

    let (_, events) = env.mgmt("GET", "/v1/audit?kind=approval_decided", None);
    assert!(events.as_array().unwrap().len() >= 4);
    env.mgmt("POST", "/v1/shutdown", Some(json!({})));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_access_can_add_a_host_the_secret_is_not_locked_to() {
    let env = setup().await;
    let (code, _) = env.mgmt("POST", "/v1/secrets", Some(json!({ "name": "hosted", "value": "tok_abcdefghijklmnop", "provider": "generic", "upstreams": ["api.one.example"] })));
    assert_eq!(code, 201);
    // Refused for the host, with the owner's fix in the message.
    let r = env.tool("call_api", json!({ "secret": "hosted", "method": "GET", "path": "/v1/me", "upstream": "https://api.two.example" }));
    assert_eq!(r["isError"], true, "{r}");
    let text = r["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        text.contains("host_not_allowed") || text.contains("not an allowed host"),
        "{r}"
    );
    assert!(
        text.contains("usk secret set hosted --upstream api.two.example"),
        "{r}"
    );
    // Ask for the host; the owner approves; the secret now allows it.
    let e2 = env.clone();
    let waiting = tokio::task::spawn_blocking(move || {
        e2.tool("request_access", json!({ "secret": "hosted", "reason": "the API moved", "upstream": "https://api.two.example/v1/" }))
    });
    loop {
        let (_, p) = env.mgmt("GET", "/v1/approvals", None);
        if let Some(a) = p.as_array().unwrap().iter().find(|a| a["kind"] == "access") {
            assert!(
                a["scope"]
                    .as_str()
                    .unwrap()
                    .contains("allow the host api.two.example"),
                "{a}"
            );
            assert_eq!(a["host"], "api.two.example");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    env.mgmt(
        "POST",
        "/v1/approvals/latest",
        Some(json!({ "decision": "allow", "remember": false })),
    );
    let r = waiting.await.unwrap();
    let j = tool_json(&r);
    assert_eq!(j["status"], "allowed", "{r}");
    assert!(
        j["message"]
            .as_str()
            .unwrap()
            .contains("api.two.example is now an allowed host"),
        "{r}"
    );
    let (_, m) = env.mgmt("GET", "/v1/secrets/hosted", None);
    assert_eq!(
        m["upstreams"],
        json!(["api.one.example", "api.two.example"])
    );
    // The host lock no longer refuses it (the host itself is unreachable here, which is a different error).
    let r = env.tool("call_api", json!({ "secret": "hosted", "method": "GET", "path": "/v1/me", "upstream": "https://api.two.example" }));
    let text = r["content"][0]["text"].as_str().unwrap_or("");
    assert!(!text.contains("host_not_allowed"), "{r}");
    let (_, events) = env.mgmt("GET", "/v1/audit?kind=secret_updated", None);
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["body"]["upstream_added"] == "api.two.example"),
        "{events}"
    );
    env.mgmt("POST", "/v1/shutdown", Some(json!({})));
}

impl Env {
    /// A tool call from a client that reports it runs in `dir`.
    fn tool_in(&self, dir: &str, name: &str, args: Value) -> Value {
        let (code, v) = call(
            self.agent
                .post(&format!("{}/mcp", self.base))
                .set("Authorization", &format!("Bearer {}", self.mcp_token))
                .set("Content-Type", "application/json")
                .set(
                    unseenkey_daemon::mcp::PROJECT_DIR_HEADER,
                    &unseenkey_core::projects::encode_dir(dir),
                )
                .send_string(
                    &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": name, "arguments": args } })
                        .to_string(),
                ),
        );
        assert_eq!(code, 200, "{v}");
        v["result"].clone()
    }
}

/// Inside a project's folder a client sees and uses only that project's
/// secrets, and the handle it gets is the project's; elsewhere nothing changes.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_in_a_project_folder_sees_only_that_project() {
    let env = setup().await;
    let (code, p) = env.mgmt(
        "POST",
        "/v1/projects",
        Some(json!({ "name": "My Shop", "paths": [r"C:\Work\Shöp"], "secrets": ["stripe-live"] })),
    );
    assert_eq!(code, 201, "{p}");
    let inside = r"c:\work\shöp\web\src";

    let r = env.tool_in(inside, "list_secrets", json!({}));
    assert_eq!(r["isError"], false, "{r}");
    let list = tool_json(&r);
    let names: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["stripe-live"]);
    assert_eq!(list[0]["project"], "My Shop");

    for (tool, args) in [
        (
            "call_api",
            json!({ "secret": "slack", "method": "GET", "path": "/api/x", "upstream": "https://slack.com" }),
        ),
        ("explain_policy", json!({ "secret": "slack" })),
        (
            "request_access",
            json!({ "secret": "slack", "reason": "post a message" }),
        ),
    ] {
        let r = env.tool_in(inside, tool, args);
        assert_eq!(r["isError"], true, "{tool}: {r}");
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("not part of the project \"My Shop\""),
            "{tool}: {text}"
        );
    }

    let r = env.tool_in(
        inside,
        "call_api",
        json!({ "secret": "stripe-live", "method": "GET", "path": "/v1/customers" }),
    );
    assert_eq!(r["isError"], false, "{r}");
    let (_, handles) = env.mgmt("GET", "/v1/handles", None);
    let h = handles
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["label"] == "mcp:cursor/My Shop/stripe-live")
        .unwrap_or_else(|| panic!("no project handle in {handles}"));
    assert_eq!(h["project"], "My Shop");
    let (_, pv) = env.mgmt(
        "GET",
        &format!("/v1/projects/{}", p["id"].as_str().unwrap()),
        None,
    );
    assert_eq!(pv["requests_today"], 1, "{pv}");
    assert_eq!(pv["handles"], 1, "{pv}");

    // Outside the folder, and without a folder, the client sees everything.
    for r in [
        env.tool_in(r"C:\Work\Other", "list_secrets", json!({})),
        env.tool("list_secrets", json!({})),
    ] {
        assert_eq!(tool_json(&r).as_array().unwrap().len(), 2, "{r}");
    }
}

/// When the provider itself refuses the key, the agent is told that retrying
/// cannot help and how the owner fixes it, instead of guessing.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_key_comes_with_the_owners_fix() {
    let env = setup().await;
    let r = env.tool(
        "call_api",
        json!({ "secret": "stripe-live", "method": "GET", "path": "/v1/refuse" }),
    );
    assert_eq!(
        r["isError"], false,
        "the provider answered; it is not a broker error: {r}"
    );
    let body = tool_json(&r);
    assert_eq!(body["status"], 401);
    let hint = body["hint"].as_str().unwrap();
    assert!(
        hint.contains("Replace value") && hint.contains("usk secret replace stripe-live"),
        "{hint}"
    );

    // A secret without a provider sends no credentials: the hint says so.
    let (code, c) = env.mgmt(
        "POST",
        "/v1/secrets",
        Some(json!({ "name": "plain", "value": "qwertyuiopasdfghjklzxcvbnm123456", "upstreams": ["api.stripe.com"] })),
    );
    assert_eq!(code, 201, "{c}");
    assert!(c["provider"].is_null(), "{c}");
    let r = env.tool(
        "call_api",
        json!({ "secret": "plain", "method": "GET", "path": "/v1/refuse", "upstream": "https://api.stripe.com" }),
    );
    let hint = tool_json(&r)["hint"].as_str().unwrap().to_string();
    assert!(hint.contains("has no provider"), "{hint}");

    // A success carries no hint.
    let r = env.tool(
        "call_api",
        json!({ "secret": "stripe-live", "method": "GET", "path": "/v1/customers" }),
    );
    assert!(tool_json(&r)["hint"].is_null(), "{r}");
}
