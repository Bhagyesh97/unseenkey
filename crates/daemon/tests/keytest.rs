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
const TWILIO_SID: &str = "AC0123456789abcdef0123456789abcdef";
const TWILIO_TOKEN: &str = "twilio-token-abcdefghijklmnop";
const MAILGUN_KEY: &str = "mailgun-key-abcdefghijklmnop";
const PLIVO_ID: &str = "MAPLIVOID01234567890";
const PLIVO_TOKEN: &str = "plivo-token-abcdefghijklmnop";

fn basic(pair: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair)
    )
}

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
        "/2010-04-01/Accounts.json" => auth == basic(&format!("{TWILIO_SID}:{TWILIO_TOKEN}")),
        "/v4/domains" => auth == basic(&format!("api:{MAILGUN_KEY}")),
        "/v1/Account/MAPLIVOID01234567890/" => auth == basic(&format!("{PLIVO_ID}:{PLIVO_TOKEN}")),
        // Answers with what it was sent, as a careless provider might.
        "/2010-04-01/echo.json" => {
            return (
                [("content-type", "application/json")],
                json!({ "auth": auth, "account_sid": TWILIO_SID }).to_string(),
            )
                .into_response()
        }
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
    owner: std::sync::Mutex<Option<String>>,
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
        let mut req = self
            .agent
            .post(&format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token));
        if let Some(o) = self.owner.lock().unwrap().as_ref() {
            req = req.set("X-Usk-Owner", o);
        }
        let (code, v) = Self::call(req.send_json(body));
        if code == 200 && path == "/v1/unlock" {
            *self.owner.lock().unwrap() = v["owner_token"].as_str().map(str::to_string);
        }
        (code, v)
    }
    fn patch(&self, path: &str, body: Value) -> (u16, Value) {
        let mut req = self
            .agent
            .request("PATCH", &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token));
        if let Some(o) = self.owner.lock().unwrap().as_ref() {
            req = req.set("X-Usk-Owner", o);
        }
        Self::call(req.send_json(body))
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
            ("api.twilio.com".into(), format!("http://{mock}")),
            ("api.mailgun.net".into(), format!("http://{mock}")),
            ("api.plivo.com".into(), format!("http://{mock}")),
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
        owner: std::sync::Mutex::new(None),
        agent: ureq::AgentBuilder::new()
            .max_idle_connections(0)
            .timeout_read(Duration::from_secs(20))
            .timeout_write(Duration::from_secs(20))
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
async fn a_key_in_two_parts() {
    let (_dir, r, c) = setup().await;
    let test = |name: &str| c.post(&format!("/v1/secrets/{name}/test"), json!({})).1;

    // Half of it can be stored (an import meets them one at a time). It is not
    // sent, and both the test and a call say what is missing.
    let (code, made) = c.post(
        "/v1/secrets",
        json!({ "name": "twilio", "value": TWILIO_TOKEN }),
    );
    assert_eq!(code, 201, "{made}");
    assert_eq!(made["provider"], "twilio");
    assert_eq!(made["type"], "basic_auth");
    let t = test("twilio");
    assert_eq!(t["tested"], false, "{t}");
    assert!(t["message"].as_str().unwrap().contains("--username"), "{t}");
    let (code, h) = c.post(
        "/v1/handles",
        json!({ "secret": "twilio", "label": "sdk", "preset_policy": "twilio:full" }),
    );
    assert_eq!(code, 201, "{h}");
    let handle = h["handle"].as_str().unwrap().to_string();
    // The way an SDK sends it: its own account as the username.
    let sdk = basic(&format!("{TWILIO_SID}:{handle}"));
    let call = |path: &str| {
        C::call(
            c.agent
                .get(&format!("{}/p/twilio{path}", c.base))
                .set("Authorization", &sdk)
                .call(),
        )
    };
    let (code, b) = call("/2010-04-01/Accounts.json");
    assert_eq!(
        (code, b["error"].as_str()),
        (400, Some("secret_shape")),
        "{b}"
    );

    // The other half arrives: it tests, and works through the broker.
    let (code, m) = c.patch("/v1/secrets/twilio", json!({ "username": TWILIO_SID }));
    assert_eq!(code, 200, "{m}");
    assert_eq!(test("twilio")["ok"], true);
    let (code, b) = call("/2010-04-01/Accounts.json");
    assert_eq!(code, 200, "{b}");

    // The pair stays hidden if a provider echoes it; the account does not need to.
    let (code, b) = call("/2010-04-01/echo.json");
    assert_eq!(code, 200, "{b}");
    assert!(b["auth"].as_str().unwrap().contains("REDACTED"), "{b}");
    assert_eq!(b["account_sid"], TWILIO_SID);

    // A new password keeps the username; both at once replace both.
    let (code, _) = c.patch(
        "/v1/secrets/twilio",
        json!({ "value": "wrong-token-abcdefghijkl" }),
    );
    assert_eq!(code, 200);
    assert_eq!(test("twilio")["ok"], false);
    let (code, _) = c.patch("/v1/secrets/twilio", json!({ "value": TWILIO_TOKEN }));
    assert_eq!(code, 200);
    assert_eq!(test("twilio")["ok"], true, "the username survived");
    let new_pair = format!("{TWILIO_SID}\n{TWILIO_TOKEN}");
    assert_eq!(
        c.patch(
            "/v1/secrets/twilio",
            json!({ "value": "wrong-abcdefghijklmnopq" })
        )
        .0,
        200
    );
    assert_eq!(
        c.patch("/v1/secrets/twilio", json!({ "value": new_pair }))
            .0,
        200
    );
    assert_eq!(test("twilio")["ok"], true, "two lines replace both");
    assert_eq!(
        c.patch(
            "/v1/secrets/twilio",
            json!({ "value": "wrong-abcdefghijklmnopq" })
        )
        .0,
        200
    );
    let same_account = format!("{TWILIO_SID}:{TWILIO_TOKEN}");
    assert_eq!(
        c.patch("/v1/secrets/twilio", json!({ "value": same_account }))
            .0,
        200
    );
    assert_eq!(
        test("twilio")["ok"],
        true,
        "its own username can come along"
    );

    // A colon in a new password does not overwrite the username: what precedes
    // it would land in a field the scrubber leaves alone.
    let colon = "half-of-the-secret:other-half-abcdefgh";
    assert_eq!(
        c.patch("/v1/secrets/twilio", json!({ "value": colon })).0,
        200
    );
    let (code, shown) = c.post("/v1/secrets/twilio/reveal", json!({ "confirm": true }));
    assert_eq!(code, 200, "{shown}");
    assert_eq!(shown["value"], colon);
    assert_eq!(shown["fields"]["username"], TWILIO_SID);
    assert_eq!(
        c.patch("/v1/secrets/twilio", json!({ "value": TWILIO_TOKEN }))
            .0,
        200
    );

    // A refused change changes nothing, however much of it was fine.
    let (code, _) = c.patch(
        "/v1/secrets/twilio",
        json!({ "value": "not-stored-abcdefghijkl", "username": "" }),
    );
    assert_eq!(code, 400);
    assert_eq!(test("twilio")["ok"], true, "the value stayed");
    let (code, _) = c.patch("/v1/secrets/twilio", json!({ "username": "with:colon" }));
    assert_eq!(code, 400);

    // Pasted whole, on one line or two, whatever the key is called.
    for (name, value) in [
        ("sms", format!("{TWILIO_SID}:{TWILIO_TOKEN}")),
        ("sms-2", format!("{TWILIO_SID}\n{TWILIO_TOKEN}\n")),
    ] {
        let (code, made) = c.post("/v1/secrets", json!({ "name": name, "value": value }));
        assert_eq!(code, 201, "{made}");
        assert_eq!(made["provider"], "twilio", "{made}");
        assert_eq!(test(name)["ok"], true, "{name}");
    }

    // A provider that has the username for everybody needs only the key.
    let (code, made) = c.post(
        "/v1/secrets",
        json!({ "name": "mailgun", "value": MAILGUN_KEY }),
    );
    assert_eq!(code, 201, "{made}");
    assert_eq!(test("mailgun")["ok"], true);
    let (code, b) = c.patch("/v1/secrets/mailgun", json!({ "username": "someone" }));
    assert_eq!(
        (code, b["error"].as_str()),
        (400, Some("username_not_applicable")),
        "{b}"
    );

    // The account can be part of the test's path.
    let (code, made) = c.post(
        "/v1/secrets",
        json!({ "name": "plivo", "value": format!("{PLIVO_ID}:{PLIVO_TOKEN}") }),
    );
    assert_eq!(code, 201, "{made}");
    assert_eq!(test("plivo")["ok"], true);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_goes_only_where_it_may() {
    let (_dir, r, c) = setup().await;
    let via = |path: &str, handle: &str, upstream: Option<&str>| {
        let mut req = c
            .agent
            .get(&format!("{}{path}", c.base))
            .set("Authorization", &format!("Bearer {handle}"));
        if let Some(u) = upstream {
            req = req.set("X-Usk-Upstream", u);
        }
        C::call(req.call())
    };
    // A host that only reads as allowed: the URL parser stops at the backslash.
    assert_eq!(
        c.post(
            "/v1/secrets",
            json!({ "name": "jira", "value": "me@example.com:atlassian-token-abcdefgh" })
        )
        .0,
        201
    );
    let (_, h) = c.post("/v1/handles", json!({ "secret": "jira", "label": "a" }));
    let jira = h["handle"].as_str().unwrap().to_string();
    for host in [
        "127.0.0.1\\.atlassian.net",
        "[127.0.0.1:9\\.atlassian.net]:443",
    ] {
        let (code, b) = via("/p/jira/rest/api/3/myself", &jira, Some(host));
        assert_eq!(
            (code, b["error"].as_str()),
            (400, Some("invalid_upstream")),
            "{host}: {b}"
        );
    }

    // Another provider's route would build a Basic header nothing guards.
    assert_eq!(
        c.post("/v1/secrets", json!({ "name": "xai", "value": GOOD_XAI }))
            .0,
        201
    );
    let (_, h) = c.post("/v1/handles", json!({ "secret": "xai", "label": "b" }));
    let xai = h["handle"].as_str().unwrap().to_string();
    let (code, b) = via("/p/mailgun/@api.x.ai/v1/models", &xai, None);
    assert_eq!(
        (code, b["error"].as_str()),
        (400, Some("route_mismatch")),
        "{b}"
    );
    assert_eq!(via("/p/xai/v1/models", &xai, None).0, 200);

    // A service account's scopes are no secret: a request may mention them.
    let file = json!({
        "type": "service_account",
        "private_key": include_str!("fixtures/service-account-test-key.txt"),
        "client_email": "bot@p.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.googleapis.com/token"
    });
    let scope = "https://www.googleapis.com/auth/webmasters.readonly";
    assert_eq!(
        c.post(
            "/v1/secrets",
            json!({ "name": "gsa", "value": file.to_string(), "fields": { "scope": scope } })
        )
        .0,
        201
    );
    let (code, b) = C::call(
        c.agent
            .post(&format!("{}/p/xai/v1/models", c.base))
            .set("Authorization", &format!("Bearer {xai}"))
            .set("X-Usk-Note", scope)
            .send_string(scope),
    );
    assert_ne!(b["error"].as_str(), Some("egress_blocked"), "{code} {b}");

    // A service account's value is replaced as a whole file, never in place.
    let (code, b) = c.patch(
        "/v1/secrets/gsa",
        json!({ "value": "not-a-key-file-abcdefgh" }),
    );
    assert_eq!(
        (code, b["error"].as_str()),
        (400, Some("cannot_replace")),
        "{b}"
    );
    r.shutdown().await;
}

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
