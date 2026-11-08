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
const SUPABASE: &str = "sb_secret_abcdefghijklmnopqrstuvwxyz";
const OLD_TOKEN: &str = "twilio-old-token-abcdefghijklmnop";
const CF_USER: &str = "cfut_userTokenAbcdefghijklmnopqrstuvwxyz";
const CF_ACCOUNT: &str = "cfat_accountTokenAbcdefghijklmnopqrstuvwxyz";

/// Calls that reached a Supabase host.
static SUPABASE_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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
        p if p.starts_with("/rest/v1/") => {
            SUPABASE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            auth == format!("Bearer {SUPABASE}")
        }
        // A reply already on its way when the key was replaced.
        "/2010-04-01/old.json" => {
            return (
                [("content-type", "application/json")],
                json!({ "said": OLD_TOKEN, "pair": basic(&format!("{TWILIO_SID}:{OLD_TOKEN}")) })
                    .to_string(),
            )
                .into_response()
        }
        "/2010-04-01/slow.json" => {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            true
        }
        "/2010-04-01/hangs.json" => {
            tokio::time::sleep(Duration::from_secs(120)).await;
            true
        }
        "/v1/models" => auth == format!("Bearer {GOOD_XAI}"),
        // As Cloudflare does: this address takes user tokens only...
        "/client/v4/user/tokens/verify" => auth == format!("Bearer {CF_USER}"),
        // ...and this one both kinds.
        "/client/v4/accounts" => {
            auth == format!("Bearer {CF_USER}") || auth == format!("Bearer {CF_ACCOUNT}")
        }
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
    fn delete(&self, path: &str) -> (u16, Value) {
        Self::call(
            self.agent
                .delete(&format!("{}{}", self.base, path))
                .set("Authorization", &format!("Bearer {}", self.token))
                .call(),
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
            ("api.cloudflare.com".into(), format!("http://{mock}")),
            ("api.deepgram.com".into(), format!("http://{mock}")),
            ("api.twilio.com".into(), format!("http://{mock}")),
            ("api.mailgun.net".into(), format!("http://{mock}")),
            ("api.plivo.com".into(), format!("http://{mock}")),
            ("mine.supabase.co".into(), format!("http://{mock}")),
            ("evil.supabase.co".into(), format!("http://{mock}")),
            // Nothing listens here.
            (
                "generativelanguage.googleapis.com".into(),
                "http://127.0.0.1:1".into(),
            ),
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
async fn a_key_goes_only_to_the_owners_own_host() {
    use std::sync::atomic::Ordering::SeqCst;
    let (_dir, r, c) = setup().await;
    let calls = || SUPABASE_CALLS.load(SeqCst);
    let via = |handle: &str, upstream: Option<&str>| {
        let mut req = c
            .agent
            .get(&format!("{}/p/supabase/rest/v1/items", c.base))
            .set("Authorization", &format!("Bearer {handle}"));
        if let Some(u) = upstream {
            req = req.set("X-Usk-Upstream", u);
        }
        C::call(req.call())
    };

    // Anyone can have a host under *.supabase.co: until the owner says which is
    // theirs, the key goes nowhere, with or without a host named by the caller.
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "supabase", "value": SUPABASE }),
    );
    assert_eq!(code, 201, "{b}");
    assert_eq!(b["needs_host"], "<project-ref>.supabase.co", "{b}");
    let (_, h) = c.post("/v1/handles", json!({ "secret": "supabase", "label": "a" }));
    let handle = h["handle"].as_str().unwrap().to_string();
    for upstream in [None, Some("evil.supabase.co"), Some("mine.supabase.co")] {
        let (code, b) = via(&handle, upstream);
        assert_eq!(
            (code, b["error"].as_str()),
            (403, Some("host_not_pinned")),
            "{upstream:?}: {b}"
        );
        assert!(b["message"]
            .as_str()
            .unwrap()
            .contains("usk secret set supabase --upstream"));
    }
    assert_eq!(calls(), 0, "nothing was sent");
    let (_, t) = c.post("/v1/secrets/supabase/test", json!({}));
    assert_eq!(t["tested"], false, "{t}");
    assert_eq!(calls(), 0, "nothing was sent by the test either");

    // Named: calls go there without saying so, and nowhere else.
    let (code, b) = c.patch(
        "/v1/secrets/supabase",
        json!({ "upstreams": ["https://Mine.supabase.co/"] }),
    );
    assert_eq!(code, 200, "{b}");
    assert_eq!(b["upstreams"], json!(["mine.supabase.co"]));
    let (code, b) = via(&handle, None);
    assert_eq!(code, 200, "{b}");
    assert_eq!(calls(), 1);
    assert_eq!(via(&handle, Some("mine.supabase.co")).0, 200);
    assert_eq!(calls(), 2);
    let (code, b) = via(&handle, Some("evil.supabase.co"));
    assert_eq!(
        (code, b["error"].as_str()),
        (403, Some("host_not_allowed")),
        "{b}"
    );
    assert_eq!(calls(), 2, "the stranger's host got nothing");
    let (_, t) = c.post("/v1/secrets/supabase/test", json!({}));
    assert_eq!(
        (t["tested"].as_bool(), t["ok"].as_bool()),
        (Some(true), Some(true)),
        "{t}"
    );

    // A policy written for the provider's wildcard allows the owner's host only.
    let (code, h) = c.post(
        "/v1/handles",
        json!({ "secret": "supabase", "label": "wide", "policy": {
            "allow": ["GET /rest/v1/**"], "upstreams": ["*.supabase.co"]
        } }),
    );
    assert_eq!(code, 201, "{h}");
    let wide = h["handle"].as_str().unwrap().to_string();
    assert_eq!(via(&wide, None).0, 200);
    let (code, b) = via(&wide, Some("evil.supabase.co"));
    assert_eq!(
        (code, b["error"].as_str()),
        (403, Some("host_not_allowed")),
        "{b}"
    );

    // Going back to the wildcard is the same as never naming one.
    let (code, _) = c.patch(
        "/v1/secrets/supabase",
        json!({ "upstreams": ["*.supabase.co"] }),
    );
    assert_eq!(code, 200);
    assert_eq!(via(&handle, None).1["error"], "host_not_pinned");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pair_pasted_the_wrong_way_round() {
    let (_dir, r, c) = setup().await;
    let reversed = format!("{TWILIO_TOKEN}:{TWILIO_SID}");
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "twilio", "value": reversed }),
    );
    assert_eq!(code, 201, "{b}");
    let (_, t) = c.post("/v1/secrets/twilio/test", json!({}));
    assert_eq!(t["ok"], true, "put right, so it works: {t}");
    let (_, s) = c.post("/v1/secrets/twilio/reveal", json!({ "confirm": true }));
    assert_eq!(
        (s["value"].as_str(), s["fields"]["username"].as_str()),
        (Some(TWILIO_TOKEN), Some(TWILIO_SID))
    );

    // Two lines, replacing both.
    let (code, b) = c.patch(
        "/v1/secrets/twilio",
        json!({ "value": format!("{TWILIO_TOKEN}\n{TWILIO_SID}") }),
    );
    assert_eq!(code, 200, "{b}");
    let (_, s) = c.post("/v1/secrets/twilio/reveal", json!({ "confirm": true }));
    assert_eq!(
        (s["value"].as_str(), s["fields"]["username"].as_str()),
        (Some(TWILIO_TOKEN), Some(TWILIO_SID))
    );

    // Neither part looks like an account: kept as given, and the username is
    // guarded, since it may be the secret half.
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "odd", "provider": "twilio", "value": "unknown-shape-part-one:unknown-shape-part-two" }),
    );
    assert_eq!(code, 201, "{b}");
    let (_, h) = c.post(
        "/v1/handles",
        json!({ "secret": "odd", "label": "o", "policy": { "allow": ["* /**"] } }),
    );
    let (code, b) = C::call(
        c.agent
            .post(&format!("{}/p/twilio/2010-04-01/Accounts.json", c.base))
            .set(
                "Authorization",
                &format!("Bearer {}", h["handle"].as_str().unwrap()),
            )
            .send_string("note=unknown-shape-part-one"),
    );
    assert_eq!(
        (code, b["error"].as_str()),
        (403, Some("egress_blocked")),
        "{b}"
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn replacing_half_of_an_aws_key_is_refused() {
    let (_dir, r, c) = setup().await;
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "aws", "value": "AKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" }),
    );
    assert_eq!(code, 201, "{b}");
    let (code, b) = c.patch(
        "/v1/secrets/aws",
        json!({ "value": "a-new-secret-access-key-abcdefgh" }),
    );
    assert_eq!(
        (code, b["error"].as_str()),
        (400, Some("cannot_replace")),
        "{b}"
    );
    let (_, s) = c.post("/v1/secrets/aws/reveal", json!({ "confirm": true }));
    assert_eq!(s["value"], "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    assert_eq!(s["fields"]["access_key_id"], "AKIAIOSFODNN7EXAMPLE");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replaced_key_stays_guarded() {
    let (_dir, r, c) = setup().await;
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "twilio", "value": format!("{TWILIO_SID}:{OLD_TOKEN}") }),
    );
    assert_eq!(code, 201, "{b}");
    let (_, h) = c.post("/v1/handles", json!({ "secret": "twilio", "label": "a" }));
    let handle = format!("Bearer {}", h["handle"].as_str().unwrap());
    assert_eq!(
        c.patch("/v1/secrets/twilio", json!({ "value": TWILIO_TOKEN }))
            .0,
        200
    );
    let body = c
        .agent
        .get(&format!("{}/p/twilio/2010-04-01/old.json", c.base))
        .set("Authorization", &handle)
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(!body.contains(OLD_TOKEN), "{body}");
    assert!(
        !body.contains(&basic(&format!("{TWILIO_SID}:{OLD_TOKEN}"))[6..]),
        "{body}"
    );
    // And after it is removed altogether.
    assert_eq!(c.delete("/v1/secrets/twilio").0, 200);
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "again", "provider": "twilio", "value": format!("{TWILIO_SID}:other-token-abcdefghijklmnop") }),
    );
    assert_eq!(code, 201, "{b}");
    let (_, h) = c.post("/v1/handles", json!({ "secret": "again", "label": "b" }));
    let body = c
        .agent
        .get(&format!("{}/p/twilio/2010-04-01/old.json", c.base))
        .set(
            "Authorization",
            &format!("Bearer {}", h["handle"].as_str().unwrap()),
        )
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    assert!(!body.contains(TWILIO_TOKEN), "{body}");
    assert!(!body.contains(OLD_TOKEN), "{body}");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_cut_off_by_the_lock_is_in_the_log() {
    let (_dir, r, c) = setup().await;
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "twilio", "value": format!("{TWILIO_SID}:{TWILIO_TOKEN}") }),
    );
    assert_eq!(code, 201, "{b}");
    let (_, h) = c.post("/v1/handles", json!({ "secret": "twilio", "label": "a" }));
    let handle = format!("Bearer {}", h["handle"].as_str().unwrap());
    let (code, b) = std::thread::scope(|scope| {
        let out = scope.spawn(|| {
            C::call(
                c.agent
                    .get(&format!("{}/p/twilio/2010-04-01/slow.json", c.base))
                    .set("Authorization", &handle)
                    .call(),
            )
        });
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(c.post("/v1/lock", json!({})).0, 200);
        out.join().unwrap()
    });
    assert_eq!(
        (code, b["error"].as_str()),
        (401, Some("vault_locked")),
        "{b}"
    );
    assert_eq!(c.post("/v1/unlock", json!({ "password": PW })).0, 200);
    let (_, events) = c.get("/v1/audit?since=1&kind=use_unfinished");
    let events = events.as_array().unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["body"]["secret"], "twilio");
    assert_eq!(events[0]["body"]["why"], "locked");
    // Written once, and an ordinary request leaves nothing behind.
    assert_eq!(c.post("/v1/lock", json!({})).0, 200);
    assert_eq!(c.post("/v1/unlock", json!({ "password": PW })).0, 200);
    assert_eq!(
        c.get("/v1/audit?since=1&kind=use_unfinished")
            .1
            .as_array()
            .unwrap()
            .len(),
        1
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_who_leaves_is_in_the_log() {
    let (_dir, r, c) = setup().await;
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "twilio", "value": format!("{TWILIO_SID}:{TWILIO_TOKEN}") }),
    );
    assert_eq!(code, 201, "{b}");
    let (_, h) = c.post("/v1/handles", json!({ "secret": "twilio", "label": "a" }));
    let handle = format!("Bearer {}", h["handle"].as_str().unwrap());
    let impatient = ureq::AgentBuilder::new()
        .max_idle_connections(0)
        .timeout_read(Duration::from_millis(300))
        .build();
    assert!(impatient
        .get(&format!("{}/p/twilio/2010-04-01/slow.json", c.base))
        .set("Authorization", &handle)
        .call()
        .is_err());
    // The call took effect or not; either way the log tells of it, once.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let (_, unfinished) = c.get("/v1/audit?since=1&kind=use_unfinished");
    let (_, finished) = c.get("/v1/audit?since=1&kind=use");
    let total = unfinished.as_array().unwrap().len() + finished.as_array().unwrap().len();
    assert_eq!(total, 1, "{unfinished} {finished}");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_key_test_does_not_say_the_key() {
    let (_dir, r, c) = setup().await;
    const KEY: &str = "AIzaSyTESTabcdefghijklmnopqrstuvwxyz012345";
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "gemini", "provider": "google-ai", "value": KEY }),
    );
    assert_eq!(code, 201, "{b}");
    let (_, t) = c.post("/v1/secrets/gemini/test", json!({}));
    assert!(
        t["message"].as_str().unwrap().contains("could not reach"),
        "{t}"
    );
    assert!(!t.to_string().contains(KEY), "{t}");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn other_fields_of_a_key_need_the_owner() {
    let (_dir, r, c) = setup().await;
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "drive", "value": json!({
            "type": "authorized_user", "client_id": "cid-123", "client_secret": "csecret-abcdefghijkl",
            "refresh_token": "rt-1-abcdefghijklmnop", "token_uri": "https://oauth2.googleapis.com/token"
        }).to_string() }),
    );
    assert_eq!(code, 201, "{b}");
    let owner = c.owner.lock().unwrap().take();
    let (code, b) = c.patch(
        "/v1/secrets/drive",
        json!({ "value": "rt-2-abcdefghijklmnop", "fields": { "token_url": "https://storage.googleapis.com/mine" } }),
    );
    assert_eq!(
        (code, b["error"].as_str()),
        (403, Some("owner_required")),
        "{b}"
    );
    *c.owner.lock().unwrap() = owner;
    let (_, s) = c.post("/v1/secrets/drive/reveal", json!({ "confirm": true }));
    assert_eq!(
        s["fields"]["token_url"],
        "https://oauth2.googleapis.com/token"
    );
    assert_eq!(s["value"], "rt-1-abcdefghijklmnop");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_change_stores_nothing() {
    let (_dir, r, c) = setup().await;
    for name in ["one", "two"] {
        let (code, b) = c.post(
            "/v1/secrets",
            json!({ "name": name, "provider": "twilio", "value": format!("{TWILIO_SID}:{TWILIO_TOKEN}") }),
        );
        assert_eq!(code, 201, "{b}");
    }
    for bad in [
        json!({ "value": "changed-token-abcdefghijklmnop", "name": "two" }),
        json!({ "value": "changed-token-abcdefghijklmnop", "upstreams": ["not a host"] }),
        json!({ "username": "ACchanged", "provider": "no-such-provider" }),
    ] {
        let (code, b) = c.patch("/v1/secrets/one", bad.clone());
        assert!(code == 400 || code == 409, "{bad}: {code} {b}");
        let (_, s) = c.post("/v1/secrets/one/reveal", json!({ "confirm": true }));
        assert_eq!(s["value"], TWILIO_TOKEN, "{bad}");
        assert_eq!(s["fields"]["username"], TWILIO_SID, "{bad}");
    }
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn putting_a_pair_right_afterwards() {
    let (_dir, r, c) = setup().await;
    // Typed into the two boxes the wrong way round: put right all the same.
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "boxes", "provider": "twilio", "value": TWILIO_SID, "fields": { "username": TWILIO_TOKEN } }),
    );
    assert_eq!(code, 201, "{b}");
    let (_, s) = c.post("/v1/secrets/boxes/reveal", json!({ "confirm": true }));
    assert_eq!(
        (s["value"].as_str(), s["fields"]["username"].as_str()),
        (Some(TWILIO_TOKEN), Some(TWILIO_SID))
    );
    // Stored with a username that is no account, then replaced with both parts.
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "odd", "provider": "twilio", "value": "unknown-shape-part-two", "fields": { "username": "unknown-shape-part-one" } }),
    );
    assert_eq!(code, 201, "{b}");
    let (code, b) = c.patch(
        "/v1/secrets/odd",
        json!({ "value": format!("{TWILIO_SID}:{TWILIO_TOKEN}") }),
    );
    assert_eq!(code, 200, "{b}");
    let (_, s) = c.post("/v1/secrets/odd/reveal", json!({ "confirm": true }));
    assert_eq!(
        (s["value"].as_str(), s["fields"]["username"].as_str()),
        (Some(TWILIO_TOKEN), Some(TWILIO_SID))
    );
    // One part stored, the account by mistake; putting it right must not block
    // every later call that names the account.
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "half", "provider": "twilio", "value": "ACabcdefabcdefabcdefabcdefabcdefab" }),
    );
    assert_eq!(code, 201, "{b}");
    let (code, b) = c.patch(
        "/v1/secrets/half",
        json!({ "value": format!("ACabcdefabcdefabcdefabcdefabcdefab\n{TWILIO_TOKEN}") }),
    );
    assert_eq!(code, 200, "{b}");
    let (_, h) = c.post(
        "/v1/handles",
        json!({ "secret": "half", "label": "h", "policy": { "allow": ["* /**"] } }),
    );
    let (code, b) = C::call(
        c.agent
            .get(&format!(
                "{}/p/twilio/2010-04-01/Accounts/ACabcdefabcdefabcdefabcdefabcdefab.json",
                c.base
            ))
            .set(
                "Authorization",
                &format!("Bearer {}", h["handle"].as_str().unwrap()),
            )
            .call(),
    );
    assert_ne!(b["error"].as_str(), Some("egress_blocked"), "{code} {b}");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_request_does_not_hold_up_a_stop() {
    let (_dir, r, c) = setup().await;
    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "twilio", "value": format!("{TWILIO_SID}:{TWILIO_TOKEN}") }),
    );
    assert_eq!(code, 201, "{b}");
    let (_, h) = c.post("/v1/handles", json!({ "secret": "twilio", "label": "a" }));
    let handle = format!("Bearer {}", h["handle"].as_str().unwrap());
    let url = format!("{}/p/twilio/2010-04-01/hangs.json", c.base);
    let agent = c.agent.clone();
    std::thread::spawn(move || {
        let _ = agent.get(&url).set("Authorization", &handle).call();
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let t0 = std::time::Instant::now();
    r.shutdown().await;
    assert!(t0.elapsed() < Duration::from_secs(6), "{:?}", t0.elapsed());
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

#[tokio::test(flavor = "multi_thread")]
async fn a_token_of_either_kind_passes_the_key_test() {
    let (_d, _r, c) = setup().await;
    for (name, value, works) in [
        ("cf-user", CF_USER, true),
        ("cf-account", CF_ACCOUNT, true),
        ("cf-bad", "cfat_badTokenAbcdefghijklmnopqrstuvwxyz", false),
    ] {
        let (code, _) = c.post(
            "/v1/secrets",
            json!({ "name": name, "value": value, "provider": "cloudflare" }),
        );
        assert!(code < 300, "{name}: {code}");
        let (_, t) = c.post(&format!("/v1/secrets/{name}/test"), json!({}));
        assert_eq!(t["tested"], true, "{name}: {t}");
        assert_eq!(t["ok"], works, "{name}: {t}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn naming_the_provider_keeps_the_owners_own_host() {
    let (_d, _r, c) = setup().await;
    // Saved without a provider, as an older service did, with the host already named.
    let (code, _) = c.post(
        "/v1/secrets",
        json!({ "name": "project", "value": "a-key-of-no-known-shape-0123456789", "upstreams": ["mine.supabase.co"] }),
    );
    assert!(code < 300, "{code}");
    let (code, s) = c.patch("/v1/secrets/project", json!({ "provider": "supabase" }));
    assert_eq!(code, 200, "{s}");
    let (_, s) = c.get("/v1/secrets/project");
    assert_eq!(s["provider"], "supabase");
    assert_eq!(s["upstreams"], json!(["mine.supabase.co"]));
    // It can be used: the test goes out instead of asking for a host.
    let (_, t) = c.post("/v1/secrets/project/test", json!({}));
    assert_eq!(t["tested"], true, "{t}");

    // A host the provider does not cover makes way for the provider's own.
    let (code, _) = c.post(
        "/v1/secrets",
        json!({ "name": "elsewhere", "value": "another-key-of-no-known-shape-0123", "upstreams": ["api.example.com"] }),
    );
    assert!(code < 300, "{code}");
    let (code, s) = c.patch("/v1/secrets/elsewhere", json!({ "provider": "xai" }));
    assert_eq!(code, 200, "{s}");
    let (_, s) = c.get("/v1/secrets/elsewhere");
    assert_eq!(s["upstreams"], json!(["api.x.ai"]));
}
