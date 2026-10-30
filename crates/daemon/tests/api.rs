//! Daemon integration tests: ingress guard (INV-6), token auth (INV-3), API flow.

use serde_json::{json, Value};
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, Running, ServeOptions};

const PW: &str = "test-password-123";

fn make_vault(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("vault.db");
    let (_v, _kit) = Vault::create(
        SqliteStorage::open(&path).unwrap(),
        SystemClock,
        &SecretBytes::from(PW),
        Argon2Profile::MINIMUM,
    )
    .unwrap();
    path
}

async fn start(dir: &std::path::Path, write_files: bool) -> Running {
    let vault_path = make_vault(dir);
    serve(ServeOptions {
        vault_path,
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: write_files,
        upstream_overrides: vec![],
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap()
}

struct C {
    base: String,
    token: String,
    /// The owner token from the last unlock; sent as the CLI and app do.
    owner: std::sync::Mutex<Option<String>>,
    agent: ureq::Agent,
}

impl C {
    fn new(r: &Running) -> Self {
        Self {
            base: format!("http://{}", r.addr),
            token: r.token().to_string(),
            owner: std::sync::Mutex::new(None),
            agent: ureq::AgentBuilder::new().max_idle_connections(0).build(),
        }
    }
    fn req(&self, method: &str, path: &str) -> ureq::Request {
        let mut r = self
            .agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token));
        if let Some(o) = self.owner.lock().unwrap().as_ref() {
            r = r.set("X-Usk-Owner", o);
        }
        r
    }
    fn status_of(r: Result<ureq::Response, ureq::Error>) -> (u16, Value) {
        match r {
            Ok(resp) => {
                let code = resp.status();
                (code, resp.into_json().unwrap_or(Value::Null))
            }
            Err(ureq::Error::Status(code, resp)) => (code, resp.into_json().unwrap_or(Value::Null)),
            Err(e) => panic!("transport error: {e}"),
        }
    }
    fn get(&self, path: &str) -> (u16, Value) {
        Self::status_of(self.req("GET", path).call())
    }
    fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let (code, v) = Self::status_of(self.req("POST", path).send_json(body));
        if code == 200 && (path == "/v1/unlock" || path == "/v1/confirm") {
            *self.owner.lock().unwrap() = v["owner_token"].as_str().map(str::to_string);
        }
        (code, v)
    }
    /// Act as a program that holds only `daemon.token`.
    fn forget_owner(&self) {
        *self.owner.lock().unwrap() = None;
    }
    fn patch(&self, path: &str, body: Value) -> (u16, Value) {
        Self::status_of(self.req("PATCH", path).send_json(body))
    }
    fn delete(&self, path: &str) -> (u16, Value) {
        Self::status_of(self.req("DELETE", path).call())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_origin_headers_are_rejected_on_every_route() {
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), false).await;
    let c = C::new(&r);
    let routes = ["/healthz", "/v1/status", "/v1/secrets", "/nope"];
    let markers: &[(&str, &str)] = &[
        ("Origin", "https://evil.example"),
        ("Referer", "https://evil.example/page"),
        ("Sec-Fetch-Site", "cross-site"),
        ("Sec-Fetch-Dest", "empty"),
        ("Sec-CH-UA", "\"Chromium\";v=\"130\""),
    ];
    for route in routes {
        for (h, v) in markers {
            let (code, body) = C::status_of(c.req("GET", route).set(h, v).call());
            assert_eq!(code, 403, "{route} with {h}");
            assert_eq!(body["error"], "browser_origin_rejected", "{route} with {h}");
        }
        // Node's fetch (undici) sends `sec-fetch-mode: cors` on its own; that is an
        // SDK, not a browser, and must pass. Browsers always add Sec-Fetch-Site too.
        let (code, _) = C::status_of(c.req("GET", route).set("Sec-Fetch-Mode", "cors").call());
        assert_ne!(
            code, 403,
            "{route}: sec-fetch-mode alone must not be treated as a browser"
        );
        // Even a valid token does not help a browser.
        let (code, _) = C::status_of(c.req("POST", route).set("Origin", "null").call());
        assert_eq!(code, 403);
    }
    // Sanity: without markers the same routes work / 404 normally.
    assert_eq!(c.get("/healthz").0, 200);
    assert_eq!(c.get("/nope").0, 404);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn host_header_must_match() {
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), false).await;
    let c = C::new(&r);
    // ureq sets Host from the URL; use a raw socket to send a spoofed Host (DNS rebinding).
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(r.addr).unwrap();
    write!(
        s,
        "GET /healthz HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert!(out.contains("host_rejected"), "{out}");
    // localhost:<port> is accepted.
    let mut s = std::net::TcpStream::connect(r.addr).unwrap();
    write!(
        s,
        "GET /healthz HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
        r.addr.port()
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert_eq!(c.get("/healthz").0, 200);
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn token_required_and_no_cors_headers() {
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), false).await;
    let base = format!("http://{}", r.addr);
    let (code, body) = C::status_of(ureq::get(&format!("{base}/v1/status")).call());
    assert_eq!(code, 401);
    assert_eq!(body["error"], "unauthorized");
    let (code, _) = C::status_of(
        ureq::get(&format!("{base}/v1/status"))
            .set(
                "Authorization",
                "Bearer usk_s_00000000000000000000000000000000",
            )
            .call(),
    );
    assert_eq!(code, 401);
    let resp = ureq::get(&format!("{base}/healthz")).call().unwrap();
    assert!(resp.header("access-control-allow-origin").is_none());
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn full_secret_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), true).await;
    let c = C::new(&r);

    // Runtime files exist while running.
    assert!(dir.path().join("daemon.token").exists());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("daemon.token")).unwrap(),
        r.token()
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("daemon.addr")).unwrap(),
        r.addr.to_string()
    );

    let (code, st) = c.get("/v1/status");
    assert_eq!(code, 200);
    assert_eq!(st["locked"], true);

    let (code, body) = c.get("/v1/secrets");
    assert_eq!(code, 401);
    assert_eq!(body["error"], "vault_locked");

    let (code, body) = c.post("/v1/unlock", json!({ "password": "wrong" }));
    assert_eq!(code, 401);
    assert_eq!(body["error"], "wrong_password");
    let (code, _) = c.post("/v1/unlock", json!({ "password": PW }));
    assert_eq!(code, 200);
    assert_eq!(c.get("/v1/status").1["locked"], false);

    let value = "sk_live_51Habcdefghijklmnop";
    let (code, created) = c.post(
        "/v1/secrets",
        json!({ "name": "stripe", "value": value, "tags": ["prod"] }),
    );
    assert_eq!(code, 201, "{created}");
    assert_eq!(created["provider"], "stripe");
    assert_eq!(created["upstreams"][0], "api.stripe.com");
    assert_eq!(created["detected"]["note"], "live key");
    let id = created["id"].as_str().unwrap().to_string();
    assert!(!created.to_string().contains(value));

    let (code, body) = c.post("/v1/secrets", json!({ "name": "stripe", "value": "x" }));
    assert_eq!(code, 409);
    assert_eq!(body["error"], "name_exists");
    let (code, _) = c.post("/v1/secrets", json!({ "name": "e", "value": "" }));
    assert_eq!(code, 400);

    let (code, list) = c.get("/v1/secrets");
    assert_eq!(code, 200);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(!list.to_string().contains(value));

    // By id and by name.
    assert_eq!(c.get(&format!("/v1/secrets/{id}")).1["name"], "stripe");
    assert_eq!(c.get("/v1/secrets/stripe").1["secret_id"], id);
    assert_eq!(c.get("/v1/secrets/missing").0, 404);

    let (code, body) = c.post("/v1/secrets/stripe/reveal", json!({ "confirm": false }));
    assert_eq!(code, 400, "{body}");
    let (code, body) = c.post(
        "/v1/secrets/stripe/reveal",
        json!({ "confirm": true, "reason": "test" }),
    );
    assert_eq!(code, 200);
    assert_eq!(body["value"], value);

    let (code, m) = c.patch(
        "/v1/secrets/stripe",
        json!({ "name": "stripe-live", "allow_injection": true, "value": "sk_live_new" }),
    );
    assert_eq!(code, 200, "{m}");
    assert_eq!(m["name"], "stripe-live");
    assert_eq!(m["allow_injection"], true);
    assert_eq!(m["value_version"], 2);
    assert_eq!(
        c.post("/v1/secrets/stripe-live/reveal", json!({ "confirm": true }))
            .1["value"],
        "sk_live_new"
    );

    let (code, _) = c.delete("/v1/secrets/stripe-live");
    assert_eq!(code, 200);
    assert_eq!(c.get("/v1/secrets").1.as_array().unwrap().len(), 0);

    let (code, _) = c.post("/v1/lock", json!({}));
    assert_eq!(code, 200);
    assert_eq!(c.get("/v1/status").1["locked"], true);

    // Shutdown via API removes runtime files.
    let (code, _) = c.post("/v1/shutdown", json!({}));
    assert_eq!(code, 200);
    r.wait().await;
    assert!(!dir.path().join("daemon.token").exists());
    assert!(!dir.path().join("daemon.addr").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn unlock_is_rate_limited() {
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), false).await;
    let c = C::new(&r);
    for _ in 0..5 {
        assert_eq!(c.post("/v1/unlock", json!({ "password": "nope" })).0, 401);
    }
    let (code, body) = c.post("/v1/unlock", json!({ "password": PW }));
    assert_eq!(code, 429);
    assert_eq!(body["error"], "rate_limited");
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_non_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let vault_path = make_vault(dir.path());
    let err = serve(ServeOptions {
        vault_path,
        listen: "0.0.0.0:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: false,
        upstream_overrides: vec![],
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .err()
    .unwrap();
    assert!(err.to_string().contains("non-loopback"));
}

/// Device unlock methods: enroll while unlocked, list while locked, unlock with
/// the KEK, refuse wrong KEKs and unknown ids, remove.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_unlock_methods() {
    use base64::Engine as _;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), false).await;
    let c = C::new(&r);
    let kek = [0x5au8; 32];
    let salt = [0x11u8; 32];

    // Needs an unlocked vault.
    let (code, body) = c.post(
        "/v1/unlock-methods",
        json!({ "kind": "hello", "label": "laptop", "salt": b64(&salt), "kek": b64(&kek) }),
    );
    assert_eq!(code, 401, "{body}");
    assert_eq!(c.post("/v1/unlock", json!({ "password": PW })).0, 200);
    let (code, body) = c.post(
        "/v1/unlock-methods",
        json!({ "kind": "hello", "label": "laptop", "salt": b64(&salt), "kek": b64(&kek) }),
    );
    assert_eq!(code, 200, "{body}");
    let id = body["id"].as_str().unwrap().to_string();

    // Bad inputs.
    assert_eq!(
        c.post(
            "/v1/unlock-methods",
            json!({ "kind": "Bad Kind", "label": "", "salt": b64(&salt), "kek": b64(&kek) })
        )
        .0,
        400
    );
    assert_eq!(
        c.post(
            "/v1/unlock-methods",
            json!({ "kind": "hello", "label": "", "salt": b64(&salt[..8]), "kek": b64(&kek) })
        )
        .0,
        400
    );

    // Listed, with the public salt, including while locked.
    assert_eq!(c.post("/v1/lock", json!({})).0, 200);
    let (code, list) = c.get("/v1/unlock-methods");
    assert_eq!(code, 200);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["id"], id);
    assert_eq!(list[0]["kind"], "hello");
    assert_eq!(list[0]["salt"], b64(&salt));

    // Unlock: malformed bodies (not counted as attempts), a wrong KEK, then the
    // right one. The limiter allows five credential attempts a minute, so the
    // test keeps to four in total.
    assert_eq!(c.post("/v1/unlock", json!({})).0, 400);
    assert_eq!(c.post("/v1/unlock", json!({ "wrap_id": id })).0, 400);
    assert_eq!(
        c.post(
            "/v1/unlock",
            json!({ "password": PW, "wrap_id": id, "kek": b64(&kek) })
        )
        .0,
        400
    );
    let (code, body) = c.post(
        "/v1/unlock",
        json!({ "wrap_id": id, "kek": b64(&[1u8; 32]) }),
    );
    assert_eq!(code, 401, "{body}");
    assert_eq!(body["error"], "wrong_password");
    let (code, body) = c.post("/v1/unlock", json!({ "wrap_id": id, "kek": b64(&kek) }));
    assert_eq!(code, 200, "{body}");
    assert_eq!(c.get("/v1/status").1["locked"], false);

    // Audit shows the method and the enrollment.
    let (_, audit) = c.get("/v1/audit?since=1&limit=100");
    let kinds: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"unlock_method_added"));
    assert!(audit
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "unlock" && e["body"]["method"] == "device"));

    // Remove; the KEK no longer unlocks; the password still does.
    assert_eq!(c.delete(&format!("/v1/unlock-methods/{id}")).0, 200);
    assert_eq!(c.delete(&format!("/v1/unlock-methods/{id}")).0, 404);
    assert_eq!(c.get("/v1/unlock-methods").1.as_array().unwrap().len(), 0);
    assert_eq!(c.post("/v1/lock", json!({})).0, 200);
    assert_eq!(
        c.post("/v1/unlock", json!({ "wrap_id": id, "kek": b64(&kek) }))
            .0,
        404
    );
    r.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstreams_are_normalised_and_a_provider_change_brings_its_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), false).await;
    let c = C::new(&r);
    assert_eq!(c.post("/v1/unlock", json!({ "password": PW })).0, 200);
    // What people type: a URL with a path, upper case, duplicates.
    let (code, m) = c.post("/v1/secrets", json!({
        "name": "hosted", "value": "tok_abcdefghijklmnop", "provider": "generic",
        "upstreams": ["https://Developers.Hostinger.com/api/vps/v1/", "developers.hostinger.com", "*.Example.com"]
    }));
    assert_eq!(code, 201, "{m}");
    assert_eq!(
        m["upstreams"],
        json!(["developers.hostinger.com", "*.example.com"])
    );
    // Something that is not a host at all is refused with the field named.
    let (code, m) = c.post(
        "/v1/secrets",
        json!({ "name": "bad", "value": "tok_abcdefghijklmnop", "upstreams": ["not a host"] }),
    );
    assert_eq!(code, 400, "{m}");
    assert_eq!(m["error"], "invalid_upstream");
    // secret set --upstream goes through the same normalisation.
    let (code, m) = c.patch(
        "/v1/secrets/hosted",
        json!({ "upstreams": ["HTTPS://API.EXAMPLE.COM/"] }),
    );
    assert_eq!(code, 200, "{m}");
    assert_eq!(m["upstreams"], json!(["api.example.com"]));
    // Changing the provider brings the preset's hosts unless hosts are given too.
    let (code, m) = c.patch("/v1/secrets/hosted", json!({ "provider": "hostinger" }));
    assert_eq!(code, 200, "{m}");
    assert_eq!(m["provider"], "hostinger");
    assert_eq!(m["upstreams"], json!(["developers.hostinger.com"]));
    let (code, m) = c.patch(
        "/v1/secrets/hosted",
        json!({ "provider": "cloudflare", "upstreams": ["api.cloudflare.com", "example.com"] }),
    );
    assert_eq!(code, 200, "{m}");
    assert_eq!(m["upstreams"], json!(["api.cloudflare.com", "example.com"]));
    let (code, m) = c.patch("/v1/secrets/hosted", json!({ "provider": "nope" }));
    assert_eq!(code, 400, "{m}");
    assert_eq!(m["error"], "unknown_provider");
    r.shutdown().await;
}

/// A second daemon that would register itself for a vault another daemon
/// already serves is refused and told who holds it; a daemon that keeps no
/// runtime files (tests, embedding) is unaffected; a clean stop frees the vault.
#[tokio::test(flavor = "multi_thread")]
async fn one_daemon_per_vault() {
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), true).await;
    let opts = |write_runtime_files: bool| ServeOptions {
        vault_path: dir.path().join("vault.db"),
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files,
        upstream_overrides: vec![],
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    };
    match serve(opts(true)).await {
        Err(unseenkey_daemon::ServeError::AlreadyRunning { addr, pid }) => {
            assert_eq!(addr, r.addr.to_string());
            assert_eq!(pid, std::process::id().to_string());
        }
        Err(e) => panic!("wrong refusal: {e}"),
        Ok(_) => panic!("a second daemon started on the same vault"),
    }
    serve(opts(false)).await.unwrap().shutdown().await;
    r.shutdown().await;
    serve(opts(true)).await.unwrap().shutdown().await;
}

/// A key pasted with a space or line break at either end is stored without
/// it (providers answer such a key with a bare 401); a multi-line value is
/// kept as given. Replacing the value goes through the same tidying.
#[tokio::test(flavor = "multi_thread")]
async fn pasted_values_lose_surrounding_whitespace() {
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), false).await;
    let c = C::new(&r);
    assert_eq!(c.post("/v1/unlock", json!({ "password": PW })).0, 200);
    let reveal = |name: &str| {
        c.post(
            &format!("/v1/secrets/{name}/reveal"),
            json!({ "confirm": true }),
        )
        .1["value"]
            .as_str()
            .unwrap()
            .to_string()
    };

    let (code, b) = c.post(
        "/v1/secrets",
        json!({ "name": "pasted", "value": "  sk_test_51Hpaddedvalue1234567 
" }),
    );
    assert_eq!(code, 201, "{b}");
    assert_eq!(reveal("pasted"), "sk_test_51Hpaddedvalue1234567");

    let pem = "-----BEGIN KEY-----
abc
-----END KEY-----
";
    let (code, b) = c.post("/v1/secrets", json!({ "name": "pem", "value": pem }));
    assert_eq!(code, 201, "{b}");
    assert_eq!(reveal("pem"), pem, "multi-line values are kept exactly");

    let (code, m) = c.patch(
        "/v1/secrets/pasted",
        json!({ "value": "	sk_test_51Hrotatedvalue7654321  " }),
    );
    assert_eq!(code, 200, "{m}");
    assert_eq!(m["value_version"], 2);
    assert_eq!(reveal("pasted"), "sk_test_51Hrotatedvalue7654321");
    let (code, e) = c.patch("/v1/secrets/pasted", json!({ "value": "   " }));
    assert_eq!(
        (code, e["error"].as_str()),
        (400, Some("empty_value")),
        "{e}"
    );
    r.shutdown().await;
}

/// The idle lock can be changed while the daemon runs, is kept in
/// config.toml, and rejects nonsense.
#[tokio::test(flavor = "multi_thread")]
async fn the_idle_lock_can_be_changed_and_is_saved() {
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), false).await;
    let c = C::new(&r);
    assert_eq!(c.post("/v1/unlock", json!({ "password": PW })).0, 200);
    let (code, b) = c.patch("/v1/settings", json!({ "idle_lock_minutes": 5 }));
    assert_eq!(code, 200, "{b}");
    assert_eq!(c.get("/v1/status").1["idle_lock_minutes"], 5);
    let saved = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
    assert!(saved.contains("idle_lock_minutes = 5"), "{saved}");
    // Other keys in the file survive.
    std::fs::write(
        dir.path().join("config.toml"),
        format!("{saved}lock_on_sleep = false\n"),
    )
    .unwrap();
    assert_eq!(
        c.patch("/v1/settings", json!({ "idle_lock_minutes": 0 })).0,
        200
    );
    let saved = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
    assert!(
        saved.contains("idle_lock_minutes = 0") && saved.contains("lock_on_sleep = false"),
        "{saved}"
    );
    let (code, e) = c.patch("/v1/settings", json!({ "idle_lock_minutes": 100000 }));
    assert_eq!(code, 400, "{e}");
    r.shutdown().await;
}

/// The session token in `daemon.token` is readable by every program running
/// as the user, an AI tool with a shell included. Revealing a value, enrolling
/// an unlock method, loosening a setting, answering an approval and handing
/// out or changing a policy need the owner token that only an unlock or
/// `POST /v1/confirm` (password or device unlock) gives out.
#[tokio::test(flavor = "multi_thread")]
async fn the_session_token_alone_cannot_reveal_approve_or_widen() {
    use base64::Engine as _;
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), false).await;
    let c = C::new(&r);
    let (code, u) = c.post("/v1/unlock", json!({ "password": PW }));
    assert_eq!(code, 200);
    assert!(u["owner_token"].as_str().unwrap().starts_with("usk_o_"));
    let (code, _) = c.post(
        "/v1/secrets",
        json!({ "name": "stripe", "value": "sk_live_51Habcdefghijklmnop" }),
    );
    assert_eq!(code, 201);
    // With the owner token (the unlocking client has it) everything works.
    assert_eq!(
        c.post("/v1/secrets/stripe/reveal", json!({ "confirm": true }))
            .0,
        200
    );

    // A program that only read daemon.token.
    c.forget_owner();
    let refused = [
        (
            "POST",
            "/v1/secrets/stripe/reveal",
            json!({ "confirm": true }),
        ),
        ("POST", "/v1/secrets/stripe/inject", json!({ "var": "K" })),
        (
            "PATCH",
            "/v1/secrets/stripe",
            json!({ "allow_injection": true }),
        ),
        ("PATCH", "/v1/secrets/stripe", json!({ "no_scrub": true })),
        (
            "PATCH",
            "/v1/secrets/stripe",
            json!({ "upstreams": ["evil.example"] }),
        ),
        (
            "PATCH",
            "/v1/secrets/stripe",
            json!({ "provider": "generic" }),
        ),
        (
            "POST",
            "/v1/handles",
            json!({ "secret": "stripe", "preset_policy": "stripe:full" }),
        ),
        (
            "POST",
            "/v1/handles",
            json!({ "secret": "stripe", "policy": { "version": 1, "allow": ["* /**"] } }),
        ),
        ("PATCH", "/v1/settings", json!({ "care": "relaxed" })),
        ("PATCH", "/v1/settings", json!({ "idle_lock_minutes": 0 })),
        (
            "POST",
            "/v1/approvals/latest",
            json!({ "decision": "allow" }),
        ),
        (
            "POST",
            "/v1/unlock-methods",
            json!({ "kind": "hello", "label": "x",
            "salt": base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
            "kek": base64::engine::general_purpose::STANDARD.encode([2u8; 32]) }),
        ),
    ];
    for (method, path, body) in refused {
        let (code, b) = match method {
            "POST" => c.post(path, body),
            _ => c.patch(path, body),
        };
        assert_eq!(code, 403, "{method} {path}: {b}");
        assert_eq!(b["error"], "owner_required", "{method} {path}");
    }
    // Nothing above took effect.
    let m = c.get("/v1/secrets/stripe").1;
    assert_eq!(m["allow_injection"], false);
    assert_eq!(m["upstreams"][0], "api.stripe.com");
    assert_eq!(c.get("/v1/status").1["care"], "balanced");
    assert_eq!(c.get("/v1/handles").1.as_array().unwrap().len(), 0);
    // What that program may still do: read metadata, add a key, and make a
    // handle with the care-level default policy (what `usk guard fix` does).
    let (code, h) = c.post(
        "/v1/handles",
        json!({ "secret": "stripe", "label": "default" }),
    );
    assert_eq!(code, 201, "{h}");
    assert_eq!(c.post("/v1/handles/default/resume", json!({})).0, 403);
    assert_eq!(
        c.patch(
            "/v1/handles/default",
            json!({ "preset_policy": "stripe:full" })
        )
        .0,
        403
    );

    // A wrong password does not confirm, and attempts are rate limited with unlocks.
    let (code, b) = c.post("/v1/confirm", json!({ "password": "not it" }));
    assert_eq!(code, 401, "{b}");
    assert_eq!(b["error"], "wrong_password");
    assert!(c.owner.lock().unwrap().is_none());
    // The right one does, and the token then opens the gated routes.
    let (code, b) = c.post("/v1/confirm", json!({ "password": PW }));
    assert_eq!(code, 200, "{b}");
    assert_eq!(
        c.post("/v1/secrets/stripe/reveal", json!({ "confirm": true }))
            .1["value"],
        "sk_live_51Habcdefghijklmnop"
    );
    // Locking forgets every owner token; the next unlock issues a new one.
    let stale = c.owner.lock().unwrap().clone().unwrap();
    assert_eq!(c.post("/v1/lock", json!({})).0, 200);
    assert_eq!(c.post("/v1/unlock", json!({ "password": PW })).0, 200);
    *c.owner.lock().unwrap() = Some(stale);
    let (code, b) = c.post("/v1/secrets/stripe/reveal", json!({ "confirm": true }));
    assert_eq!(code, 403, "{b}");
    // Confirming needs an unlocked vault: unlocking is the confirmation then.
    assert_eq!(c.post("/v1/lock", json!({})).0, 200);
    assert_eq!(c.post("/v1/confirm", json!({ "password": PW })).0, 401);
    r.shutdown().await;
}

/// With several requests waiting, "latest" is ambiguous and refused: a tool
/// could slip its own request in just before the owner answers.
#[tokio::test(flavor = "multi_thread")]
async fn approving_latest_with_several_pending_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), false).await;
    let c = C::new(&r);
    assert_eq!(c.post("/v1/unlock", json!({ "password": PW })).0, 200);
    let (code, b) = c.post("/v1/approvals/latest", json!({ "decision": "allow" }));
    assert_eq!(code, 404, "{b}");
    // Two parked requests: deciding "latest" must name one by id instead.
    let state = r.state_for_tests();
    for n in 0..2 {
        let _rx = state
            .approval_create(unseenkey_daemon::state::PendingApproval {
                id: unseenkey_core::ids::Id::new_v7(1_000 + n),
                kind: "request".into(),
                handle_id: unseenkey_core::ids::Id::new_v7(1),
                label: format!("h{n}"),
                secret: "s".into(),
                caller: "mcp:x".into(),
                method: "POST".into(),
                host: "api.stripe.com".into(),
                path: "/v1/refunds".into(),
                scope: "this request".into(),
                remember_key: None,
                created_at: 1_000 + n,
                expires_at: i64::MAX,
            })
            .await;
    }
    let (code, b) = c.post("/v1/approvals/latest", json!({ "decision": "allow" }));
    assert_eq!(code, 409, "{b}");
    assert_eq!(b["error"], "ambiguous");
    assert_eq!(c.get("/v1/approvals").1.as_array().unwrap().len(), 2);
    r.shutdown().await;
}

/// Registering an AI tool under a name that already exists hands the new
/// token everything approved for that name. A program that read
/// `daemon.token` must not be able to take over Claude Code's identity that
/// way: replacing needs the owner, and every registration is audited.
#[tokio::test(flavor = "multi_thread")]
async fn an_existing_ai_tool_cannot_be_taken_over_with_the_session_token() {
    let dir = tempfile::tempdir().unwrap();
    let r = start(dir.path(), false).await;
    let c = C::new(&r);

    // Locked: nothing can be registered, so nothing goes unaudited.
    let (code, b) = c.post("/v1/callers", json!({ "name": "claude-code" }));
    assert_eq!(code, 401, "{b}");
    assert_eq!(b["error"], "vault_locked");

    assert_eq!(c.post("/v1/unlock", json!({ "password": PW })).0, 200);
    c.forget_owner();

    // A new name needs only the session token.
    let (code, first) = c.post("/v1/callers", json!({ "name": "claude-code" }));
    assert_eq!(code, 201, "{first}");
    let first = first["token"].as_str().unwrap().to_string();

    // The same name again: refused, with or without asking to replace.
    let (code, b) = c.post("/v1/callers", json!({ "name": "claude-code" }));
    assert_eq!(code, 409, "{b}");
    assert_eq!(b["error"], "caller_exists");
    let (code, b) = c.post(
        "/v1/callers",
        json!({ "name": "claude-code", "replace": true }),
    );
    assert_eq!(code, 403, "{b}");
    assert_eq!(b["error"], "owner_required");

    // The original token still works.
    let mcp = |token: &str| {
        C::status_of(
            c.agent
                .post(&format!("{}/mcp", c.base))
                .set("Authorization", &format!("Bearer {token}"))
                .set("Content-Type", "application/json")
                .send_string(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
        )
        .0
    };
    assert_eq!(mcp(&first), 200);

    // The owner can replace it; the old token stops working.
    assert_eq!(c.post("/v1/confirm", json!({ "password": PW })).0, 200);
    let (code, second) = c.post(
        "/v1/callers",
        json!({ "name": "claude-code", "replace": true }),
    );
    assert_eq!(code, 201, "{second}");
    let second = second["token"].as_str().unwrap().to_string();
    assert_ne!(first, second);
    assert_eq!(mcp(&first), 401);
    assert_eq!(mcp(&second), 200);

    // Removing is audited too.
    assert_eq!(c.delete("/v1/callers/claude-code").0, 200);

    let (_, audit) = c.get("/v1/audit?since=1&limit=100");
    let entries: Vec<(&str, &str)> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"].as_str().unwrap().starts_with("caller_"))
        .map(|e| {
            (
                e["kind"].as_str().unwrap(),
                e["body"]["name"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        entries,
        [
            ("caller_registered", "claude-code"),
            ("caller_replaced", "claude-code"),
            ("caller_removed", "claude-code"),
        ]
    );
    r.shutdown().await;
}
