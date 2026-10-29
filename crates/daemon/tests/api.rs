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
    agent: ureq::Agent,
}

impl C {
    fn new(r: &Running) -> Self {
        Self {
            base: format!("http://{}", r.addr),
            token: r.token().to_string(),
            agent: ureq::AgentBuilder::new().max_idle_connections(0).build(),
        }
    }
    fn req(&self, method: &str, path: &str) -> ureq::Request {
        self.agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token))
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
        Self::status_of(self.req("POST", path).send_json(body))
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
