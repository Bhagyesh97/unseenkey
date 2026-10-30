//! `/v1/projects` and a project's daily limit.

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

const PW: &str = "projects-test-password";

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
    fn mgmt(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut req = self
            .agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token));
        if let Some(o) = self.owner.lock().unwrap().as_ref() {
            req = req.set("X-Usk-Owner", o);
        }
        let (code, v) = Self::call(match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        });
        if code == 200 && path == "/v1/unlock" {
            *self.owner.lock().unwrap() = v["owner_token"].as_str().map(str::to_string);
        }
        (code, v)
    }
    fn ok(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let (code, v) = self.mgmt(method, path, body);
        assert!((200..300).contains(&code), "{method} {path}: {code} {v}");
        v
    }
    fn brokered(&self, handle: &str) -> (u16, Value) {
        Self::call(
            self.agent
                .get(&format!("{}/p/stripe/v1/customers", self.base))
                .set("Authorization", &format!("Bearer {handle}"))
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
        axum::serve(
            listener,
            Router::new().fallback(any(|| async {
                ([("content-type", "application/json")], "{\"ok\":true}")
            })),
        )
        .await
        .unwrap()
    });
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
    let c = C {
        base: format!("http://{}", r.addr),
        token: r.token().to_string(),
        owner: std::sync::Mutex::new(None),
        agent: ureq::AgentBuilder::new()
            .max_idle_connections(0)
            .timeout(Duration::from_secs(20))
            .build(),
    };
    c.ok("POST", "/v1/unlock", Some(json!({ "password": PW })));
    for (name, value) in [
        ("stripe-live", "sk_live_51Habcdefghijklmnop"),
        ("stripe-test", "sk_test_51Hzyxwvutsrqponmlk"),
    ] {
        c.ok(
            "POST",
            "/v1/secrets",
            Some(json!({ "name": name, "value": value })),
        );
    }
    (dir, r, c)
}

#[tokio::test(flavor = "multi_thread")]
async fn projects_over_the_api() {
    let (_dir, r, c) = setup().await;
    // A folder alone is enough: the name comes from it, and never collides.
    let (code, p) = c.mgmt(
        "POST",
        "/v1/projects",
        Some(json!({ "paths": ["/work/shop/"] })),
    );
    assert_eq!(code, 201, "{p}");
    assert_eq!(p["name"], "shop");
    assert_eq!(p["paths"], json!(["/work/shop"]));
    let (_, p2) = c.mgmt(
        "POST",
        "/v1/projects",
        Some(json!({ "paths": ["/other/shop"] })),
    );
    assert_eq!(p2["name"], "shop 2");
    let (code, e) = c.mgmt("POST", "/v1/projects", Some(json!({})));
    assert_eq!(code, 400, "{e}");
    let (code, e) = c.mgmt("POST", "/v1/projects", Some(json!({ "name": "SHOP" })));
    assert_eq!(
        (code, e["error"].as_str()),
        (409, Some("project_exists")),
        "{e}"
    );

    let id = p["id"].as_str().unwrap();
    let v = c.ok(
        "POST",
        &format!("/v1/projects/{id}/secrets"),
        Some(json!({ "secret": "stripe-live" })),
    );
    assert_eq!(v["secrets"][0]["name"], "stripe-live");
    let (code, e) = c.mgmt(
        "POST",
        "/v1/projects/shop/secrets",
        Some(json!({ "secret": "nope" })),
    );
    assert_eq!(code, 404, "{e}");

    // By folder: the deepest project that contains the directory.
    let here = c.ok("GET", "/v1/projects?dir=%2Fwork%2Fshop%2Fweb", None);
    assert_eq!(here.as_array().unwrap().len(), 1);
    assert_eq!(here[0]["name"], "shop");
    assert!(c
        .ok("GET", "/v1/projects?dir=%2Fnowhere", None)
        .as_array()
        .unwrap()
        .is_empty());

    let v = c.ok(
        "PATCH",
        "/v1/projects/shop",
        Some(json!({ "name": "Shop", "cap_per_day": 3, "notes": "storefront" })),
    );
    assert_eq!(
        (v["name"].as_str(), v["cap_per_day"].as_u64()),
        (Some("Shop"), Some(3))
    );
    let v = c.ok(
        "PATCH",
        "/v1/projects/Shop",
        Some(json!({ "notes": "kept the cap" })),
    );
    assert_eq!(v["cap_per_day"], 3, "an absent field stays");
    let v = c.ok(
        "PATCH",
        "/v1/projects/Shop",
        Some(json!({ "cap_per_day": null })),
    );
    assert!(v["cap_per_day"].is_null(), "null clears");

    let v = c.ok(
        "DELETE",
        &format!("/v1/projects/{id}/secrets/stripe-live"),
        None,
    );
    assert!(v["secrets"].as_array().unwrap().is_empty());
    c.ok("DELETE", &format!("/v1/projects/{id}"), None);
    let (code, _) = c.mgmt("GET", &format!("/v1/projects/{id}"), None);
    assert_eq!(code, 404);

    let (_, audit) = c.mgmt("GET", "/v1/audit?limit=1000", None);
    let kinds: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    for k in ["project_created", "project_changed", "project_deleted"] {
        assert!(kinds.contains(&k), "{k} missing from {kinds:?}");
    }
    r.shutdown().await;
}

/// The daily limit counts every handle made for the project, and only those.
#[tokio::test(flavor = "multi_thread")]
async fn a_project_stops_at_its_daily_limit() {
    let (_dir, r, c) = setup().await;
    c.ok(
        "POST",
        "/v1/projects",
        Some(
            json!({ "name": "shop", "secrets": ["stripe-live", "stripe-test"], "cap_per_day": 3 }),
        ),
    );
    let mk = |label: &str, secret: &str, project: Option<&str>| {
        let mut body = json!({ "secret": secret, "label": label });
        if let Some(p) = project {
            body["project"] = json!(p);
        }
        c.ok("POST", "/v1/handles", Some(body))["handle"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let web = mk("web", "stripe-live", Some("shop"));
    let worker = mk("worker", "stripe-test", Some("shop"));
    let outside = mk("script", "stripe-live", None);
    let (code, e) = c.mgmt("POST", "/v1/projects", Some(json!({ "name": "blog" })));
    assert_eq!(code, 201, "{e}");
    let (code, e) = c.mgmt(
        "POST",
        "/v1/handles",
        Some(json!({ "secret": "stripe-live", "label": "b", "project": "blog" })),
    );
    assert_eq!(
        (code, e["error"].as_str()),
        (400, Some("secret_not_in_project")),
        "{e}"
    );

    assert_eq!(c.brokered(&web).0, 200);
    assert_eq!(c.brokered(&worker).0, 200);
    assert_eq!(c.brokered(&web).0, 200);
    let (code, body) = c.brokered(&worker);
    assert_eq!(code, 429, "{body}");
    assert_eq!(body["error"], "project_cap_reached", "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("\"shop\""),
        "{body}"
    );
    // A handle not made for the project is not held back by it.
    assert_eq!(c.brokered(&outside).0, 200);

    let v = c.ok("GET", "/v1/projects/shop", None);
    assert_eq!(v["requests_today"], 3, "{v}");
    assert_eq!(v["handles"], 2, "{v}");
    let (_, audit) = c.mgmt("GET", "/v1/audit?kind=deny&limit=100", None);
    assert!(
        audit
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["body"]["reason"] == "project_cap"),
        "{audit}"
    );

    c.ok(
        "PATCH",
        "/v1/projects/shop",
        Some(json!({ "cap_per_day": 10 })),
    );
    assert_eq!(
        c.brokered(&worker).0,
        200,
        "raising the limit lets it through"
    );
    r.shutdown().await;
}
