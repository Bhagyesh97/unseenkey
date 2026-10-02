//! Broker overhead: latency of a request through the broker versus the same
//! request straight to the upstream (a loopback mock). Ignored by default
//! because the numbers depend on the machine; run it by hand:
//!
//! ```text
//! cargo test -p unseenkey-daemon --release --test overhead -- --ignored --nocapture
//! ```

use axum::routing::any;
use axum::Router;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, ServeOptions};

const PW: &str = "overhead-test-password";
const KEY: &str = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
const WARMUP: usize = 50;
const N: usize = 400;

async fn mock_upstream() -> SocketAddr {
    let app = Router::new().route(
        "/{*rest}",
        any(|| async {
            (
                [("content-type", "application/json")],
                json!({ "object": "list", "data": [{ "id": "gpt-4o" }, { "id": "o3" }] })
                    .to_string(),
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

fn measure(mut f: impl FnMut()) -> Vec<Duration> {
    for _ in 0..WARMUP {
        f();
    }
    let mut v = Vec::with_capacity(N);
    for _ in 0..N {
        let t = Instant::now();
        f();
        v.push(t.elapsed());
    }
    v.sort();
    v
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "benchmark; run by hand in release mode"]
async fn broker_overhead_p99() {
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
    let daemon = serve(ServeOptions {
        vault_path: path,
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: false,
        upstream_overrides: vec![("api.openai.com".into(), format!("http://{mock}"))],
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap();
    let base = format!("http://{}", daemon.addr);
    let token = daemon.token().to_string();
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    let mgmt = |method: &str, path: &str, body: Value| -> Value {
        agent
            .request(method, &format!("{base}{path}"))
            .set("Authorization", &format!("Bearer {token}"))
            .send_json(body)
            .unwrap()
            .into_json()
            .unwrap()
    };
    mgmt("POST", "/v1/unlock", json!({ "password": PW }));
    mgmt(
        "POST",
        "/v1/secrets",
        json!({ "name": "openai", "value": KEY }),
    );
    let created = mgmt(
        "POST",
        "/v1/handles",
        json!({ "secret": "openai", "label": "bench", "preset_policy": "openai:chat" }),
    );
    let handle = created["handle"].as_str().unwrap().to_string();

    // Same request, two routes, one keep-alive agent each.
    let direct_agent = ureq::AgentBuilder::new().build();
    let direct_url = format!("http://{mock}/v1/models");
    let direct = measure(|| {
        let r = direct_agent.get(&direct_url).call().unwrap();
        assert_eq!(r.status(), 200);
        r.into_string().unwrap();
    });
    let broker_agent = ureq::AgentBuilder::new().build();
    let broker_url = format!("{base}/p/openai/v1/models");
    let brokered = measure(|| {
        let r = broker_agent
            .get(&broker_url)
            .set("Authorization", &format!("Bearer {handle}"))
            .call()
            .unwrap();
        assert_eq!(r.status(), 200);
        r.into_string().unwrap();
    });

    let (d50, d95, d99) = (
        percentile(&direct, 0.50),
        percentile(&direct, 0.95),
        percentile(&direct, 0.99),
    );
    let (b50, b95, b99) = (
        percentile(&brokered, 0.50),
        percentile(&brokered, 0.95),
        percentile(&brokered, 0.99),
    );
    println!(
        "\nbroker overhead over {N} requests (after {WARMUP} warm-up), loopback mock upstream"
    );
    println!("              p50       p95       p99");
    println!(
        "direct    {:>7.2}ms {:>7.2}ms {:>7.2}ms",
        ms(d50),
        ms(d95),
        ms(d99)
    );
    println!(
        "brokered  {:>7.2}ms {:>7.2}ms {:>7.2}ms",
        ms(b50),
        ms(b95),
        ms(b99)
    );
    println!(
        "overhead  {:>7.2}ms {:>7.2}ms {:>7.2}ms\n",
        ms(b50) - ms(d50),
        ms(b95) - ms(d95),
        ms(b99) - ms(d99)
    );
    // Generous ceiling: a regression that adds tens of milliseconds is a bug,
    // machine noise is not.
    assert!(
        ms(b99) - ms(d99) < 100.0,
        "p99 overhead {:.2} ms is far above the 10 ms target",
        ms(b99) - ms(d99)
    );
    daemon.shutdown().await;
}
