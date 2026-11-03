//! Stress: many callers at once, changes during traffic, hostile input.
//! Ignored by default, because it takes minutes and prints numbers that depend
//! on the machine; run it by hand:
//!
//! ```text
//! cargo test -p unseenkey-daemon --release --test stress -- --ignored --nocapture --test-threads=1
//! ```

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, Running, ServeOptions};

const PW: &str = "stress-test-password";
const SID: &str = "AC0123456789abcdef0123456789abcdef";
const TOKEN: &str = "twilio-token-abcdefghijklmnop";
const API: &str = "api.example.test";
const AUTH: &str = "auth.example.test";
const TEST_KEY: &str = include_str!("fixtures/service-account-test-key.txt");

fn basic(pair: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(pair)
    )
}

fn key_file(token_uri: &str) -> String {
    json!({
        "type": "service_account", "project_id": "p", "private_key_id": "kid-1",
        "private_key": TEST_KEY, "client_email": "bot@p.iam.gserviceaccount.com",
        "token_uri": token_uri
    })
    .to_string()
}

#[derive(Default)]
struct Mock {
    /// Path and Authorization header of each API call.
    seen: Mutex<Vec<(String, String)>>,
    token_calls: AtomicUsize,
    token_fails: AtomicBool,
    /// Keep no record, so a long run measures the daemon's memory and not this list.
    quiet: AtomicBool,
}

async fn mock(State(m): State<Arc<Mock>>, req: Request) -> axum::response::Response {
    let path = req.uri().path().to_string();
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if path == "/token" {
        let n = m.token_calls.fetch_add(1, Ordering::SeqCst) + 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if m.token_fails.load(Ordering::SeqCst) {
            return (
                StatusCode::BAD_REQUEST,
                [("content-type", "application/json")],
                json!({ "error": "invalid_grant" }).to_string(),
            )
                .into_response();
        }
        return (
            [("content-type", "application/json")],
            json!({ "access_token": format!("ya29.stress-{n}-abcdefghijklmnop"), "expires_in": 3600 })
                .to_string(),
        )
            .into_response();
    }
    if !m.quiet.load(Ordering::SeqCst) {
        m.seen.lock().unwrap().push((path.clone(), auth.clone()));
    }
    if path.ends_with("/redirect") {
        return (
            StatusCode::FOUND,
            [("location", "https://evil.example.test/steal")],
            "",
        )
            .into_response();
    }
    // Echoes what it was sent, as a careless provider might.
    (
        [("content-type", "application/json")],
        json!({ "ok": true, "echo": auth }).to_string(),
    )
        .into_response()
}

/// A provider that answers in small chunks, split at the offset in its path.
async fn chunked(listener: tokio::net::TcpListener) {
    loop {
        let Ok((mut s, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            let mut got = 0;
            while !buf[..got].windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf[got..]).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => got += n,
                }
            }
            let head = String::from_utf8_lossy(&buf[..got]).into_owned();
            let path = head.split_whitespace().nth(1).unwrap_or("/0").to_string();
            if path == "/sse" {
                let start = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
                let _ = s.write_all(start.as_bytes()).await;
                for i in 0..20 {
                    let event = format!("data: {{\"n\":{i},\"text\":\"{}\"}}\n\n", "x".repeat(170));
                    let _ = s
                        .write_all(format!("{:x}\r\n{event}\r\n", event.len()).as_bytes())
                        .await;
                    let _ = s.flush().await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let _ = s.write_all(b"0\r\n\r\n").await;
                let _ = s.shutdown().await;
                return;
            }
            let cut: usize = path.trim_start_matches('/').parse().unwrap_or(0);
            let auth = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .starts_with("authorization:")
                        .then(|| l[14..].trim().to_string())
                })
                .unwrap_or_default();
            let encoded = auth.strip_prefix("Basic ").unwrap_or("").to_string();
            let raw = base64::engine::general_purpose::STANDARD
                .decode(&encoded)
                .ok()
                .and_then(|r| String::from_utf8(r).ok())
                .unwrap_or_default();
            let pass = raw
                .split_once(':')
                .map(|(_, p)| p)
                .unwrap_or("")
                .to_string();
            let body = format!("<{encoded}|{raw}|{pass}>");
            let cut = cut.min(body.len());
            let head = "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
            let _ = s.write_all(head.as_bytes()).await;
            for part in [&body.as_bytes()[..cut], &body.as_bytes()[cut..]] {
                if part.is_empty() {
                    continue;
                }
                let _ = s
                    .write_all(format!("{:x}\r\n", part.len()).as_bytes())
                    .await;
                let _ = s.write_all(part).await;
                let _ = s.write_all(b"\r\n").await;
                let _ = s.flush().await;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let _ = s.write_all(b"0\r\n\r\n").await;
            let _ = s.shutdown().await;
        });
    }
}

struct Env {
    daemon: Running,
    addr: SocketAddr,
    base: String,
    token: String,
    owner: Mutex<Option<String>>,
    agent: ureq::Agent,
    mock: Arc<Mock>,
    _dir: tempfile::TempDir,
}

fn outcome(r: Result<ureq::Response, ureq::Error>) -> (u16, String) {
    match r {
        Ok(resp) => {
            let code = resp.status();
            (code, resp.into_string().unwrap_or_default())
        }
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_string().unwrap_or_default()),
        Err(e) => (0, format!("transport: {e}")),
    }
}

impl Env {
    fn mgmt(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut req = self
            .agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Content-Type", "application/json");
        if let Some(o) = self.owner.lock().unwrap().as_ref() {
            req = req.set("X-Usk-Owner", o);
        }
        let (code, text) = outcome(match body {
            Some(b) => req.send_string(&b.to_string()),
            None => req.call(),
        });
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        if code == 200 && path == "/v1/unlock" {
            *self.owner.lock().unwrap() = v["owner_token"].as_str().map(str::to_string);
        }
        (code, v)
    }
    fn add(&self, body: Value) -> Value {
        let (code, v) = self.mgmt("POST", "/v1/secrets", Some(body));
        assert_eq!(code, 201, "{v}");
        v
    }
    fn handle(&self, secret: &str, preset_policy: Option<&str>) -> String {
        static N: AtomicUsize = AtomicUsize::new(0);
        let label = format!("stress-{}", N.fetch_add(1, Ordering::SeqCst));
        let (code, v) = self.mgmt(
            "POST",
            "/v1/handles",
            Some(json!({ "secret": secret, "label": label, "preset_policy": preset_policy, "on_anomaly": "alert" })),
        );
        assert_eq!(code, 201, "{v}");
        v["handle"].as_str().unwrap().to_string()
    }
    fn get(&self, path: &str, authorization: &str) -> (u16, String) {
        outcome(
            self.agent
                .get(&format!("{}{path}", self.base))
                .set("Authorization", authorization)
                .call(),
        )
    }
    /// A request exactly as written: an HTTP client would tidy some of these paths.
    fn raw(&self, method: &str, target: &str, authorization: &str) -> u16 {
        let mut s = TcpStream::connect(self.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        write!(
            s,
            "{method} {target} HTTP/1.1\r\nHost: {}\r\nAuthorization: {authorization}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            self.addr
        )
        .unwrap();
        let mut text = String::new();
        let _ = s.read_to_string(&mut text);
        text.split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }
    fn alive(&self) {
        let (code, v) = self.mgmt("GET", "/v1/status", None);
        assert_eq!(code, 200, "the daemon stopped answering: {v}");
    }
    fn seen(&self) -> usize {
        self.mock.seen.lock().unwrap().len()
    }
}

async fn setup(extra_hosts: &[&str]) -> Env {
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
    let m = Arc::new(Mock::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream: SocketAddr = listener.local_addr().unwrap();
    let state = m.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(any(mock)).with_state(state),
        )
        .await
        .unwrap()
    });
    let chunks = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let chunk_addr: SocketAddr = chunks.local_addr().unwrap();
    tokio::spawn(chunked(chunks));
    let mut hosts = vec![API, AUTH, "api.twilio.com"];
    hosts.extend_from_slice(extra_hosts);
    let mut upstream_overrides: Vec<(String, String)> = hosts
        .iter()
        .map(|h| (h.to_string(), format!("http://{upstream}")))
        .collect();
    upstream_overrides.push(("api.plivo.com".into(), format!("http://{chunk_addr}")));
    let daemon = serve(ServeOptions {
        vault_path: path,
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: false,
        upstream_overrides,
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap();
    let env = Env {
        addr: daemon.addr,
        base: format!("http://{}", daemon.addr),
        token: daemon.token().to_string(),
        owner: Mutex::new(None),
        agent: ureq::AgentBuilder::new()
            .timeout_read(Duration::from_secs(60))
            .timeout_write(Duration::from_secs(60))
            .redirects(0)
            .build(),
        mock: m,
        daemon,
        _dir: dir,
    };
    let (code, v) = env.mgmt("POST", "/v1/unlock", Some(json!({ "password": PW })));
    assert_eq!(code, 200, "{v}");
    env
}

/// What many callers got.
struct Tally {
    codes: BTreeMap<u16, usize>,
    micros: Vec<u128>,
    took: Duration,
}

impl Tally {
    fn print(&mut self, what: &str) {
        self.micros.sort_unstable();
        let at = |q: f64| {
            let i = ((self.micros.len() as f64 - 1.0) * q) as usize;
            self.micros.get(i).copied().unwrap_or(0) as f64 / 1000.0
        };
        println!(
            "{what}: {} calls in {:.1}s ({:.0}/s), p50 {:.1} ms, p99 {:.1} ms, worst {:.1} ms, codes {:?}",
            self.micros.len(),
            self.took.as_secs_f64(),
            self.micros.len() as f64 / self.took.as_secs_f64().max(0.001),
            at(0.5),
            at(0.99),
            at(1.0),
            self.codes
        );
    }
}

/// `threads` callers make `each` calls, all starting together. A reply that
/// fails `check` fails the test.
fn callers(
    threads: usize,
    each: usize,
    call: impl Fn(&ureq::Agent, usize, usize) -> (u16, String) + Sync,
    check: impl Fn(u16, &str) + Sync,
) -> Tally {
    let start = Barrier::new(threads);
    let began = Instant::now();
    let parts: Vec<Vec<(u16, u128)>> = std::thread::scope(|sc| {
        let workers: Vec<_> = (0..threads)
            .map(|t| {
                let (start, call, check) = (&start, &call, &check);
                sc.spawn(move || {
                    let agent = ureq::AgentBuilder::new()
                        .timeout_read(Duration::from_secs(60))
                        .redirects(0)
                        .build();
                    start.wait();
                    (0..each)
                        .map(|i| {
                            let t0 = Instant::now();
                            let (code, body) = call(&agent, t, i);
                            let took = t0.elapsed().as_micros();
                            check(code, &body);
                            (code, took)
                        })
                        .collect()
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().unwrap()).collect()
    });
    let mut tally = Tally {
        codes: BTreeMap::new(),
        micros: Vec::new(),
        took: began.elapsed(),
    };
    for (code, micros) in parts.into_iter().flatten() {
        *tally.codes.entry(code).or_default() += 1;
        tally.micros.push(micros);
    }
    tally
}

/// Repeatable, so a failure can be run again.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn text(&mut self) -> String {
        const PIECES: &[&str] = &[
            ":",
            "\n",
            "\r\n",
            " ",
            "\t",
            "{",
            "}",
            "\"",
            "\\",
            "/",
            "//",
            "=",
            "%",
            "%0a",
            "\0",
            "€",
            "😀",
            "é",
            "AC",
            "SK",
            "rzp_live_",
            "AKIA",
            "usk_h_",
            "{{usk:",
            "}}",
            "-----BEGIN PRIVATE KEY-----",
            "0123456789abcdef",
            "0123456789abcdef0123456789abcdef",
            "https://",
            "x",
            "service_account",
            "\"type\"",
            "client_email",
            "private_key",
        ];
        let n = self.below(12);
        (0..n).map(|_| PIECES[self.below(PIECES.len())]).collect()
    }
}

macro_rules! blocking {
    ($body:block) => {
        tokio::task::block_in_place(|| $body)
    };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn a_two_part_key_under_load() {
    let e = setup(&[]).await;
    blocking!({
        e.add(json!({ "name": "twilio", "value": format!("{SID}:{TOKEN}") }));
        let handle = e.handle("twilio", Some("twilio:full"));
        let bearer = format!("Bearer {handle}");
        let sdk = basic(&format!("{SID}:{handle}"));
        let want = basic(&format!("{SID}:{TOKEN}"));
        let url = format!("{}/p/twilio/2010-04-01/Accounts.json", e.base);
        let mut t = callers(
            64,
            100,
            |agent, tid, _| {
                let auth = if tid % 2 == 0 { &bearer } else { &sdk };
                outcome(agent.get(&url).set("Authorization", auth).call())
            },
            |code, body| {
                assert_eq!(code, 200, "{body}");
                assert!(!body.contains(TOKEN), "{body}");
                assert!(!body.contains(&want[6..]), "{body}");
            },
        );
        t.print("two-part key, 64 callers");
        let seen = e.mock.seen.lock().unwrap();
        assert_eq!(seen.len(), 6400);
        assert!(
            seen.iter().all(|(_, a)| *a == want),
            "wrong credential upstream"
        );
    });
    e.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn replacing_a_key_during_traffic_never_mixes_the_parts() {
    let e = setup(&[]).await;
    blocking!({
        let a = (
            "AC00000000000000000000000000000000",
            "password-aaaaaaaaaaaaaaaa",
        );
        let b = (
            "AC11111111111111111111111111111111",
            "password-bbbbbbbbbbbbbbbb",
        );
        e.add(json!({ "name": "twilio", "value": format!("{}:{}", a.0, a.1) }));
        let handle = format!("Bearer {}", e.handle("twilio", Some("twilio:full")));
        let url = format!("{}/p/twilio/2010-04-01/Accounts.json", e.base);
        let stop = AtomicBool::new(false);
        let changes = AtomicUsize::new(0);
        let echoed_old = AtomicUsize::new(0);
        let (pa, pb) = (
            basic(&format!("{}:{}", a.0, a.1)),
            basic(&format!("{}:{}", b.0, b.1)),
        );
        std::thread::scope(|sc| {
            sc.spawn(|| {
                for i in 0..200 {
                    let (user, pass) = if i % 2 == 0 { b } else { a };
                    let (code, v) = e.mgmt(
                        "PATCH",
                        "/v1/secrets/twilio",
                        Some(json!({ "value": format!("{user}
{pass}") })),
                    );
                    assert_eq!(code, 200, "{v}");
                    changes.fetch_add(1, Ordering::SeqCst);
                }
                stop.store(true, Ordering::SeqCst);
            });
            let mut t = callers(
                32,
                150,
                |agent, _, _| outcome(agent.get(&url).set("Authorization", &handle).call()),
                |code, body| {
                    assert_eq!(code, 200, "{body}");
                    if body.contains(&pa[6..]) || body.contains(&pb[6..]) {
                        echoed_old.fetch_add(1, Ordering::SeqCst);
                    }
                },
            );
            t.print("32 callers during 200 replacements");
        });
        let (want_a, want_b) = (pa.clone(), pb.clone());
        let seen = e.mock.seen.lock().unwrap();
        let mixed = seen
            .iter()
            .filter(|(_, x)| *x != want_a && *x != want_b)
            .count();
        println!(
            "calls {}, mixed parts {mixed}, a just-replaced key echoed to a caller {} times",
            seen.len(),
            echoed_old.load(Ordering::SeqCst)
        );
        assert_eq!(mixed, 0, "a username went out with another key's password");
    });
    e.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn a_service_account_signs_in_once_however_many_callers() {
    let e = setup(&[]).await;
    blocking!({
        e.add(json!({
            "name": "gsc", "value": key_file(&format!("https://{AUTH}/token")),
            "upstreams": [API], "fields": { "scope": "s.one" }
        }));
        let handle = format!("Bearer {}", e.handle("gsc", None));
        let url = format!("{}/p/generic/@{API}/v1/things", e.base);
        let call = |agent: &ureq::Agent, _: usize, _: usize| {
            outcome(agent.get(&url).set("Authorization", &handle).call())
        };
        let clean = |code: u16, body: &str| {
            assert_eq!(code, 200, "{body}");
            assert!(!body.contains("ya29"), "token reached the caller: {body}");
        };

        // A cold start: everybody at once.
        let mut t = callers(200, 1, call, clean);
        t.print("200 callers, nothing cached");
        let signed_in = e.mock.token_calls.load(Ordering::SeqCst);
        println!("sign-ins for 200 simultaneous callers: {signed_in}");
        assert_eq!(signed_in, 1, "the sign-in was not shared");

        // New scopes during traffic.
        let before = e.mock.token_calls.load(Ordering::SeqCst);
        std::thread::scope(|sc| {
            sc.spawn(|| {
                for i in 0..20 {
                    let (code, v) = e.mgmt(
                        "PATCH",
                        "/v1/secrets/gsc",
                        Some(json!({ "scope": format!("s.scope{i}") })),
                    );
                    assert_eq!(code, 200, "{v}");
                    std::thread::sleep(Duration::from_millis(150));
                }
            });
            let mut t = callers(32, 40, call, clean);
            t.print("32 callers during 20 scope changes");
        });
        let during = e.mock.token_calls.load(Ordering::SeqCst) - before;
        println!("sign-ins during 20 scope changes: {during}");
        assert!(during <= 21, "more sign-ins than versions: {during}");
        let seen = e.mock.seen.lock().unwrap().clone();
        assert!(seen
            .iter()
            .all(|(_, a)| a.starts_with("Bearer ya29.stress-")));

        // Google says no, to everyone.
        e.mock.token_fails.store(true, Ordering::SeqCst);
        let (code, v) = e.mgmt(
            "PATCH",
            "/v1/secrets/gsc",
            Some(json!({ "scope": "s.final" })),
        );
        assert_eq!(code, 200, "{v}");
        let before = e.mock.token_calls.load(Ordering::SeqCst);
        let mut t = callers(50, 1, call, |code, body| {
            assert!(code >= 400, "{code} {body}");
            assert!(!body.contains("PRIVATE KEY"), "{body}");
        });
        t.print("50 callers while the sign-in is refused");
        println!(
            "sign-in attempts for those 50: {}",
            e.mock.token_calls.load(Ordering::SeqCst) - before
        );
        // And it recovers by itself.
        e.mock.token_fails.store(false, Ordering::SeqCst);
        let (code, body) = call(&e.agent, 0, 0);
        assert_eq!(code, 200, "no recovery: {body}");
    });
    e.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn locking_during_traffic() {
    let e = setup(&[]).await;
    blocking!({
        e.add(json!({ "name": "twilio", "value": format!("{SID}:{TOKEN}") }));
        e.add(json!({
            "name": "gsc", "value": key_file(&format!("https://{AUTH}/token")),
            "upstreams": [API], "fields": { "scope": "s.one" }
        }));
        let (ht, hg) = (
            format!("Bearer {}", e.handle("twilio", Some("twilio:full"))),
            format!("Bearer {}", e.handle("gsc", None)),
        );
        let (ut, ug) = (
            format!("{}/p/twilio/2010-04-01/Accounts.json", e.base),
            format!("{}/p/generic/@{API}/v1/things", e.base),
        );
        std::thread::scope(|sc| {
            sc.spawn(|| {
                for _ in 0..30 {
                    assert_eq!(e.mgmt("POST", "/v1/lock", Some(json!({}))).0, 200);
                    std::thread::sleep(Duration::from_millis(30));
                    let (code, v) = e.mgmt("POST", "/v1/unlock", Some(json!({ "password": PW })));
                    assert_eq!(code, 200, "{v}");
                    std::thread::sleep(Duration::from_millis(60));
                }
            });
            let mut t = callers(
                24,
                200,
                |agent, tid, _| {
                    let (u, h) = if tid % 2 == 0 { (&ut, &ht) } else { (&ug, &hg) };
                    outcome(agent.get(u).set("Authorization", h).call())
                },
                |code, body| {
                    assert!(code != 0 && code < 500, "{code} {body}");
                    assert!(!body.contains(TOKEN) && !body.contains("ya29"), "{body}");
                },
            );
            t.print("24 callers during 30 locks");
        });
        e.alive();
        let (code, body) = e.get("/p/twilio/2010-04-01/Accounts.json", &ht);
        assert_eq!(code, 200, "{body}");
    });
    e.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn hostile_authorization_headers() {
    let e = setup(&[]).await;
    blocking!({
        e.add(json!({ "name": "twilio", "value": format!("{SID}:{TOKEN}") }));
        let handle = e.handle("twilio", Some("twilio:full"));
        let target = "/p/twilio/2010-04-01/Accounts.json";
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut codes: BTreeMap<u16, usize> = BTreeMap::new();
        let mut cases: Vec<String> = [
            "Basic",
            "Basic ",
            "Basic :",
            "Basic ====",
            "Basic !!!",
            "Bearer",
            "Bearer ",
            "basic x",
            "Digest a=b",
            "Basic Og==",
            "Basic Og",
            "Basic QQ==",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // A handle that only nearly is one.
        for wrong in [
            format!("{SID}:{handle}x"),
            format!("{SID}:{}", &handle[..handle.len() - 1]),
            ":".to_string(),
            ":::".to_string(),
            format!("{handle}:{handle}x"),
            format!(":{SID}"),
            "€:😀".to_string(),
            "a".repeat(8000) + ":b",
        ] {
            cases.push(format!("Basic {}", b64.encode(wrong)));
        }
        let mut rng = Rng(0x9E3779B97F4A7C15);
        for _ in 0..3000 {
            let n = rng.below(200);
            let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            cases.push(format!("Basic {}", b64.encode(bytes)));
        }
        for c in &cases {
            let code = e.raw("GET", target, c);
            *codes.entry(code).or_default() += 1;
            assert!(code != 0 && code < 500, "{code} for {:.80}", c);
        }
        println!(
            "hostile Authorization headers: {} tried, codes {codes:?}",
            cases.len()
        );
        assert_eq!(e.seen(), 0, "a bad handle reached the provider");
        // Oversized.
        let big = format!("Basic {}", "A".repeat(200_000));
        let code = e.raw("GET", target, &big);
        println!("200 KB header: {code}");
        assert!(code < 500, "{code}");
        e.alive();
        assert_eq!(
            e.get(target, &format!("Bearer {handle}")).0,
            200,
            "still works"
        );
    });
    e.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn hostile_values_when_adding_and_changing() {
    let e = setup(&[]).await;
    blocking!({
        let mut rng = Rng(0xD1B54A32D192ED03);
        let mut codes: BTreeMap<u16, usize> = BTreeMap::new();
        let providers = [
            None,
            Some("twilio"),
            Some("razorpay"),
            Some("mailgun"),
            Some("gcp"),
            Some("aws"),
            Some("jira"),
        ];
        let mut note = |code: u16, what: &str| {
            *codes.entry(code).or_default() += 1;
            assert!(code != 0 && code < 500, "{code} on {what:.120}");
        };
        for i in 0..1500 {
            let value = rng.text();
            let provider = providers[rng.below(providers.len())];
            let name = format!("fuzz-{i}");
            let (code, _) = e.mgmt(
                "POST",
                "/v1/detect",
                Some(json!({ "value": value, "name": rng.text() })),
            );
            note(code, &value);
            let (code, made) = e.mgmt(
                "POST",
                "/v1/secrets",
                Some(json!({ "name": name, "value": value, "provider": provider })),
            );
            note(code, &value);
            if code == 201 {
                let path = format!("/v1/secrets/{}", made["id"].as_str().unwrap());
                let (code, _) = e.mgmt("PATCH", &path, Some(json!({ "username": rng.text() })));
                note(code, &value);
                let (code, _) = e.mgmt("PATCH", &path, Some(json!({ "value": rng.text() })));
                note(code, &value);
                let (code, _) = e.mgmt("DELETE", &path, None);
                note(code, &value);
            }
        }
        println!("hostile values: codes {codes:?}");
        // Where a key file may send its signed sign-in request.
        for (i, uri) in [
            "http://evil.example.test/token",
            "file:///etc/passwd",
            "ftp://evil.example.test/",
            "javascript:alert(1)",
            "https://",
            "//evil.example.test/token",
            "evil.example.test",
            "https://user:pw@evil.example.test/token",
            "https://accounts.google.com@evil.example.test/token",
            "https://evil.example.test:99999/token",
            "https://[::1]/token",
            "http://127.0.0.1:1/token",
            "http://localhost:1/token",
            "http://169.254.169.254/token",
            "https://evil.example.test/token",
        ]
        .iter()
        .enumerate()
        {
            let (code, v) = e.mgmt(
                "POST",
                "/v1/secrets",
                Some(json!({ "name": format!("uri-{i}"), "value": key_file(uri), "provider": "gcp" })),
            );
            println!(
                "token_uri {uri:<55} -> {code} {} {}",
                v["error"].as_str().unwrap_or(""),
                v["upstreams"]
            );
            assert!(code < 500, "{uri}");
        }
        e.alive();
    });
    e.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn the_pair_is_hidden_wherever_a_chunk_splits_it() {
    let e = setup(&[]).await;
    blocking!({
        let (user, pass) = ("MAPLIVOID01234567890", "plivo-password-abcdefghijkl");
        e.add(json!({ "name": "plivo", "value": format!("{user}:{pass}") }));
        let handle = format!("Bearer {}", e.handle("plivo", Some("plivo:full")));
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        let mut leaks = 0;
        let total = encoded.len() + format!("{user}:{pass}").len() + pass.len() + 4;
        for cut in 0..=total {
            let (code, body) = e.get(&format!("/p/plivo/{cut}"), &handle);
            assert_eq!(code, 200, "{body}");
            if body.contains(pass) || body.contains(&encoded) {
                leaks += 1;
                println!("leak at cut {cut}: {body}");
            }
        }
        println!("chunk splits tried: {}, leaks: {leaks}", total + 1);
        assert_eq!(leaks, 0);
    });
    e.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn a_key_file_does_not_hold_back_a_stream() {
    let e = setup(&[]).await;
    blocking!({
        // Any streamed reply, with a long key file elsewhere in the vault.
        e.add(json!({
            "name": "gsc", "value": key_file(&format!("https://{AUTH}/token")),
            "upstreams": [API], "fields": { "scope": "s.one" }
        }));
        e.add(
            json!({ "name": "plivo", "value": "MAPLIVOID01234567890:plivo-password-abcdefghijkl" }),
        );
        let handle = format!("Bearer {}", e.handle("plivo", Some("plivo:full")));
        let t0 = Instant::now();
        let resp = e
            .agent
            .get(&format!("{}/p/plivo/sse", e.base))
            .set("Authorization", &handle)
            .call()
            .unwrap();
        let mut reader = resp.into_reader();
        let mut buf = [0u8; 4096];
        let (mut first, mut total) = (None, 0);
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            first.get_or_insert(t0.elapsed());
            total += n;
        }
        let (first, last) = (first.unwrap(), t0.elapsed());
        println!("stream: first bytes at {first:?}, all {total} bytes at {last:?}");
        assert!(
            first < Duration::from_millis(800),
            "held back for {first:?}"
        );
    });
    e.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn host_locks_and_redirects() {
    let e = setup(&["site.atlassian.net"]).await;
    blocking!({
        e.add(json!({ "name": "jira", "value": "me@example.com:atlassian-token-abcdefgh" }));
        let handle = format!("Bearer {}", e.handle("jira", Some("jira:full")));
        // Each of these must not leave with the key.
        for host in [
            "evil.example.test",
            "atlassian.net.evil.example.test",
            "site.atlassian.net.evil.example.test",
            "site.atlassian.net@evil.example.test",
            "site.atlassian.net:443@evil.example.test",
            "site.atlassian.net%2f.evil.example.test",
            "site.atlassian.net%00.evil.example.test",
            "evilatlassian.net",
            "127.0.0.1",
            "localhost",
            "[::1]",
            "169.254.169.254",
        ] {
            let before = e.seen();
            let code = e.raw(
                "GET",
                &format!("/p/jira/@{host}/rest/api/3/myself"),
                &handle,
            );
            println!("jira -> @{host:<45} {code}");
            assert_eq!(e.seen(), before, "{host} reached the mock");
            assert!(
                code == 403 || code == 400,
                "{host} answered {code}: it was not refused"
            );
        }
        // The same, naming the host in a header.
        for host in [
            "evil.example.test\\.atlassian.net",
            "https://evil.example.test\\.atlassian.net",
            "[127.0.0.1:1\\.atlassian.net]:443",
            "evil.example.test#.atlassian.net",
            "evil.example.test?.atlassian.net",
            "evil.example.test/.atlassian.net",
        ] {
            let before = e.seen();
            let (code, body) = outcome(
                e.agent
                    .get(&format!("{}/p/jira/rest/api/3/myself", e.base))
                    .set("Authorization", &handle)
                    .set("X-Usk-Upstream", host)
                    .call(),
            );
            println!("jira -> header {host:<42} {code}");
            assert_eq!(e.seen(), before, "{host} reached the mock");
            assert!(code == 403 || code == 400, "{host} answered {code}: {body}");
        }
        // The real site works, whatever its case.
        for host in ["site.atlassian.net", "SITE.ATLASSIAN.NET"] {
            let (code, body) = e.get(&format!("/p/jira/@{host}/rest/api/3/myself"), &handle);
            println!("jira -> @{host}: {code}");
            assert_eq!(code, 200, "{body}");
        }
        // A provider's redirect is passed on, not followed with the key.
        let before = e.seen();
        let r = ureq::AgentBuilder::new()
            .redirects(0)
            .build()
            .get(&format!("{}/p/jira/@site.atlassian.net/redirect", e.base))
            .set("Authorization", &handle)
            .call();
        let (code, loc) = match r {
            Ok(resp) => (resp.status(), resp.header("location").map(str::to_string)),
            Err(ureq::Error::Status(c, resp)) => (c, resp.header("location").map(str::to_string)),
            Err(x) => panic!("{x}"),
        };
        println!("redirect: {code} {loc:?}");
        assert_eq!(e.seen(), before + 1, "followed the redirect");
    });
    e.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn each_new_policy_does_what_it_says() {
    let hosts = [
        "api.razorpay.com",
        "api.mailgun.net",
        "api.nexmo.com",
        "rest.nexmo.com",
        "api.cloudinary.com",
        "site.atlassian.net",
        "api.dataforseo.com",
    ];
    let e = setup(&hosts).await;
    blocking!({
        const Y: bool = true;
        const N: bool = false;
        type Row = (&'static str, &'static str, &'static str, &'static str, bool);
        let rows: &[Row] = &[
            ("razorpay", "read-only", "GET", "/v1/payments", Y),
            ("razorpay", "read-only", "POST", "/v1/orders", N),
            ("razorpay", "read-only", "DELETE", "/v1/x", N),
            ("razorpay", "orders", "POST", "/v1/orders", Y),
            ("razorpay", "orders", "GET", "/v1/orders/o1", Y),
            ("razorpay", "orders", "POST", "/v1/payments/p1/refund", N),
            ("razorpay", "orders", "POST", "/v1/payments/p1/refund/", N),
            ("razorpay", "orders", "POST", "/V1/PAYMENTS/p1/REFUND", N),
            ("razorpay", "orders", "POST", "/v1/payments/p1/%72efund", N),
            (
                "razorpay",
                "orders",
                "POST",
                "/v1/orders/../payments/p1/refund",
                N,
            ),
            (
                "razorpay",
                "orders",
                "POST",
                "/v1/orders/%2e%2e/payments/p1/refund",
                N,
            ),
            (
                "razorpay",
                "orders",
                "POST",
                "/v1/orders%2f..%2fpayments%2fp1%2frefund",
                N,
            ),
            ("razorpay", "orders", "POST", "//v1/payments/p1/refund", N),
            ("razorpay", "orders", "POST", "/v1/refunds", N),
            ("razorpay", "orders", "GET", "/v1/payouts/p", N),
            ("razorpay", "orders", "DELETE", "/v1/orders", N),
            ("mailgun", "read-only", "GET", "/v3/example.com/events", Y),
            ("mailgun", "read-only", "GET", "/v4/domains", N),
            ("mailgun", "read-only", "GET", "/v3/domains/example.com", N),
            ("mailgun", "read-only", "GET", "/x/../v1/keys", N),
            ("mailgun", "read-only", "GET", "/x/%2e%2e/v1/keys", N),
            ("mailgun", "read-only", "GET", "/x%2f..%2fv1/keys", N),
            ("mailgun", "read-only", "GET", "/v1\\keys", N),
            (
                "twilio",
                "read-only",
                "GET",
                "/2010-04-01/Accounts/AC1/Messages.json",
                Y,
            ),
            ("twilio", "read-only", "GET", "/2010-04-01/Accounts.json", N),
            (
                "twilio",
                "read-only",
                "GET",
                "/2010-04-01/Accounts/AC1.json",
                N,
            ),
            (
                "twilio",
                "read-only",
                "GET",
                "/2010-04-01/Accounts/AC1/Keys.json",
                N,
            ),
            (
                "twilio",
                "read-only",
                "GET",
                "/2010-04-01/Accounts/AC1/Keys/SK1.json",
                N,
            ),
            (
                "twilio",
                "messaging",
                "POST",
                "/2010-04-01/Accounts/AC1/Messages.json",
                Y,
            ),
            (
                "twilio",
                "messaging",
                "GET",
                "/2010-04-01/Accounts/AC1/Messages/SM1.json",
                Y,
            ),
            (
                "twilio",
                "messaging",
                "POST",
                "/2010-04-01/Accounts/AC1/Messages/SM1.json",
                Y,
            ),
            (
                "twilio",
                "messaging",
                "POST",
                "/2010-04-01/Accounts/AC1/Calls.json",
                N,
            ),
            (
                "twilio",
                "messaging",
                "GET",
                "/2010-04-01/Accounts/AC1/Calls.json",
                N,
            ),
            (
                "twilio",
                "messaging",
                "POST",
                "/2010-04-01/Accounts/AC1.json",
                N,
            ),
            (
                "twilio",
                "messaging",
                "POST",
                "/2010-04-01/Accounts/AC1/IncomingPhoneNumbers.json",
                N,
            ),
            (
                "jira",
                "read-only",
                "POST",
                "/rest/api/3/search/../issue",
                N,
            ),
            (
                "jira",
                "read-only",
                "POST",
                "/rest/api/3/search/%2e%2e/issue",
                N,
            ),
            ("mailgun", "read-only", "GET", "/v1/keys", N),
            ("mailgun", "read-only", "GET", "/v1/keys/k1", N),
            ("mailgun", "read-only", "GET", "/v1/keys/", N),
            ("mailgun", "read-only", "GET", "//v1/keys", N),
            ("mailgun", "read-only", "GET", "/v1/%6Beys", N),
            ("mailgun", "read-only", "GET", "/v1/KEYS", N),
            ("mailgun", "read-only", "POST", "/v3/d/messages", N),
            ("mailgun", "send", "POST", "/v3/example.com/messages", Y),
            (
                "mailgun",
                "send",
                "POST",
                "/v3/example.com/messages.mime",
                Y,
            ),
            ("mailgun", "send", "POST", "/v3/domains", N),
            ("mailgun", "send", "POST", "/v1/keys", N),
            ("mailgun", "send", "DELETE", "/v3/example.com/messages", N),
            ("vonage", "read-only", "GET", "/v2/reports", Y),
            ("vonage", "read-only", "GET", "/accounts/a/secrets", N),
            ("vonage", "messaging", "POST", "/v1/messages", Y),
            ("vonage", "messaging", "POST", "/sms/json", Y),
            ("vonage", "messaging", "POST", "/accounts/a/secrets", N),
            ("vonage", "messaging", "DELETE", "/accounts/a/secrets/s", N),
            (
                "cloudinary",
                "read-only",
                "GET",
                "/v1_1/c/resources/image",
                Y,
            ),
            ("cloudinary", "read-only", "POST", "/v1_1/c/image/upload", N),
            ("cloudinary", "upload", "POST", "/v1_1/c/image/upload", Y),
            (
                "cloudinary",
                "upload",
                "POST",
                "/v1_1/c/resources/image/upload",
                N,
            ),
            (
                "cloudinary",
                "upload",
                "DELETE",
                "/v1_1/c/resources/image",
                N,
            ),
            ("jira", "read-only", "GET", "/rest/api/3/myself", Y),
            ("jira", "read-only", "POST", "/rest/api/3/search/jql", Y),
            ("jira", "read-only", "POST", "/rest/api/3/issue", N),
            ("jira", "issues", "POST", "/rest/api/3/issue", Y),
            ("jira", "issues", "PUT", "/rest/api/3/issue/P-1", Y),
            ("jira", "issues", "POST", "/rest/api/3/issue/P-1/comment", Y),
            (
                "jira",
                "issues",
                "POST",
                "/rest/api/3/issue/P-1/transitions",
                Y,
            ),
            ("jira", "issues", "DELETE", "/rest/api/3/issue/P-1", N),
            ("jira", "issues", "POST", "/rest/api/3/project", N),
            ("jira", "issues", "PUT", "/rest/api/3/user", N),
            (
                "dataforseo",
                "read-only",
                "GET",
                "/v3/appendix/user_data",
                Y,
            ),
            (
                "dataforseo",
                "read-only",
                "POST",
                "/v3/serp/google/organic/live/advanced",
                N,
            ),
        ];
        let mut handles: BTreeMap<String, String> = BTreeMap::new();
        let mut wrong = 0;
        for (provider, policy, method, path, expect) in rows {
            let key = format!("{provider}:{policy}");
            if !handles.contains_key(&key) {
                let name = provider.to_string();
                if e.mgmt("GET", &format!("/v1/secrets/{name}"), None).0 != 200 {
                    let value = if *provider == "mailgun" {
                        "mailgun-key-abcdefghijklmnop".to_string()
                    } else if *provider == "twilio" {
                        format!("{SID}:{TOKEN}")
                    } else {
                        format!("{provider}user:{provider}-password-abcdef")
                    };
                    e.add(json!({ "name": name, "value": value, "provider": provider }));
                }
                let h = e.handle(&name, Some(&key));
                handles.insert(key.clone(), format!("Bearer {h}"));
            }
            let site = if *provider == "jira" {
                "@site.atlassian.net"
            } else {
                ""
            };
            let target = if site.is_empty() {
                format!("/p/{provider}{path}")
            } else {
                format!("/p/{provider}/{site}{path}")
            };
            let before = e.seen();
            let code = e.raw(method, &target, &handles[&key]);
            let reached = e.seen() > before;
            let flag = if reached != *expect {
                wrong += 1;
                "WRONG"
            } else {
                "ok"
            };
            let last = if reached {
                e.mock
                    .seen
                    .lock()
                    .unwrap()
                    .last()
                    .map(|s| s.0.clone())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            println!("{flag:<6}{key:<24}{method:<7}{path:<46}{code} {last}");
        }
        println!("policy rows: {}, wrong: {wrong}", rows.len());
        assert_eq!(wrong, 0);
    });
    e.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn ai_tools_in_parallel() {
    let e = setup(&[]).await;
    blocking!({
        e.add(json!({ "name": "twilio", "value": format!("{SID}:{TOKEN}") }));
        let (code, c) = e.mgmt("POST", "/v1/callers", Some(json!({ "name": "stress" })));
        assert_eq!(code, 201, "{c}");
        let token = c["token"].as_str().unwrap().to_string();
        let url = format!("{}/mcp", e.base);
        let want_echo = basic(&format!("{SID}:{TOKEN}"));
        let mut t = callers(
            24,
            60,
            |agent, _, i| {
                let (name, args) = if i % 2 == 0 {
                    ("list_secrets", json!({}))
                } else {
                    (
                        "call_api",
                        json!({ "secret": "twilio", "method": "GET", "path": "/2010-04-01/Accounts/AC1/Messages.json" }),
                    )
                };
                outcome(
                    agent
                        .post(&url)
                        .set("Authorization", &format!("Bearer {token}"))
                        .set("Content-Type", "application/json")
                        .send_string(
                            &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": name, "arguments": args } }).to_string(),
                        ),
                )
            },
            |code, body| {
                assert_eq!(code, 200, "{body}");
                assert!(!body.contains(TOKEN), "{body}");
                assert!(!body.contains(&want_echo[6..]), "{body}");
                assert!(!body.contains("\"isError\":true"), "{body}");
            },
        );
        t.print("AI tool calls, 24 clients");
        assert!(e.seen() > 0);
        let (_, body) = outcome(
            e.agent
                .post(&url)
                .set("Authorization", &format!("Bearer {token}"))
                .set("Content-Type", "application/json")
                .send_string(
                    &json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "list_secrets", "arguments": {} } }).to_string(),
                ),
        );
        assert!(body.contains(SID), "the account is shown: {body}");
    });
    e.daemon.shutdown().await;
}

fn working_set_mb() -> f64 {
    let pid = std::process::id();
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-Process -Id {pid}).WorkingSet64"),
        ])
        .output();
    out.ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<f64>()
                .ok()
        })
        .unwrap_or(0.0)
        / 1_048_576.0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore]
async fn a_long_mixed_run() {
    let e = setup(&[]).await;
    blocking!({
        e.add(json!({ "name": "twilio", "value": format!("{SID}:{TOKEN}") }));
        e.add(json!({
            "name": "gsc", "value": key_file(&format!("https://{AUTH}/token")),
            "upstreams": [API], "fields": { "scope": "s.one" }
        }));
        let (ht, hg) = (
            format!("Bearer {}", e.handle("twilio", Some("twilio:full"))),
            format!("Bearer {}", e.handle("gsc", None)),
        );
        let (ut, ug) = (
            format!("{}/p/twilio/2010-04-01/Accounts.json", e.base),
            format!("{}/p/generic/@{API}/v1/things", e.base),
        );
        e.mock.quiet.store(true, Ordering::SeqCst);
        let minutes: u64 = std::env::var("USK_STRESS_MINUTES")
            .ok()
            .and_then(|m| m.parse().ok())
            .unwrap_or(5);
        let windows = minutes * 2;
        let db = e._dir.path().join("vault.db");
        for w in 0..windows {
            let until = Instant::now() + Duration::from_secs(30);
            let start = Barrier::new(16);
            let mut micros: Vec<u128> = Vec::new();
            let mut bad = 0usize;
            std::thread::scope(|sc| {
                let workers: Vec<_> = (0..16)
                    .map(|tid| {
                        let (ut, ug, ht, hg, start) = (&ut, &ug, &ht, &hg, &start);
                        sc.spawn(move || {
                            let agent = ureq::AgentBuilder::new()
                                .timeout_read(Duration::from_secs(60))
                                .build();
                            start.wait();
                            let (mut m, mut b) = (Vec::new(), 0usize);
                            while Instant::now() < until {
                                let (u, h) = if tid % 2 == 0 { (ut, ht) } else { (ug, hg) };
                                let t0 = Instant::now();
                                let (code, _) =
                                    outcome(agent.get(u).set("Authorization", h).call());
                                m.push(t0.elapsed().as_micros());
                                if code != 200 {
                                    b += 1;
                                }
                            }
                            (m, b)
                        })
                    })
                    .collect();
                for w in workers {
                    let (m, b) = w.join().unwrap();
                    micros.extend(m);
                    bad += b;
                }
            });
            micros.sort_unstable();
            let p = |q: f64| micros[((micros.len() as f64 - 1.0) * q) as usize] as f64 / 1000.0;
            println!(
                "window {w:>2}: {:>6} calls ({:>5.0}/s), bad {bad}, p50 {:>6.1} ms, p99 {:>7.1} ms, memory {:>6.0} MB, vault {:>6.1} MB",
                micros.len(),
                micros.len() as f64 / 30.0,
                p(0.5),
                p(0.99),
                working_set_mb(),
                std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0) as f64 / 1_048_576.0,
            );
            assert_eq!(bad, 0);
        }
        let (code, v) = e.mgmt("GET", "/v1/audit/verify", None);
        println!("audit chain after the run: {code} {v}");
        assert_eq!(v["ok"], true, "{v}");
    });
    e.daemon.shutdown().await;
}
