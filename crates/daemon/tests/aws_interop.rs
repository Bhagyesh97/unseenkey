//! Interoperability with the real AWS SDK, verified by AWS's own signer.
//!
//! ```text
//! boto3 (handle + placeholder secret) ──▶ broker ──▶ verify_server.py (botocore)
//! ```
//!
//! boto3 is configured with the three environment variables `usk env aws`
//! prints. The broker signs each request again with the real key. The stand-in
//! for AWS recomputes every signature with botocore from what it received and
//! answers 403 when one does not match, exactly like AWS.
//!
//! Needs Python with `boto3`, so it is ignored by default:
//!
//! ```text
//! pip install boto3
//! USK_TEST_PYTHON=python cargo test -p unseenkey-daemon --test aws_interop -- --ignored --nocapture
//! ```

use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, ServeOptions};

const PW: &str = "aws-interop-password";
const AKID: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const HOSTS: &[&str] = &[
    "s3.us-east-1.amazonaws.com",
    "dynamodb.eu-west-1.amazonaws.com",
    "sts.ap-south-1.amazonaws.com",
];

fn python() -> String {
    std::env::var("USK_TEST_PYTHON").unwrap_or_else(|_| "python3".into())
}

fn script(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("aws_interop")
        .join(name)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs Python with boto3; see the module docs"]
async fn boto3_through_the_broker_verifies_with_botocore() {
    // 1. The stand-in for AWS.
    let mut verifier = Command::new(python())
        .arg(script("verify_server.py"))
        .args([AKID, SECRET])
        .args(HOSTS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start verify_server.py (set USK_TEST_PYTHON to a Python with boto3)");
    let mut line = String::new();
    BufReader::new(verifier.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let ports: Value = serde_json::from_str(&line).expect("port map from verify_server.py");

    // 2. Vault, daemon (AWS hosts redirected to the stand-in), secret, handle.
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
    let daemon = serve(ServeOptions {
        vault_path: path,
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: false,
        upstream_overrides: HOSTS
            .iter()
            .map(|h| (h.to_string(), format!("http://127.0.0.1:{}", ports[h])))
            .collect(),
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap();
    let base = format!("http://{}", daemon.addr);
    let token = daemon.token().to_string();
    let agent = ureq::AgentBuilder::new()
        .max_idle_connections(0)
        .timeout(Duration::from_secs(20))
        .build();
    // The owner token from the unlock, as the CLI and app send it: naming a
    // policy for a handle is owner-only.
    let owner = std::cell::RefCell::new(None::<String>);
    let mgmt = |path: &str, body: Value| -> Value {
        let mut req = agent
            .post(&format!("{base}{path}"))
            .set("Authorization", &format!("Bearer {token}"));
        if let Some(o) = owner.borrow().as_ref() {
            req = req.set("X-Usk-Owner", o);
        }
        let v: Value = req
            .send_json(body)
            .unwrap_or_else(|e| panic!("{path}: {e}"))
            .into_json()
            .unwrap();
        if path == "/v1/unlock" {
            *owner.borrow_mut() = v["owner_token"].as_str().map(str::to_string);
        }
        v
    };
    mgmt("/v1/unlock", json!({ "password": PW }));
    mgmt(
        "/v1/secrets",
        json!({ "name": "aws", "value": format!("{AKID}\n{SECRET}") }),
    );
    let handle = mgmt(
        "/v1/handles",
        json!({ "secret": "aws", "label": "boto3", "preset_policy": "aws:full" }),
    );
    let env = handle["env"].as_object().expect("env for the SDK").clone();
    assert!(env.contains_key("AWS_ENDPOINT_URL") && env.contains_key("AWS_ACCESS_KEY_ID"));

    // 3. The real SDK, configured only through that environment.
    let mut client = Command::new(python());
    client
        .arg(script("client.py"))
        .env_remove("AWS_PROFILE")
        .env_remove("AWS_SESSION_TOKEN")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .env("AWS_CONFIG_FILE", dir.path().join("no-config"))
        .env(
            "AWS_SHARED_CREDENTIALS_FILE",
            dir.path().join("no-credentials"),
        )
        .env("PYTHONIOENCODING", "utf-8");
    for (k, v) in &env {
        client.env(k, v.as_str().unwrap());
    }
    let out = tokio::task::spawn_blocking(move || client.output().expect("run client.py"))
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // 4. What the stand-in saw.
    let stats: Value = agent
        .get(&format!("http://127.0.0.1:{}/__stats", ports[HOSTS[0]]))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    println!(
        "client: {stdout}\nverifier: ok={} failed={}",
        stats["ok"], stats["failed"]
    );
    for r in stats["requests"].as_array().unwrap() {
        println!(
            "  {} {} {}{} ({} bytes) {}",
            r["service"].as_str().unwrap(),
            r["method"].as_str().unwrap(),
            r["host"].as_str().unwrap(),
            r["path"].as_str().unwrap(),
            r["body_len"],
            if r["problem"].is_null() {
                "verified"
            } else {
                "REJECTED"
            }
        );
    }
    assert!(
        out.status.success(),
        "boto3 failed:\n{stderr}\nverifier: {}",
        stats["failed"]
    );
    assert_eq!(stats["failed"], json!([]), "signatures botocore rejected");
    assert_eq!(
        stats["ok"], 7,
        "every SDK call must have reached the stand-in and verified"
    );
    let result: Value = serde_json::from_str(stdout.trim().lines().last().unwrap()).unwrap();
    assert_eq!(result["s3_list"], json!(["reports/q3 summary.txt"]));
    assert_eq!(result["dynamodb_item"], "Ada");
    assert_eq!(result["sts_account"], "123456789012");
    assert!(result["s3_get"]
        .as_str()
        .unwrap()
        .starts_with("contents of /demo-bucket/reports/"));
    // The handle never went upstream, and the audit log names the actions.
    assert!(!stats
        .to_string()
        .contains(handle["handle"].as_str().unwrap()));
    let audit: Value = agent
        .get(&format!("{base}/v1/audit?since=1&kind=use&limit=100"))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    let actions: Vec<String> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            format!(
                "{} {}",
                e["body"]["aws"].as_str().unwrap_or("?"),
                e["body"]["action"].as_str().unwrap_or("-")
            )
        })
        .collect();
    assert!(
        actions.contains(&"dynamodb/eu-west-1 DynamoDB_20120810.GetItem".to_string()),
        "{actions:?}"
    );
    assert!(
        actions.contains(&"sts/ap-south-1 GetCallerIdentity".to_string()),
        "{actions:?}"
    );

    drop(verifier.stdin.take());
    let _ = verifier.wait();
    daemon.shutdown().await;
}
