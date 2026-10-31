//! AWS through the broker. The SDK's SigV4 header carries the handle and the
//! region/service scope; the broker throws that signature away and signs again
//! with the real key. A capturing mock stands in for AWS, and each test
//! re-derives the signature from exactly what the mock received.

use axum::extract::{Request, State};
use axum::routing::any;
use axum::Router;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use unseenkey_core::broker::sigv4;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, Running, ServeOptions};

const PW: &str = "aws-test-password";
const AKID: &str = "AKIAIOSFODNN7EXAMPLE";
const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const TOKEN: &str = "FwoGZXIvYXdzEXAMPLEtokenEXAMPLEtokenEXAMPLEtoken0123456789abcdef";
const HOSTS: &[&str] = &[
    "s3.us-east-1.amazonaws.com",
    "dynamodb.eu-west-1.amazonaws.com",
    "bedrock-runtime.us-east-1.amazonaws.com",
    "sts.amazonaws.com",
    "sqs.us-east-2.amazonaws.com",
];

#[derive(Clone, Debug)]
struct Captured {
    method: String,
    path: String,
    query: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    fn authz_part(&self, key: &str) -> String {
        let authz = self.header("authorization").expect("authorization header");
        authz
            .split([',', ' '])
            .find_map(|p| p.trim().strip_prefix(key))
            .unwrap_or_else(|| panic!("{key} missing in {authz}"))
            .to_string()
    }
    /// Re-derive the signature from what arrived, with the real secret, for the
    /// host the broker believed it was talking to.
    fn assert_signed_for(&self, host: &str, region: &str, service: &str, secret: &str) {
        assert!(self
            .header("authorization")
            .unwrap()
            .starts_with("AWS4-HMAC-SHA256 Credential="));
        let cred = self.authz_part("Credential=");
        let mut scope = cred.split('/');
        let akid = scope.next().unwrap();
        let date = scope.next().unwrap();
        assert_eq!(scope.next(), Some(region), "{cred}");
        assert_eq!(scope.next(), Some(service), "{cred}");
        assert_eq!(scope.next(), Some("aws4_request"));
        let amz_date = self.header("x-amz-date").expect("x-amz-date");
        assert!(amz_date.starts_with(date));
        let payload = self.header("x-amz-content-sha256").expect("payload hash");
        assert_eq!(payload, sigv4::payload_hash(&self.body), "body hash");
        let signed_headers = self.authz_part("SignedHeaders=");
        for must in ["host", "x-amz-date", "x-amz-content-sha256"] {
            assert!(
                signed_headers.split(';').any(|h| h == must),
                "{must} not signed"
            );
        }
        // Every x-amz-* header that arrived must be covered by the signature.
        for (name, _) in &self.headers {
            if name.starts_with("x-amz-") {
                assert!(
                    signed_headers.split(';').any(|h| h == name),
                    "{name} not signed"
                );
            }
        }
        let headers: Vec<(String, String)> = signed_headers
            .split(';')
            .flat_map(|name| {
                if name == "host" {
                    vec![("host".to_string(), host.to_string())]
                } else {
                    self.headers
                        .iter()
                        .filter(|(k, _)| k == name)
                        .cloned()
                        .collect()
                }
            })
            .collect();
        let secret = SecretBytes::from(secret);
        let expected = sigv4::sign(
            &sigv4::Credentials {
                access_key_id: akid,
                secret_access_key: &secret,
                session_token: None,
            },
            region,
            service,
            amz_date,
            &sigv4::Request {
                method: &self.method,
                path: &self.path,
                query: self.query.as_deref(),
                headers: &headers,
                payload_hash: payload,
            },
        );
        assert_eq!(self.authz_part("Signature="), expected.signature);
    }
}

type Seen = Arc<Mutex<Vec<Captured>>>;

async fn capture(
    State(seen): State<Seen>,
    req: Request,
) -> ([(&'static str, &'static str); 1], &'static str) {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, 1 << 20)
        .await
        .unwrap_or_default();
    seen.lock().unwrap().push(Captured {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().map(str::to_string),
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect(),
        body: body.to_vec(),
    });
    ([("content-type", "application/json")], "{\"ok\":true}")
}

struct T {
    daemon: Running,
    base: String,
    token: String,
    owner: std::sync::Mutex<Option<String>>,
    agent: ureq::Agent,
    seen: Seen,
}

fn outcome(r: Result<ureq::Response, ureq::Error>) -> (u16, Value) {
    match r {
        Ok(resp) => {
            let code = resp.status();
            (code, resp.into_json().unwrap_or(Value::Null))
        }
        Err(ureq::Error::Status(code, resp)) => (code, resp.into_json().unwrap_or(Value::Null)),
        Err(e) => panic!("transport: {e}"),
    }
}

/// The header an AWS SDK would send, signed with its placeholder secret.
fn sdk_auth(handle: &str, region: &str, service: &str) -> String {
    format!(
        "AWS4-HMAC-SHA256 Credential={handle}/20260101/{region}/{service}/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={}",
        "ab".repeat(32)
    )
}

impl T {
    fn mgmt(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut req = self
            .agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {}", self.token));
        if let Some(o) = self.owner.lock().unwrap().as_ref() {
            req = req.set("X-Usk-Owner", o);
        }
        let (code, v) = outcome(match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        });
        if code == 200 && path == "/v1/unlock" {
            *self.owner.lock().unwrap() = v["owner_token"].as_str().map(str::to_string);
        }
        (code, v)
    }
    fn aws(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> (u16, Value) {
        let mut req = self
            .agent
            .request(method, &format!("{}/p/aws{}", self.base, path));
        for (k, v) in headers {
            req = req.set(k, v);
        }
        outcome(req.send_bytes(body))
    }
    fn last(&self) -> Captured {
        self.seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a captured request")
    }
    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
    fn handle(&self, secret: &str, label: &str, policy: &str) -> (String, Value) {
        let (code, h) = self.mgmt(
            "POST",
            "/v1/handles",
            Some(json!({ "secret": secret, "label": label, "preset_policy": policy })),
        );
        assert_eq!(code, 201, "{h}");
        (h["handle"].as_str().unwrap().to_string(), h)
    }
}

async fn setup() -> T {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    std::mem::forget(dir);
    drop(
        Vault::create(
            SqliteStorage::open(&path).unwrap(),
            SystemClock,
            &SecretBytes::from(PW),
            Argon2Profile::MINIMUM,
        )
        .unwrap(),
    );
    let seen: Seen = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock: SocketAddr = listener.local_addr().unwrap();
    let app = Router::new()
        .fallback(any(capture))
        .with_state(seen.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let daemon = serve(ServeOptions {
        vault_path: path,
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: false,
        upstream_overrides: HOSTS
            .iter()
            .map(|h| (h.to_string(), format!("http://{mock}")))
            .collect(),
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap();
    let t = T {
        base: format!("http://{}", daemon.addr),
        token: daemon.token().to_string(),
        owner: std::sync::Mutex::new(None),
        agent: ureq::AgentBuilder::new()
            .max_idle_connections(0)
            .timeout_read(Duration::from_secs(20))
            .timeout_write(Duration::from_secs(20))
            .redirects(0)
            .build(),
        daemon,
        seen,
    };
    assert_eq!(
        t.mgmt("POST", "/v1/unlock", Some(json!({ "password": PW })))
            .0,
        200
    );
    t
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credentials_are_stored_in_one_shape_whatever_was_pasted() {
    let t = setup().await;
    // A key id alone is refused with an explanation.
    let (code, body) = t.mgmt(
        "POST",
        "/v1/secrets",
        Some(json!({ "name": "half", "value": AKID })),
    );
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["error"], "aws_credentials_incomplete");
    // Two pasted lines.
    let (code, c) = t.mgmt(
        "POST",
        "/v1/secrets",
        Some(json!({ "name": "aws-lines", "value": format!("{AKID}\n{SECRET}\n") })),
    );
    assert_eq!(code, 201, "{c}");
    assert_eq!(c["type"], "aws_credentials");
    assert_eq!(c["provider"], "aws");
    assert_eq!(c["upstreams"], json!(["*.amazonaws.com"]));
    // A credentials-file section with a session token.
    let ini = format!("[dev]\naws_access_key_id={AKID}\naws_secret_access_key={SECRET}\naws_session_token={TOKEN}\n");
    assert_eq!(
        t.mgmt(
            "POST",
            "/v1/secrets",
            Some(json!({ "name": "aws-ini", "value": ini }))
        )
        .0,
        201
    );
    // The CLI's shape: secret as the value, key id as a field.
    let (code, c) = t.mgmt(
        "POST",
        "/v1/secrets",
        Some(json!({ "name": "aws-fields", "type": "aws_credentials", "value": SECRET, "fields": { "access_key_id": AKID } })),
    );
    assert_eq!(code, 201, "{c}");
    assert_eq!(c["provider"], "aws");
    // All three reveal to the same layout.
    for (name, token) in [
        ("aws-lines", None),
        ("aws-ini", Some(TOKEN)),
        ("aws-fields", None),
    ] {
        let (code, r) = t.mgmt(
            "POST",
            &format!("/v1/secrets/{name}/reveal"),
            Some(json!({ "confirm": true })),
        );
        assert_eq!(code, 200, "{r}");
        assert_eq!(r["value"], SECRET, "{name}");
        assert_eq!(r["fields"]["access_key_id"], AKID, "{name}");
        assert_eq!(r["fields"]["session_token"].as_str(), token, "{name}");
    }
    // The environment for an SDK: endpoint, handle as the key id, a placeholder secret.
    let (handle, h) = t.handle("aws-lines", "sdk", "aws:full");
    assert_eq!(h["env"]["AWS_ENDPOINT_URL"], format!("{}/p/aws", t.base));
    assert_eq!(h["env"]["AWS_ACCESS_KEY_ID"], handle);
    let placeholder = h["env"]["AWS_SECRET_ACCESS_KEY"].as_str().unwrap();
    assert!(!placeholder.is_empty() && placeholder != SECRET);
    t.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sdk_requests_are_signed_again_with_the_real_key() {
    let t = setup().await;
    assert_eq!(
        t.mgmt(
            "POST",
            "/v1/secrets",
            Some(json!({ "name": "aws", "value": format!("{AKID}\n{SECRET}") }))
        )
        .0,
        201
    );
    let (handle, _) = t.handle("aws", "sdk", "aws:full");
    let empty = sigv4::payload_hash(b"");
    let sdk = |region: &str, service: &str| sdk_auth(&handle, region, service);

    // S3 GET: the endpoint comes from the scope; path and query pass through.
    let (code, body) = t.aws(
        "GET",
        "/my-bucket/photos/a%20b.jpg?versionId=3&x-id=GetObject",
        &[
            ("authorization", &sdk("us-east-1", "s3")),
            ("x-amz-date", "20260101T000000Z"),
            ("x-amz-content-sha256", &empty),
            ("x-amz-security-token", "client-side-token-must-not-pass"),
        ],
        b"",
    );
    assert_eq!(code, 200, "{body}");
    let c = t.last();
    assert_eq!(c.path, "/my-bucket/photos/a%20b.jpg");
    assert_eq!(c.query.as_deref(), Some("versionId=3&x-id=GetObject"));
    assert!(c.authz_part("Credential=").starts_with(&format!("{AKID}/")));
    assert_ne!(
        c.header("x-amz-date"),
        Some("20260101T000000Z"),
        "the broker signs with its own clock"
    );
    assert_eq!(c.header("x-amz-security-token"), None);
    assert!(
        !format!("{c:?}").contains(&handle),
        "the handle must not travel upstream"
    );
    c.assert_signed_for("s3.us-east-1.amazonaws.com", "us-east-1", "s3", SECRET);

    // DynamoDB: JSON protocol, the target header is signed and audited.
    let item = br#"{"TableName":"users","Key":{"id":{"S":"42"}}}"#;
    let (code, _) = t.aws(
        "POST",
        "/",
        &[
            ("authorization", &sdk("eu-west-1", "dynamodb")),
            ("content-type", "application/x-amz-json-1.0"),
            ("x-amz-target", "DynamoDB_20120810.GetItem"),
        ],
        item,
    );
    assert_eq!(code, 200);
    let c = t.last();
    assert_eq!(c.body, item);
    let signed = c.authz_part("SignedHeaders=");
    assert!(
        signed.contains("content-type") && signed.contains("x-amz-target"),
        "{signed}"
    );
    c.assert_signed_for(
        "dynamodb.eu-west-1.amazonaws.com",
        "eu-west-1",
        "dynamodb",
        SECRET,
    );

    // Query protocol with sloppy encoding: tidied, then signed as sent.
    let (code, _) = t.aws(
        "GET",
        "/123456789012/my%20queue?Action=SendMessage&MessageBody=hello+world&Version=2012-11-05",
        &[("authorization", &sdk("us-east-2", "sqs"))],
        b"",
    );
    assert_eq!(code, 200);
    let c = t.last();
    assert_eq!(
        c.query.as_deref(),
        Some("Action=SendMessage&MessageBody=hello%2Bworld&Version=2012-11-05")
    );
    c.assert_signed_for("sqs.us-east-2.amazonaws.com", "us-east-2", "sqs", SECRET);

    // A streaming upload: aws-chunked framing is undone, the trailing checksum
    // becomes a signed header, and the plain payload is hashed exactly.
    let chunked = b"b;chunk-signature=aaaa\r\nhello world\r\n0;chunk-signature=bbbb\r\nx-amz-checksum-crc32:DUoRhQ==\r\nx-amz-trailer-signature:cccc\r\n\r\n";
    let (code, body) = t.aws(
        "PUT",
        "/my-bucket/hello.txt",
        &[
            ("authorization", &sdk("us-east-1", "s3")),
            ("content-encoding", "aws-chunked"),
            (
                "x-amz-content-sha256",
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            ),
            ("x-amz-trailer", "x-amz-checksum-crc32"),
            ("x-amz-decoded-content-length", "11"),
            ("x-amz-sdk-checksum-algorithm", "CRC32"),
            ("content-type", "text/plain"),
        ],
        chunked,
    );
    assert_eq!(code, 200, "{body}");
    let c = t.last();
    assert_eq!(c.body, b"hello world");
    assert_eq!(c.header("content-length"), Some("11"));
    assert_eq!(c.header("x-amz-checksum-crc32"), Some("DUoRhQ=="));
    assert_eq!(c.header("content-encoding"), None);
    assert_eq!(c.header("x-amz-trailer"), None);
    assert_eq!(c.header("x-amz-decoded-content-length"), None);
    c.assert_signed_for("s3.us-east-1.amazonaws.com", "us-east-1", "s3", SECRET);
    // Broken framing is refused, not forwarded.
    let before = t.count();
    let (code, body) = t.aws(
        "PUT",
        "/my-bucket/bad",
        &[
            ("authorization", &sdk("us-east-1", "s3")),
            ("content-encoding", "aws-chunked"),
        ],
        b"zz\r\nnope",
    );
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["error"], "malformed_request");
    assert_eq!(t.count(), before);

    // Bedrock's signing name covers several endpoints: the host must be named.
    let (code, body) = t.aws(
        "POST",
        "/model/x/invoke",
        &[("authorization", &sdk("us-east-1", "bedrock"))],
        b"{}",
    );
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["error"], "aws_host_required");
    let (code, _) = t.aws(
        "POST",
        "/@bedrock-runtime.us-east-1.amazonaws.com/model/x/invoke",
        &[
            ("authorization", &sdk("us-east-1", "bedrock")),
            ("content-type", "application/json"),
        ],
        b"{}",
    );
    assert_eq!(code, 200);
    let c = t.last();
    assert_eq!(c.path, "/model/x/invoke");
    c.assert_signed_for(
        "bedrock-runtime.us-east-1.amazonaws.com",
        "us-east-1",
        "bedrock",
        SECRET,
    );

    // No SDK at all (curl, an agent): handle in a header, host in the URL,
    // scope worked out from the host.
    let (code, _) = t.aws(
        "POST",
        "/@sts.amazonaws.com/",
        &[
            ("x-usk-handle", &handle),
            (
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            ),
        ],
        b"Action=GetCallerIdentity&Version=2011-06-15",
    );
    assert_eq!(code, 200);
    t.last()
        .assert_signed_for("sts.amazonaws.com", "us-east-1", "sts", SECRET);

    // The audit log says what was done, not just "POST /".
    let (_, events) = t.mgmt("GET", "/v1/audit?since=1&kind=use&limit=100", None);
    let events = events.as_array().unwrap();
    let find = |aws: &str| {
        events
            .iter()
            .find(|e| e["body"]["aws"] == aws)
            .unwrap_or_else(|| panic!("no audit event for {aws}"))
    };
    assert_eq!(
        find("dynamodb/eu-west-1")["body"]["action"],
        "DynamoDB_20120810.GetItem"
    );
    assert_eq!(find("sqs/us-east-2")["body"]["action"], "SendMessage");
    assert_eq!(find("sts/us-east-1")["body"]["action"], "GetCallerIdentity");
    assert!(find("s3/us-east-1")["body"]["action"].is_null());

    // Refusals.
    let (code, body) = t.aws(
        "GET",
        "/b/k",
        &[(
            "authorization",
            &sdk_auth("usk_h_00000000000000000000000000000000", "us-east-1", "s3"),
        )],
        b"",
    );
    assert_eq!(code, 401, "{body}");
    let (code, body) = t.aws(
        "GET",
        "/b/k",
        &[("authorization", &format!("AWS4-ECDSA-P256-SHA256 Credential={handle}/20260101/s3/aws4_request, SignedHeaders=host, Signature=00"))],
        b"",
    );
    assert_eq!(code, 400, "{body}");
    assert_eq!(body["error"], "sigv4a_unsupported");
    // The host lock still decides where the key may go.
    let (code, body) = t.aws(
        "GET",
        "/@evil.example/b/k",
        &[("authorization", &sdk("us-east-1", "s3"))],
        b"",
    );
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "host_not_allowed");
    t.daemon.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_tokens_and_narrowed_policies() {
    let t = setup().await;
    let (code, c) = t.mgmt(
        "POST",
        "/v1/secrets",
        Some(json!({ "name": "aws-temp", "value": format!("{AKID}\n{SECRET}\n{TOKEN}") })),
    );
    assert_eq!(code, 201, "{c}");
    let (full, _) = t.handle("aws-temp", "full", "aws:full");
    let (read_only, _) = t.handle("aws-temp", "ro", "aws:s3-read-only");

    // Temporary credentials: the stored token is sent and signed.
    let (code, _) = t.aws(
        "GET",
        "/b/k",
        &[("authorization", &sdk_auth(&full, "us-east-1", "s3"))],
        b"",
    );
    assert_eq!(code, 200);
    let c = t.last();
    assert_eq!(c.header("x-amz-security-token"), Some(TOKEN));
    assert!(c
        .authz_part("SignedHeaders=")
        .contains("x-amz-security-token"));
    c.assert_signed_for("s3.us-east-1.amazonaws.com", "us-east-1", "s3", SECRET);

    // The S3 read-only policy: S3 GET passes, S3 PUT and every other service do not.
    let before = t.count();
    assert_eq!(
        t.aws(
            "GET",
            "/b/k",
            &[("authorization", &sdk_auth(&read_only, "us-east-1", "s3"))],
            b""
        )
        .0,
        200
    );
    assert_eq!(t.count(), before + 1);
    let (code, body) = t.aws(
        "PUT",
        "/b/k",
        &[("authorization", &sdk_auth(&read_only, "us-east-1", "s3"))],
        b"x",
    );
    assert_eq!(code, 403, "{body}");
    let (code, body) = t.aws(
        "GET",
        "/?Action=ListQueues",
        &[("authorization", &sdk_auth(&read_only, "us-east-2", "sqs"))],
        b"",
    );
    assert_eq!(code, 403, "{body}");
    assert_eq!(body["error"], "host_not_allowed");
    assert_eq!(
        t.count(),
        before + 1,
        "nothing refused reached the upstream"
    );
    t.daemon.shutdown().await;
}
