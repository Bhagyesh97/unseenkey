//! End-to-end smoke test of the `usk` binary, including the auto-started daemon.
//!
//! Each test uses its own temp directory and an ephemeral daemon port
//! (`USK_LISTEN=127.0.0.1:0`), so tests can run in parallel.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn usk(vault: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_usk"))
        .arg("--vault")
        .arg(vault)
        .args(args)
        .env("USK_LISTEN", "127.0.0.1:0")
        .env("USK_IDLE_LOCK_MINUTES", "0")
        // Made-up keys must never reach a real provider.
        .env("USK_NO_KEY_TEST", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn usk");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

const PW: &str = "a-long-enough-password\n";

struct StopDaemon<'a>(&'a Path);
impl Drop for StopDaemon<'_> {
    fn drop(&mut self) {
        // On a failure, the daemon's own log is the only evidence of what it did.
        if std::thread::panicking() {
            let log = self.0.parent().unwrap().join("logs").join("uskd.log");
            eprintln!("--- {} ---", log.display());
            eprintln!("{}", std::fs::read_to_string(&log).unwrap_or_default());
        }
        let _ = usk(self.0, &["daemon", "stop"], "");
    }
}

#[test]
fn init_add_ls_reveal_rm_with_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);

    let o = usk(&vault, &["init", "--profile", "light"], PW);
    assert!(o.status.success(), "{}", err(&o));
    let text = out(&o);
    assert!(text.contains("RECOVERY PHRASE"));
    let words: Vec<&str> = text
        .lines()
        .filter(|l| {
            l.trim_start()
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
                && l.contains(". ")
        })
        .flat_map(|l| {
            l.split_whitespace()
                .filter(|w| !w.ends_with('.'))
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(words.len(), 24, "{text}");

    // First command starts the daemon and unlocks it (password on stdin line 1).
    let value = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
    let o = usk(
        &vault,
        &["add", "openai", "--stdin"],
        &format!("{PW}{value}\n"),
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("Detected: OpenAI"), "{}", out(&o));
    assert!(out(&o).contains("api.openai.com"));
    assert!(!out(&o).contains(value), "add must not echo the value");
    assert!(dir.path().join("daemon.token").exists());

    // Daemon is now unlocked: no password needed.
    let o = usk(&vault, &["ls"], "");
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("openai"));
    assert!(!out(&o).contains(value));

    let o = usk(&vault, &["--json", "show", "openai"], "");
    assert!(o.status.success(), "{}", err(&o));
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(j["provider"], "openai");
    assert_eq!(j["kind"], "api_key");

    let o = usk(&vault, &["reveal", "openai"], "");
    assert!(!o.status.success(), "reveal without --yes must fail");
    let o = usk(&vault, &["reveal", "openai", "--yes"], PW);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o).trim(), value);

    let o = usk(&vault, &["daemon", "status"], "");
    assert!(out(&o).contains("running"), "{}", out(&o));

    // Lock, then a wrong password exits 3.
    let o = usk(&vault, &["lock"], "");
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["ls"], "wrong-password\n");
    assert_eq!(o.status.code(), Some(3), "{}", err(&o));

    let o = usk(&vault, &["rm", "openai", "--yes"], PW);
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["ls"], "");
    assert!(out(&o).contains("No secrets yet"));

    // Recovery while the daemon runs: it locks the daemon, rewrites the header,
    // and the daemon picks up the new password on the next unlock.
    let phrase = words.join(" ");
    let o = usk(
        &vault,
        &["recover", "--profile", "light"],
        &format!("{phrase}\nbrand-new-password-123\n"),
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["ls"], "brand-new-password-123\n");
    assert!(o.status.success(), "{}", err(&o));

    let o = usk(&vault, &["doctor"], "");
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(out(&o).contains("All checks passed"));

    // Handles, env snippets and the audit log.
    let o = usk(
        &vault,
        &["add", "stripe", "--stdin"],
        "sk_test_51Habcdefghijklmnop\n",
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(
        &vault,
        &[
            "handle", "create", "stripe", "--label", "dev", "--policy", "payments",
        ],
        "brand-new-password-123\n",
    );
    assert!(o.status.success(), "{}", err(&o));
    let t = out(&o);
    assert!(t.contains("usk_h_"), "{t}");
    assert!(t.contains("Cannot"), "policy explanation expected: {t}");
    assert!(
        !t.contains("sk_test_"),
        "handle output must not contain the key"
    );
    let o = usk(
        &vault,
        &["--json", "env", "stripe", "--policy", "read-only"],
        "brand-new-password-123\n",
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        out(&o).contains("STRIPE_SECRET_KEY=usk_h_")
            || out(&o).contains("STRIPE_SECRET_KEY = \"usk_h_"),
        "{}",
        out(&o)
    );
    assert!(out(&o).contains("/p/stripe"), "{}", out(&o));
    let o = usk(&vault, &["handle", "ls"], "");
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        out(&o).contains("dev") && out(&o).contains("stripe env"),
        "{}",
        out(&o)
    );
    let o = usk(&vault, &["handle", "show", "dev"], "");
    assert!(out(&o).contains("Only to api.stripe.com"), "{}", out(&o));
    let o = usk(
        &vault,
        &["handle", "policy", "dev", "--preset", "read-only"],
        "brand-new-password-123\n",
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["handle", "revoke", "dev"], "");
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["--json", "handle", "ls"], "");
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert!(j
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["label"] == "dev" && h["revoked_at"].is_i64()));
    let o = usk(&vault, &["log", "--kind", "handle_created"], "");
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).lines().count() >= 2, "{}", out(&o));
    let o = usk(&vault, &["log", "verify"], "");
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("intact"), "{}", out(&o));

    let o = usk(&vault, &["daemon", "stop"], "");
    assert!(o.status.success());
    assert!(
        wait_for(|| !dir.path().join("daemon.token").exists()),
        "token file should be removed on stop"
    );
}

fn wait_for(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..50 {
        if cond() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

#[test]
fn import_from_env() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    let env = dir.path().join(".env");
    std::fs::write(
        &env,
        "PORT=3000\nSTRIPE_SECRET_KEY=sk_test_51Habcdefghijklmnop\nDB_PASSWORD=hunter2hunter2\n",
    )
    .unwrap();
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());

    let o = usk(
        &vault,
        &["import", "--from-env", env.to_str().unwrap(), "--dry-run"],
        "",
    );
    assert!(o.status.success(), "{}", err(&o));
    let t = out(&o);
    assert!(t.contains("STRIPE_SECRET_KEY") && t.contains("Stripe") && t.contains("DB_PASSWORD"));
    assert!(!t.contains("PORT"));
    assert!(!t.contains("sk_test_"));

    let o = usk(&vault, &["import", "--from-env", env.to_str().unwrap()], PW);
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["--json", "ls"], "");
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    let names: Vec<&str> = j
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["db-password", "stripe-secret-key"]);
}

#[test]
fn run_injection_and_env_guard() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    let key = "sk_live_51Habcdefghijklmnop";
    let o = usk(
        &vault,
        &["add", "stripe", "--stdin"],
        &format!("{PW}{key}\n"),
    );
    assert!(o.status.success(), "{}", err(&o));

    // Injection is off by default: `usk run` refuses with a clear hint.
    let (shell, flag, echo) = if cfg!(windows) {
        ("cmd", "/c", "echo %K%")
    } else {
        ("sh", "-c", "echo $K")
    };
    let o = usk(
        &vault,
        &["run", "--with", "K=stripe", "--", shell, flag, echo],
        PW,
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("injection is off"), "{}", err(&o));
    assert!(!out(&o).contains(key));

    // Enable it, run again: the program sees the value, we only ever see it redacted.
    let o = usk(
        &vault,
        &["secret", "set", "stripe", "--allow-injection", "true"],
        PW,
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("injection allowed"), "{}", out(&o));
    let o = usk(
        &vault,
        &["run", "--with", "K=stripe", "--", shell, flag, echo],
        PW,
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("[REDACTED:usk:stripe]"), "{}", out(&o));
    assert!(!out(&o).contains(key), "child output must be scrubbed");
    assert!(
        err(&o).contains("is a shell"),
        "shell warning expected: {}",
        err(&o)
    );
    assert!(err(&o).contains("redacted 1 occurrence"), "{}", err(&o));
    // Exit codes propagate.
    let o = usk(
        &vault,
        &["run", "--with", "K=stripe", "--", shell, flag, "exit 7"],
        PW,
    );
    assert_eq!(o.status.code(), Some(7));
    // Audited as `inject`, never as a value.
    let o = usk(&vault, &["--json", "log", "--kind", "inject"], "");
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert!(j.as_array().unwrap().len() >= 2, "{}", out(&o));
    assert!(!out(&o).contains(key));

    // .env guard: an OpenAI key (fixable) and a password with no provider (left alone).
    let env = dir.path().join(".env");
    let openai = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
    std::fs::write(
        &env,
        format!("PORT=3000\nOPENAI_API_KEY={openai}\nDB_PASSWORD=hunter2hunter2\n"),
    )
    .unwrap();
    let o = usk(&vault, &["guard", "scan", env.to_str().unwrap()], "");
    assert!(o.status.success(), "{}", err(&o));
    let t = out(&o);
    assert!(
        t.contains("OPENAI_API_KEY") && t.contains("replace with handle"),
        "{t}"
    );
    assert!(
        t.contains("DB_PASSWORD") && t.contains("no provider preset"),
        "{t}"
    );
    assert!(!t.contains("PORT"), "{t}");
    assert!(!t.contains(openai));
    let o = usk(
        &vault,
        &["guard", "fix", env.to_str().unwrap(), "--dry-run"],
        "",
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        std::fs::read_to_string(&env).unwrap().contains(openai),
        "dry run must not write"
    );
    let o = usk(&vault, &["guard", "fix", env.to_str().unwrap()], "");
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    let fixed = std::fs::read_to_string(&env).unwrap();
    assert!(!fixed.contains(openai), "{fixed}");
    assert!(fixed.contains("OPENAI_API_KEY=usk_h_"), "{fixed}");
    assert!(
        fixed.contains("OPENAI_BASE_URL=http://127.0.0.1:"),
        "{fixed}"
    );
    assert!(fixed.contains("/p/openai/v1"), "{fixed}");
    assert!(
        fixed.contains("PORT=3000") && fixed.contains("DB_PASSWORD=hunter2hunter2"),
        "{fixed}"
    );
    let o = usk(&vault, &["--json", "ls"], "");
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert!(
        j.as_array()
            .unwrap()
            .iter()
            .any(|m| m["name"] == "openai-api-key"),
        "{}",
        out(&o)
    );
    // Second fix is a no-op: the key is already a handle.
    let o = usk(&vault, &["guard", "fix", env.to_str().unwrap()], "");
    assert!(out(&o).contains("nothing to fix"), "{}", out(&o));
}

#[test]
fn mcp_install_bridge_and_remove() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    let key = "sk_live_51Habcdefghijklmnop";
    let o = usk(
        &vault,
        &["add", "stripe", "--stdin"],
        &format!("{PW}{key}\n"),
    );
    assert!(o.status.success(), "{}", err(&o));

    // Install writes the client's config under --home and a token file next to the vault.
    let home = dir.path().join("home");
    let o = usk(
        &vault,
        &["mcp", "install", "cursor", "--home", home.to_str().unwrap()],
        "",
    );
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    let cfg: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(home.join(".cursor").join("mcp.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        cfg["mcpServers"]["unseenkey"]["args"],
        serde_json::json!(["mcp", "--client", "cursor"])
    );
    assert!(cfg["mcpServers"]["unseenkey"]["command"]
        .as_str()
        .unwrap()
        .contains("usk"));
    assert!(
        !cfg.to_string().contains("usk_m_"),
        "configs must not contain tokens"
    );
    let token_file = dir.path().join("mcp").join("cursor.token");
    assert!(std::fs::read_to_string(&token_file)
        .unwrap()
        .starts_with("usk_m_"));
    let o = usk(&vault, &["mcp", "clients"], "");
    assert!(out(&o).contains("mcp:cursor"), "{}", out(&o));

    // The stdio bridge: JSON-RPC lines in, JSON-RPC lines out, nothing else on stdout.
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"0\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"list_secrets\",\"arguments\":{}}}\n",
    );
    let o = usk(&vault, &["mcp", "--client", "cursor"], input);
    assert!(o.status.success(), "{}", err(&o));
    let lines: Vec<serde_json::Value> = out(&o)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("non-JSON on stdout: {l} ({e})"))
        })
        .collect();
    assert_eq!(lines.len(), 3, "{}", out(&o));
    assert_eq!(lines[0]["result"]["serverInfo"]["name"], "unseenkey");
    let names: Vec<&str> = lines[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"call_api") && names.contains(&"list_secrets"));
    let text = lines[2]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("\"stripe\""), "{text}");
    assert!(
        !out(&o).contains(key),
        "bridge output must never contain a value"
    );

    // Remove: token gone, and the bridge does not register the name again;
    // it answers the handshake and says how to reconnect.
    let o = usk(&vault, &["mcp", "remove", "cursor"], "");
    assert!(o.status.success(), "{}", err(&o));
    assert!(!token_file.exists());
    let lines = bridge(&vault, "cursor");
    assert_eq!(lines[0]["result"]["serverInfo"]["name"], "unseenkey");
    assert!(tool_text(&lines).contains("usk mcp install cursor"));
    assert!(!token_file.exists());
}

/// Runs the stdio bridge for `client` over the handshake, the tool list and
/// one `list_secrets` call; returns the three replies.
fn bridge(vault: &Path, client: &str) -> Vec<serde_json::Value> {
    let input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"0\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"list_secrets\",\"arguments\":{}}}\n",
    );
    let o = usk(vault, &["mcp", "--client", client], input);
    assert!(o.status.success(), "{}", err(&o));
    let lines: Vec<serde_json::Value> = out(&o)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("non-JSON on stdout: {l} ({e})"))
        })
        .collect();
    assert_eq!(lines.len(), 3, "{}", out(&o));
    assert!(lines[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "call_api"));
    lines
}

fn tool_text(lines: &[serde_json::Value]) -> String {
    lines[2]["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no tool result: {}", lines[2]))
        .to_string()
}

#[test]
fn the_bridge_registers_itself() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);

    // No vault yet: the session stays up and says how to set one up.
    let lines = bridge(&vault, "claude-code-plugin");
    assert!(lines[0]["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("usk init"));
    assert_eq!(lines[2]["result"]["isError"], true);
    assert!(tool_text(&lines).contains("usk init"));

    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    let o = usk(
        &vault,
        &["add", "stripe", "--stdin"],
        &format!("{PW}sk_live_51Habcdefghijklmnop\n"),
    );
    assert!(o.status.success(), "{}", err(&o));

    // Unlocked: the first run registers the client and keeps its token.
    let token_file = dir.path().join("mcp").join("claude-code-plugin.token");
    let lines = bridge(&vault, "claude-code-plugin");
    assert!(tool_text(&lines).contains("\"stripe\""), "{}", lines[2]);
    let token = std::fs::read_to_string(&token_file).unwrap();
    assert!(token.starts_with("usk_m_"));
    let o = usk(&vault, &["mcp", "clients"], "");
    assert!(out(&o).contains("mcp:claude-code-plugin"), "{}", out(&o));
    // Later runs reuse it.
    bridge(&vault, "claude-code-plugin");
    assert_eq!(std::fs::read_to_string(&token_file).unwrap(), token);

    // Locked: registering waits for an unlock; the session stays up.
    assert!(usk(&vault, &["lock"], "").status.success());
    let other = dir.path().join("mcp").join("other-tool.token");
    let lines = bridge(&vault, "other-tool");
    assert!(lines[0]["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("locked"));
    assert!(tool_text(&lines).contains("usk unlock"));
    assert!(!other.exists());
    assert!(usk(&vault, &["unlock"], PW).status.success());
    let lines = bridge(&vault, "other-tool");
    assert!(tool_text(&lines).contains("\"stripe\""), "{}", lines[2]);
    assert!(other.exists());

    // A name that is registered without this bridge's token is never taken over.
    std::fs::remove_file(&token_file).unwrap();
    let lines = bridge(&vault, "claude-code-plugin");
    assert!(tool_text(&lines).contains("usk mcp install claude-code-plugin"));
    assert!(!token_file.exists());
    // The owner can: install asks for the password and writes a new token.
    let o = usk(&vault, &["mcp", "install", "claude-code-plugin"], PW);
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(out(&o).contains("needs your password"), "{}", out(&o));
    let lines = bridge(&vault, "claude-code-plugin");
    assert!(tool_text(&lines).contains("\"stripe\""), "{}", lines[2]);
    assert_ne!(std::fs::read_to_string(&token_file).unwrap(), token);

    // Not a name a caller can have: refused before anything is registered.
    let o = usk(&vault, &["mcp", "--client", "Bad Name"], "");
    assert!(!o.status.success());
}

#[test]
fn aws_credentials_and_sdk_environment() {
    const AKID: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());

    // Prompted: the key id first, then the CLI asks for the secret access key.
    // (Not a terminal here, so each prompt reads one line: password, id, secret.)
    let o = usk(
        &vault,
        &["add", "aws-dev"],
        &format!("{PW}{AKID}\n{SECRET}\n"),
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("*.amazonaws.com"), "{}", out(&o));
    // Piped: both halves at once, as they sit in ~/.aws/credentials.
    let ini = format!("[prod]\naws_access_key_id = {AKID}\naws_secret_access_key = {SECRET}\n");
    let o = usk(&vault, &["add", "aws-prod", "--stdin"], &ini);
    assert!(o.status.success(), "{}", err(&o));
    // A key id with nothing after it is refused.
    let o = usk(&vault, &["add", "aws-half", "--stdin"], AKID);
    assert!(!o.status.success());
    assert!(err(&o).contains("secret access key"), "{}", err(&o));

    let o = usk(&vault, &["--json", "ls"], "");
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    let items = j.as_array().unwrap();
    assert_eq!(items.len(), 2);
    for m in items {
        assert_eq!(m["kind"], "aws_credentials", "{m}");
        assert_eq!(m["provider"], "aws", "{m}");
    }
    for name in ["aws-dev", "aws-prod"] {
        let o = usk(&vault, &["reveal", name, "--yes"], PW);
        assert_eq!(out(&o).lines().next(), Some(SECRET), "{name}: {}", err(&o));
    }

    // What an SDK needs: the broker as endpoint, a handle as the key id, and a
    // placeholder secret.
    let o = usk(
        &vault,
        &[
            "env",
            "aws-dev",
            "--policy",
            "s3-read-only",
            "--shell",
            "dotenv",
        ],
        PW,
    );
    assert!(o.status.success(), "{}", err(&o));
    let env = out(&o);
    assert!(
        env.contains("AWS_ENDPOINT_URL=http://127.0.0.1:") && env.contains("/p/aws"),
        "{env}"
    );
    assert!(env.contains("AWS_ACCESS_KEY_ID=usk_h_"), "{env}");
    assert!(env.contains("AWS_SECRET_ACCESS_KEY="), "{env}");
    assert!(!env.contains(SECRET) && !env.contains(AKID), "{env}");
}

#[test]
fn camouflage_handles_from_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    let key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
    let o = usk(&vault, &["add", "openai", "--stdin"], &format!("{PW}{key}"));
    assert!(o.status.success(), "{}", err(&o));

    let o = usk(
        &vault,
        &[
            "env",
            "openai",
            "--policy",
            "chat",
            "--camouflage",
            "--shell",
            "dotenv",
        ],
        PW,
    );
    assert!(o.status.success(), "{}", err(&o));
    let env_text = out(&o);
    let handle = env_text
        .lines()
        .find_map(|l| l.strip_prefix("OPENAI_API_KEY="))
        .expect("OPENAI_API_KEY line")
        .to_string();
    assert!(handle.starts_with("sk-proj-usk-"), "{handle}");
    assert_ne!(handle, key);

    // A project .env that already holds the camouflage handle: the guard knows
    // it is a handle, not a leaked OpenAI key, and leaves it alone.
    let env_file = dir.path().join(".env");
    std::fs::write(&env_file, format!("PORT=3000\n{env_text}")).unwrap();
    let o = usk(&vault, &["guard", "fix", env_file.to_str().unwrap()], "");
    assert!(o.status.success(), "{}", err(&o));
    let after = std::fs::read_to_string(&env_file).unwrap();
    assert!(
        after.contains(&format!("OPENAI_API_KEY={handle}")),
        "{after}"
    );
    let o = usk(&vault, &["--json", "ls"], "");
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(
        j.as_array().unwrap().len(),
        1,
        "the handle was not imported as a secret"
    );

    // Without the flag, the canonical form.
    let o = usk(
        &vault,
        &[
            "env", "openai", "--policy", "chat", "--label", "plain", "--shell", "dotenv",
        ],
        PW,
    );
    assert!(out(&o).contains("OPENAI_API_KEY=usk_h_"), "{}", out(&o));
}

#[test]
fn status_without_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let o = usk(&vault, &["status"], "");
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("no (run `usk init`)"));
    let o = usk(&vault, &["ls"], "");
    assert!(!o.status.success());
    assert!(err(&o).contains("no vault found"));
}

#[test]
fn caps_canaries_and_resume_from_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    let o = usk(
        &vault,
        &["add", "stripe", "--stdin"],
        &format!("{PW}sk_live_51Habcdefghijklmnop"),
    );
    assert!(o.status.success(), "{}", err(&o));

    // Caps land in the policy and are explained back.
    let o = usk(
        &vault,
        &[
            "handle",
            "create",
            "stripe",
            "--policy",
            "read-only",
            "--label",
            "capped",
            "--cap",
            "500/day",
            "--cap",
            "60/min",
            "--on-anomaly",
            "pause",
        ],
        PW,
    );
    assert!(o.status.success(), "{}", err(&o));
    let text = out(&o);
    assert!(text.contains("60 requests per minute"), "{text}");
    assert!(text.contains("500 per day"), "{text}");
    let o = usk(&vault, &["handle", "show", "capped"], "");
    assert!(out(&o).contains("on anomaly: pause"), "{}", out(&o));

    // A bad cap is refused before anything is created.
    let o = usk(
        &vault,
        &[
            "handle", "create", "stripe", "--label", "bad", "--cap", "10/week",
        ],
        "",
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("day or min"), "{}", err(&o));

    // A canary: shown once, listed as such, never a working handle.
    let o = usk(
        &vault,
        &[
            "handle", "create", "stripe", "--canary", "--label", "tripwire",
        ],
        "",
    );
    assert!(o.status.success(), "{}", err(&o));
    let text = out(&o);
    assert!(text.contains("Canary created"), "{text}");
    assert!(text.contains("usk_h_"), "{text}");
    assert!(text.contains("\"lock\""), "{text}");
    let o = usk(&vault, &["handle", "ls"], "");
    let list = out(&o);
    assert!(
        list.contains("tripwire") && list.contains("canary"),
        "{list}"
    );
    let o = usk(&vault, &["handle", "show", "tripwire"], "");
    assert!(out(&o).contains("canary:     yes"), "{}", out(&o));

    // Resume is a no-op on a normal handle and says so politely.
    let o = usk(&vault, &["handle", "resume", "capped"], PW);
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("back to normal"), "{}", out(&o));

    // `usk env` takes the same flags.
    let o = usk(
        &vault,
        &[
            "env",
            "stripe",
            "--policy",
            "read-only",
            "--cap",
            "100/day",
            "--shell",
            "dotenv",
        ],
        PW,
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("STRIPE_SECRET_KEY=usk_h_"), "{}", out(&o));
    let o = usk(&vault, &["--json", "handle", "show", "stripe env"], "");
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(j["policy"]["limits"]["requests_per_day"], 100);
}

#[test]
fn provider_changes_and_user_presets_from_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    // A provider the project does not ship, added as a file before anything starts.
    std::fs::create_dir_all(dir.path().join("presets")).unwrap();
    std::fs::write(
        dir.path().join("presets").join("acme.toml"),
        "id = \"acme\"\ndisplay = \"Acme Cloud\"\nupstreams = [\"api.acme.test\"]\nauth = { kind = \"bearer\" }\nbase_path = \"\"\n[env]\nbase_url = \"ACME_BASE_URL\"\napi_key = \"ACME_TOKEN\"\n[[policies]]\nid = \"read-only\"\ndisplay = \"Read only\"\nrecommended = true\nallow = [\"GET /**\"]\n",
    )
    .unwrap();
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    let o = usk(&vault, &["presets"], "");
    assert!(o.status.success(), "{}", err(&o));
    let list = out(&o);
    assert!(list.contains("acme") && list.contains("(yours)"), "{list}");
    assert!(list.contains("hostinger"), "{list}");
    // A token with no recognisable shape, with a URL for the host, and trailing spaces.
    let o = usk(
        &vault,
        &[
            "add",
            "deploy-key",
            "--stdin",
            "--upstream",
            "https://developers.hostinger.com/api/",
        ],
        &format!("{PW}abcdefghijklmnopqrstuvwxyz0123456789ABCD   "),
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["--json", "show", "deploy-key"], "");
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(
        j["upstreams"],
        serde_json::json!(["developers.hostinger.com"])
    );
    assert!(j["provider"].is_null());
    // Give it a provider after the fact; the preset's hosts come along.
    let o = usk(
        &vault,
        &["secret", "set", "deploy-key", "--provider", "hostinger"],
        PW,
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["--json", "show", "deploy-key"], "");
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(j["provider"], "hostinger");
    assert_eq!(
        j["upstreams"],
        serde_json::json!(["developers.hostinger.com"])
    );
    // And the user preset works end to end: a handle with its policy and env.
    let o = usk(
        &vault,
        &["secret", "set", "deploy-key", "--provider", "acme"],
        PW,
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(
        &vault,
        &[
            "env",
            "deploy-key",
            "--policy",
            "read-only",
            "--shell",
            "dotenv",
        ],
        PW,
    );
    assert!(o.status.success(), "{}", err(&o));
    let env_text = out(&o);
    assert!(
        env_text.contains("ACME_BASE_URL=http://127.0.0.1:"),
        "{env_text}"
    );
    assert!(env_text.contains("/p/acme"), "{env_text}");
    assert!(env_text.contains("ACME_TOKEN=usk_h_"), "{env_text}");
}

#[test]
fn projects_from_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    let app = dir.path().join("my-app");
    std::fs::create_dir_all(&app).unwrap();
    let openai = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
    std::fs::write(
        app.join(".env"),
        format!("PORT=3000\nOPENAI_API_KEY={openai}\n"),
    )
    .unwrap();
    let app_s = app.to_str().unwrap();

    // One step: project for the folder, keys into the vault, handles in the file.
    let o = usk(&vault, &["project", "protect", app_s], PW);
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    let t = out(&o);
    assert!(t.contains("Created project my-app"), "{t}");
    assert!(t.contains("is protected"), "{t}");
    let env = std::fs::read_to_string(app.join(".env")).unwrap();
    assert!(!env.contains(openai), "{env}");
    // Protecting again finds the same project and nothing left to move.
    let o = usk(&vault, &["project", "protect", app_s], "");
    assert!(out(&o).contains("nothing to fix"), "{}", out(&o));

    let o = usk(&vault, &["--json", "project", "ls"], "");
    let list: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
    assert_eq!(list[0]["name"], "my-app");
    assert_eq!(list[0]["secrets"][0]["name"], "openai-api-key");
    let o = usk(&vault, &["--json", "handle", "ls"], "");
    let handles: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(handles[0]["project"], "my-app", "{handles}");

    let o = usk(
        &vault,
        &["project", "set", "my-app", "--cap", "500/day"],
        "",
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["project", "show", "MY-APP"], "");
    assert!(out(&o).contains("0 of 500 requests"), "{}", out(&o));

    let o = usk(
        &vault,
        &["add", "other", "--stdin"],
        "sk-proj-zyxwvutsrqponmlkjihgfedcba9876543210ZYXWVU",
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["project", "attach", "my-app", "other"], "");
    assert!(out(&o).contains("openai-api-key, other"), "{}", out(&o));
    let o = usk(&vault, &["project", "detach", "my-app", "other"], "");
    assert!(out(&o).contains("now uses: openai-api-key."), "{}", out(&o));
    let o = usk(&vault, &["project", "attach", "nope", "other"], "");
    assert!(!o.status.success());
    assert!(err(&o).contains("no project named"), "{}", err(&o));

    let o = usk(&vault, &["project", "rm", "my-app", "--yes"], "");
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["project", "ls"], "");
    assert!(out(&o).contains("No projects yet"), "{}", out(&o));
    // The secrets stay.
    assert!(out(&usk(&vault, &["ls"], "")).contains("openai-api-key"));
}

#[test]
fn replacing_a_value_keeps_the_handles() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    let o = usk(
        &vault,
        &["add", "deploy", "--stdin"],
        &format!("{PW}qwertyuiopasdfghjklzxcvbnm123456"),
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["handle", "create", "deploy", "--label", "ci"], "");
    assert!(o.status.success(), "{}", err(&o));

    let o = usk(
        &vault,
        &["secret", "replace", "deploy", "--stdin"],
        "  zxcvbnmasdfghjklqwertyuiop654321 
",
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("now version 2"), "{}", out(&o));
    let o = usk(&vault, &["reveal", "deploy", "--yes"], PW);
    assert!(
        out(&o).contains("zxcvbnmasdfghjklqwertyuiop654321"),
        "{}",
        out(&o)
    );
    assert!(!out(&o).contains(" zxcv"), "trimmed: {}", out(&o));
    let o = usk(&vault, &["--json", "handle", "ls"], "");
    let hs: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(hs[0]["label"], "ci");
    assert_eq!(hs[0]["active"], true, "the handle survives the new value");

    let o = usk(&vault, &["secret", "replace", "deploy", "--stdin"], "   ");
    assert!(!o.status.success());
    assert!(err(&o).contains("empty value"), "{}", err(&o));
}

#[test]
fn a_name_fills_in_the_provider() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    // An opaque token named after its provider.
    let o = usk(
        &vault,
        &["add", "Hostinger", "--stdin"],
        &format!("{PW}qwertyuiopasdfghjklzxcvbnm1234567890ABCD"),
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        out(&o).contains("Provider: Hostinger (from the name"),
        "{}",
        out(&o)
    );
    assert!(out(&o).contains("developers.hostinger.com"), "{}", out(&o));
    // A shape only one preset claims.
    let o = usk(
        &vault,
        &["add", "mail", "--stdin"],
        "xkeysib-0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab-AbCdEfGh",
    );
    assert!(out(&o).contains("Detected: Brevo"), "{}", out(&o));
    // Neither: say what to do.
    let o = usk(
        &vault,
        &["add", "thing", "--stdin"],
        "qwertyuiopasdfghjklzxcvbnm1234567890ZZZZ",
    );
    assert!(out(&o).contains("No provider: choose one"), "{}", out(&o));
}
