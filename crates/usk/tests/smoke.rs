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
    // Run with a vault of its own, so the config has to name it.
    assert_eq!(
        cfg["mcpServers"]["unseenkey"]["args"],
        serde_json::json!([
            "--vault",
            vault.to_str().unwrap(),
            "mcp",
            "--client",
            "cursor"
        ])
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
    assert!(tool_text(&lines).contains("mcp install cursor"));
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
    assert!(tool_text(&lines).contains("mcp install claude-code-plugin"));
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
fn a_key_in_two_parts_from_the_cli() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    // Asked for each part, because of the name.
    let o = usk(
        &vault,
        &["add", "twilio"],
        &format!("{PW}AC0123456789abcdef0123456789abcdef\ntwilio-token-abcdefghijklmnop\n"),
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["reveal", "twilio", "--yes"], PW);
    let shown = out(&o);
    assert!(shown.contains("twilio-token-abcdefghijklmnop"), "{shown}");
    assert!(shown.contains("username"), "{shown}");
    assert!(
        shown.contains("AC0123456789abcdef0123456789abcdef"),
        "{shown}"
    );

    // Asked for the rest, because of the shape of the first part.
    let o = usk(
        &vault,
        &["add", "payments"],
        "rzp_test_abcdefghijklmn\nrazorpay-secret-abcdefghijkl\n",
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["reveal", "payments", "--yes"], PW);
    assert!(out(&o).contains("rzp_test_abcdefghijklmn"), "{}", out(&o));
    assert!(
        out(&o).contains("razorpay-secret-abcdefghijkl"),
        "{}",
        out(&o)
    );

    // Piped, one part is stored as given and the other can follow.
    let o = usk(
        &vault,
        &["add", "plivo", "--stdin"],
        "plivo-token-abcdefghijklmnop",
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(
        &vault,
        &[
            "secret",
            "set",
            "plivo",
            "--username",
            "MAPLIVOID01234567890",
        ],
        "",
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["reveal", "plivo", "--yes"], PW);
    assert!(out(&o).contains("MAPLIVOID01234567890"), "{}", out(&o));

    // Nothing to split or ask for on a provider with one value.
    let o = usk(
        &vault,
        &["add", "openai", "--provider", "openai"],
        "sk-abcdefghijklmnopqrstuvwxyz0123456789\n",
    );
    assert!(o.status.success(), "{}", err(&o));
}

#[test]
fn two_variables_become_one_key() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    let env = dir.path().join(".env");
    std::fs::write(
        &env,
        "TWILIO_ACCOUNT_SID=AC0123456789abcdef0123456789abcdef\nTWILIO_AUTH_TOKEN=twilio-token-abcdefghijklmnop\n",
    )
    .unwrap();
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    let o = usk(&vault, &["import", "--from-env", env.to_str().unwrap()], PW);
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["--json", "ls"], "");
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(j.as_array().unwrap().len(), 1, "one secret: {j}");
    let o = usk(&vault, &["reveal", "twilio-auth-token", "--yes"], PW);
    assert!(
        out(&o).contains("twilio-token-abcdefghijklmnop"),
        "{}",
        out(&o)
    );
    assert!(
        out(&o).contains("username=AC0123456789abcdef0123456789abcdef"),
        "{}",
        out(&o)
    );
}

#[test]
fn changing_the_password() {
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

    // Refused: wrong current password, too short, unchanged. None of them
    // locks the vault or changes anything.
    const NEW: &str = "a-different-long-password\n";
    for (input, why) in [
        (format!("wrong-password-here\n{NEW}"), "wrong"),
        (format!("{PW}short\n"), "12 characters"),
        (format!("{PW}{PW}"), "current password"),
    ] {
        let o = usk(&vault, &["passwd", "--profile", "light"], &input);
        assert!(!o.status.success(), "{input}");
        assert!(err(&o).to_lowercase().contains(why), "{}", err(&o));
    }
    let o = usk(&vault, &["--json", "status"], "");
    let s: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(s["daemon"]["locked"], false, "still unlocked");

    let o = usk(
        &vault,
        &["passwd", "--profile", "light"],
        &format!("{PW}{NEW}"),
    );
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["--json", "status"], "");
    let s: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(s["daemon"]["locked"], true, "locked by the change");

    // The running daemon takes the new password, not the old one.
    assert!(!usk(&vault, &["unlock"], PW).status.success());
    let o = usk(&vault, &["unlock"], NEW);
    assert!(o.status.success(), "{}", err(&o));
    let o = usk(&vault, &["reveal", "deploy", "--yes"], NEW);
    assert!(
        out(&o).contains("qwertyuiopasdfghjklzxcvbnm123456"),
        "{}",
        out(&o)
    );
    // The change is in the log, and the log still holds together.
    let o = usk(&vault, &["log", "--kind", "password_changed"], "");
    assert!(out(&o).contains("password_changed"), "{}", out(&o));
    assert!(usk(&vault, &["log", "verify"], NEW).status.success());
}

#[test]
fn a_key_needing_its_own_host_and_a_value_too_large() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    let o = usk(
        &vault,
        &["add", "supabase", "--stdin"],
        &format!("{PW}sb_secret_abcdefghijklmnopqrstuvwxyz"),
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("Not usable yet"), "{}", out(&o));
    assert!(
        out(&o).contains("usk secret set supabase --upstream"),
        "{}",
        out(&o)
    );
    // Named at once: nothing more to do.
    let o = usk(
        &vault,
        &[
            "add",
            "supabase-2",
            "--provider",
            "supabase",
            "--upstream",
            "abcd1234.supabase.co",
            "--stdin",
        ],
        "sb_secret_abcdefghijklmnopqrstuvwxyz",
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        out(&o).contains("Upstream locked to: abcd1234.supabase.co"),
        "{}",
        out(&o)
    );

    // Too large: said in words.
    let big = "x".repeat(8 * 1024 * 1024);
    let o = usk(&vault, &["add", "big", "--stdin"], &big);
    assert!(!o.status.success());
    assert!(err(&o).contains("too large"), "{}", err(&o));
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

/// `usk` with `PATH` holding only `path`, so the AI tools it can find are the test's.
fn usk_on_path(vault: &Path, path: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_usk"))
        .arg("--vault")
        .arg(vault)
        .args(args)
        .env("PATH", path)
        .env("USK_LISTEN", "127.0.0.1:0")
        .env("USK_IDLE_LOCK_MINUTES", "0")
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

#[test]
fn mcp_install_finds_the_tools_makes_the_vault_and_can_be_repeated() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v").join("vault.db");
    std::fs::create_dir_all(vault.parent().unwrap()).unwrap();
    let _stop = StopDaemon(&vault);
    let home = dir.path().join("home");
    let path = dir.path().join("bin");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&path).unwrap();
    let home_s = home.to_str().unwrap();
    let args = ["mcp", "install", "--home", home_s];
    let run = |args: &[&str], stdin: &str| usk_on_path(&vault, &path, args, stdin);

    // No tool on this computer: say so, and make nothing.
    let o = run(&args, "");
    assert!(!o.status.success());
    assert!(err(&o).contains("no AI tool found"), "{}", err(&o));
    assert!(!vault.exists());

    // A tool, no vault, no person at a terminal: a program never gets a vault by accident.
    let cursor = home.join(".cursor");
    std::fs::create_dir_all(&cursor).unwrap();
    let o = run(&args, "");
    assert!(!o.status.success());
    assert!(err(&o).contains("usk init"), "{}", err(&o));
    assert!(!vault.exists());

    // Asked to: one password, once, and the tool is connected and told what is next.
    let o = run(&["mcp", "install", "--home", home_s, "--new-vault"], PW);
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    let text = out(&o);
    assert!(text.contains("RECOVERY PHRASE"), "{text}");
    assert!(text.contains("Cursor: connected"), "{text}");
    assert!(text.contains(" add openai"), "{text}");
    assert!(text.contains("Restart Cursor"), "{text}");
    let config = cursor.join("mcp.json");
    assert!(config.exists());
    let token_file = vault.parent().unwrap().join("mcp").join("cursor.token");
    let token = std::fs::read_to_string(&token_file).unwrap();

    // Again: no password, same token.
    let o = run(&args, "");
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(out(&o).contains("Cursor: already connected"), "{}", out(&o));
    assert_eq!(std::fs::read_to_string(&token_file).unwrap(), token);

    // With a key stored there is nothing to add.
    assert!(
        run(&["add", "stripe", "--stdin"], "sk_live_51Habcdefghijklmnop")
            .status
            .success()
    );
    assert!(!out(&run(&args, "")).contains(" add openai"));

    // A token that stopped working is replaced, with the password.
    std::fs::write(&token_file, "usk_m_stale").unwrap();
    let o = run(&args, PW);
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(out(&o).contains("needs your password"), "{}", out(&o));
    let token = std::fs::read_to_string(&token_file).unwrap();
    assert_ne!(token, "usk_m_stale");

    // A config it cannot edit stays as it was, the token too, and the words say what to add.
    let broken = "{ \"mcpServers\": {}, // a comment\n}";
    std::fs::write(&config, broken).unwrap();
    std::fs::write(&token_file, "usk_m_stale").unwrap();
    let o = run(&args, PW);
    assert!(!o.status.success());
    assert!(err(&o).contains("left as it was"), "{}", err(&o));
    assert!(err(&o).contains("--client"), "{}", err(&o));
    assert_eq!(std::fs::read_to_string(&config).unwrap(), broken);
    assert_eq!(std::fs::read_to_string(&token_file).unwrap(), "usk_m_stale");
    std::fs::write(&token_file, &token).unwrap();

    // Other servers in the file are kept.
    std::fs::write(
        &config,
        r#"{"mcpServers": {"other": {"command": "x"}}, "theme": 1}"#,
    )
    .unwrap();
    assert!(run(&args, "").status.success());
    let cfg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&config).unwrap()).unwrap();
    assert_eq!(cfg["mcpServers"]["other"]["command"], "x");
    assert_eq!(cfg["theme"], 1);
    assert!(cfg["mcpServers"]["unseenkey"].is_object());

    // Locked: a connected tool needs nothing, so nothing asks for the password,
    // and the file is left exactly as it was.
    assert!(run(&["lock"], "").status.success());
    let before = std::fs::read_to_string(&config).unwrap();
    let o = run(&args, "");
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(out(&o).contains("Cursor: already connected"), "{}", out(&o));
    let s: serde_json::Value = serde_json::from_str(&out(&run(&["--json", "status"], ""))).unwrap();
    assert_eq!(s["daemon"]["locked"], true);
    assert_eq!(std::fs::read_to_string(&config).unwrap(), before);
    assert!(run(&["unlock"], PW).status.success());

    // A disconnect holds when tools are found, and naming the tool undoes it.
    assert!(run(&["mcp", "remove", "cursor"], "").status.success());
    let o = run(&args, "");
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(out(&o).contains("left alone"), "{}", out(&o));
    assert!(!token_file.exists());
    let o = run(&["mcp", "install", "cursor", "--home", home_s], PW);
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(token_file.exists());

    // From another vault the tool stays where it is, and no second vault appears.
    let other = dir.path().join("other").join("vault.db");
    std::fs::create_dir_all(other.parent().unwrap()).unwrap();
    let before = std::fs::read_to_string(&config).unwrap();
    let o = usk_on_path(&other, &path, &args, "");
    assert!(!o.status.success());
    assert!(err(&o).contains("connected to the vault at"), "{}", err(&o));
    assert!(!other.exists());
    assert_eq!(std::fs::read_to_string(&config).unwrap(), before);

    // A wrong password keeps its own exit code.
    std::fs::remove_file(&token_file).unwrap();
    let o = run(&args, "not-the-password\n");
    assert_eq!(o.status.code(), Some(3), "{}\n{}", out(&o), err(&o));
}

/// A stand-in for `claude`, installed the way npm does it on Windows (a `.cmd`).
/// It records its arguments, keeps one `mcp` entry in a file, and refuses a second
/// `mcp add`, as the real one does. `plugin.json` is what `plugin list` prints.
fn fake_claude(dir: &Path) {
    #[cfg(windows)]
    std::fs::write(
        dir.join("claude.cmd"),
        "@echo off\r\n\
         echo %* >> \"%~dp0calls.txt\"\r\n\
         if \"%1\"==\"plugin\" goto plugin\r\n\
         if \"%2\"==\"get\" goto get\r\n\
         if \"%2\"==\"remove\" goto remove\r\n\
         if exist \"%~dp0added\" exit /b 1\r\n\
         echo %* > \"%~dp0added\"\r\n\
         exit /b 0\r\n\
         :get\r\n\
         if not exist \"%~dp0added\" exit /b 1\r\n\
         type \"%~dp0added\"\r\n\
         exit /b 0\r\n\
         :remove\r\n\
         del \"%~dp0added\"\r\n\
         exit /b 0\r\n\
         :plugin\r\n\
         if exist \"%~dp0plugin.json\" (type \"%~dp0plugin.json\") else (echo [])\r\n\
         exit /b 0\r\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = dir.join("claude");
        std::fs::write(
            &file,
            "#!/bin/sh\n\
             here=${0%/*}\n\
             echo \"$*\" >> \"$here/calls.txt\"\n\
             if [ \"$1\" = plugin ]; then\n\
               if [ -e \"$here/plugin.json\" ]; then /bin/cat \"$here/plugin.json\"; else echo '[]'; fi\n\
               exit 0\n\
             fi\n\
             if [ \"$2\" = get ]; then\n\
               [ -e \"$here/added\" ] || exit 1\n\
               /bin/cat \"$here/added\"\n\
               exit 0\n\
             fi\n\
             if [ \"$2\" = remove ]; then /bin/rm -f \"$here/added\"; exit 0; fi\n\
             if [ -e \"$here/added\" ]; then exit 1; fi\n\
             echo \"$*\" > \"$here/added\"\n\
             exit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

#[test]
fn a_bridge_with_no_vault_answers_and_says_what_is_missing() {
    // As Claude Desktop meets it on a computer with nothing set up yet, and
    // with the byte order mark Windows PowerShell puts in front of a pipe.
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let input = "\u{feff}{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n\
                 {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\
                 {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"list_secrets\",\"arguments\":{}}}\n";
    let o = usk(&vault, &["mcp", "--client", "claude-desktop"], input);
    assert!(o.status.success(), "{}", err(&o));
    let replies: Vec<serde_json::Value> = out(&o)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(replies.len(), 2, "{}", out(&o));
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "unseenkey");
    assert_eq!(replies[1]["result"]["isError"], true);
    assert!(replies[1]["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("not set up on this computer"));
    assert!(!vault.exists(), "a bridge never makes a vault");
}

#[test]
fn mcp_install_runs_claude_however_it_was_installed_and_steps_aside_for_the_plugin() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    let home = dir.path().join("home");
    let path = dir.path().join("bin");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&path).unwrap();
    fake_claude(&path);
    let home_s = home.to_str().unwrap();
    let args = ["mcp", "install", "--home", home_s];
    let calls = path.join("calls.txt");
    let log = || std::fs::read_to_string(&calls).unwrap();
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    assert!(usk(&vault, &["unlock"], PW).status.success());

    let o = usk_on_path(&vault, &path, &args, "");
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(out(&o).contains("Claude Code: connected"), "{}", out(&o));
    assert!(
        log().contains("mcp add --scope user unseenkey"),
        "{}",
        log()
    );
    assert!(log().contains("--client claude-code"), "{}", log());

    // Again: the entry already runs this, so it is not touched.
    let o = usk_on_path(&vault, &path, &args, "");
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(
        out(&o).contains("Claude Code: already connected"),
        "{}",
        out(&o)
    );
    assert!(!log().contains("mcp remove"), "{}", log());
    assert_eq!(log().matches("mcp add").count(), 1, "{}", log());

    // An entry naming an old path is ours, and is replaced.
    std::fs::write(
        path.join("added"),
        format!(
            "/old/usk --vault {} mcp --client claude-code\n",
            vault.display()
        ),
    )
    .unwrap();
    let o = usk_on_path(&vault, &path, &args, "");
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(
        log().contains("mcp remove --scope user unseenkey"),
        "{}",
        log()
    );
    assert_eq!(log().matches("mcp add").count(), 2, "{}", log());

    // Claude Code connected to another vault stays there.
    std::fs::write(
        path.join("added"),
        "/old/usk --vault /elsewhere/vault.db mcp --client claude-code\n",
    )
    .unwrap();
    let o = usk_on_path(&vault, &path, &args, "");
    assert!(!o.status.success());
    assert!(err(&o).contains("connected to the vault at"), "{}", err(&o));
    assert_eq!(log().matches("mcp add").count(), 2, "{}", log());
    std::fs::remove_file(path.join("added")).unwrap();

    // With the plugin on, finding tools leaves Claude Code alone, and says what is next.
    let plugin = path.join("plugin.json");
    std::fs::write(&plugin, r#"[{"id":"unseenkey@unseenkey","enabled":true}]"#).unwrap();
    let before = log().matches("mcp add").count();
    let o = usk_on_path(&vault, &path, &args, "");
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(
        out(&o).contains("through the Unseenkey plugin"),
        "{}",
        out(&o)
    );
    assert!(out(&o).contains("Restart Claude Code"), "{}", out(&o));
    assert_eq!(log().matches("mcp add").count(), before, "{}", log());

    // Turned off, or gone though its name is still registered: Claude Code needs connecting.
    std::fs::write(&plugin, r#"[{"id":"unseenkey@unseenkey","enabled":false}]"#).unwrap();
    let list = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n";
    assert!(
        usk(&vault, &["mcp", "--client", "claude-code-plugin"], list)
            .status
            .success()
    );
    let o = usk_on_path(&vault, &path, &args, "");
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert_eq!(log().matches("mcp add").count(), before + 1, "{}", log());

    // No `claude` at all: say what to run, and it is not a failure.
    let empty = dir.path().join("nothing");
    std::fs::create_dir_all(&empty).unwrap();
    let o = usk_on_path(
        &vault,
        &empty,
        &["mcp", "install", "claude-code", "--home", home_s],
        "",
    );
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(
        out(&o).contains("claude mcp add --scope user unseenkey"),
        "{}",
        out(&o)
    );
}

/// A stand-in for a daemon of another version: answers every request with its status.
fn service_of_version(dir: &Path, version: &'static str) {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std::fs::write(
        dir.join("daemon.addr"),
        listener.local_addr().unwrap().to_string(),
    )
    .unwrap();
    std::fs::write(dir.join("daemon.token"), "usk_s_stand_in").unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let body =
                format!(r#"{{"version":"{version}","locked":true,"secrets":0,"uptime_s":1}}"#);
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
}

#[test]
fn a_service_of_another_version_is_called_out() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    service_of_version(dir.path(), "0.1.2");
    let o = usk(&vault, &["status"], "");
    assert!(err(&o).contains("version 0.1.2"), "{}", err(&o));
    assert!(err(&o).contains("usk daemon restart"), "{}", err(&o));
    // Once per run, however many times this run connects.
    assert_eq!(err(&o).matches("warning:").count(), 1, "{}", err(&o));

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    service_of_version(dir.path(), "99.0.0");
    let o = usk(&vault, &["status"], "");
    assert!(err(&o).contains("newer than this usk"), "{}", err(&o));
    assert!(!err(&o).contains("usk daemon restart"), "{}", err(&o));
    // Restarting from an older copy would be a downgrade, so it is refused, and
    // the doctor does not advise it.
    let o = usk(&vault, &["daemon", "restart"], "");
    assert!(!o.status.success());
    assert!(err(&o).contains("newer than this usk"), "{}", err(&o));
    let o = usk(&vault, &["doctor"], "");
    assert!(!out(&o).contains("usk daemon restart"), "{}", out(&o));
    assert_eq!(
        (out(&o) + &err(&o)).matches("newer than this usk").count(),
        1
    );
}

#[test]
fn restarting_the_service_locks_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    assert!(usk(&vault, &["unlock"], PW).status.success());

    let o = usk(&vault, &["daemon", "restart"], "");
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    assert!(out(&o).contains("Daemon restarted"), "{}", out(&o));
    assert!(out(&o).contains("usk unlock"), "{}", out(&o));
    assert!(!err(&o).contains("warning:"), "{}", err(&o));

    let o = usk(&vault, &["--json", "status"], "");
    let s: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(s["daemon"]["locked"], true);
    assert_eq!(s["daemon"]["version"], s["version"]);
}

#[test]
fn the_log_shows_what_just_happened() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    assert!(usk(
        &vault,
        &["add", "stripe", "--stdin"],
        &format!("{PW}sk_live_51Habcdefghijklmnop")
    )
    .status
    .success());

    let o = usk(&vault, &["log", "--limit", "1"], "");
    assert!(out(&o).contains("secret_created"), "{}", out(&o));
    assert!(out(&o).contains("usk log --since 1"), "{}", out(&o));
    let o = usk(&vault, &["log", "--since", "1", "--limit", "1"], "");
    assert!(out(&o).contains("unlock"), "{}", out(&o));
    assert!(!out(&o).contains("Older ones"), "{}", out(&o));
    // The hint is for when there is more, and keeps to the kind asked for.
    let o = usk(&vault, &["log", "--kind", "secret_created"], "");
    assert!(!out(&o).contains("Older ones"), "{}", out(&o));
    assert!(usk(
        &vault,
        &["add", "stripe-two", "--stdin"],
        "sk_live_51Hzyxwvutsrqponmlkji"
    )
    .status
    .success());
    let o = usk(
        &vault,
        &["log", "--kind", "secret_created", "--limit", "1"],
        "",
    );
    assert!(
        out(&o).contains("--since 1 --kind secret_created"),
        "{}",
        out(&o)
    );
}

#[test]
fn an_account_id_stays_in_the_env_file() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    let _stop = StopDaemon(&vault);
    assert!(usk(&vault, &["init", "--profile", "light"], PW)
        .status
        .success());
    let env = dir.path().join(".env");
    let sid = "AC0123456789abcdef0123456789abcdef";
    std::fs::write(
        &env,
        format!("TWILIO_SID={sid}\nSTRIPE_KEY=sk_live_51Habcdefghijklmnop\n"),
    )
    .unwrap();
    let o = usk(&vault, &["guard", "fix", env.to_str().unwrap()], PW);
    assert!(o.status.success(), "{}\n{}", out(&o), err(&o));
    let text = std::fs::read_to_string(&env).unwrap();
    assert!(text.contains(&format!("TWILIO_SID={sid}")), "{text}");
    assert!(!text.contains("sk_live_51Habcdefghijklmnop"), "{text}");
    let o = usk(&vault, &["ls"], "");
    assert!(!out(&o).contains("twilio-sid"), "{}", out(&o));
}
