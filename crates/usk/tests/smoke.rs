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
    let o = usk(&vault, &["reveal", "openai", "--yes"], "");
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
        "",
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
        "",
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
        "",
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
        "",
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("injection is off"), "{}", err(&o));
    assert!(!out(&o).contains(key));

    // Enable it, run again: the program sees the value, we only ever see it redacted.
    let o = usk(
        &vault,
        &["secret", "set", "stripe", "--allow-injection", "true"],
        "",
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(out(&o).contains("injection allowed"), "{}", out(&o));
    let o = usk(
        &vault,
        &["run", "--with", "K=stripe", "--", shell, flag, echo],
        "",
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
        "",
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

    // Remove: token gone, bridge refuses.
    let o = usk(&vault, &["mcp", "remove", "cursor"], "");
    assert!(o.status.success(), "{}", err(&o));
    assert!(!token_file.exists());
    let o = usk(&vault, &["mcp", "--client", "cursor"], input);
    assert!(!o.status.success());
    assert!(err(&o).contains("usk mcp install cursor"), "{}", err(&o));
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
