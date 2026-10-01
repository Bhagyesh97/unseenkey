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
    assert!(usk(&vault, &["lock"], "").status.success());
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
