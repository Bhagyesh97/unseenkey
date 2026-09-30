//! End-to-end smoke test of the `usk` binary with stdin-driven input.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn usk(vault: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_usk"))
        .arg("--vault")
        .arg(vault)
        .args(args)
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

const PW: &str = "a-long-enough-password\n";

#[test]
fn init_add_ls_reveal_rm() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");

    let o = usk(&vault, &["init", "--profile", "light"], PW);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
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

    // Password on line 1, value on the rest (--stdin).
    let value = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
    let o = usk(
        &vault,
        &["add", "openai", "--stdin"],
        &format!("{PW}{value}\n"),
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(out(&o).contains("Detected: OpenAI"));
    assert!(out(&o).contains("api.openai.com"));
    assert!(!out(&o).contains(value), "add must not echo the value");

    let o = usk(&vault, &["ls"], PW);
    assert!(o.status.success());
    assert!(out(&o).contains("openai"));
    assert!(!out(&o).contains(value));

    let o = usk(&vault, &["--json", "show", "openai"], PW);
    assert!(o.status.success());
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(j["provider"], "openai");
    assert_eq!(j["type"], "api_key");
    assert!(!out(&o).contains(value));

    let o = usk(&vault, &["reveal", "openai"], PW);
    assert!(!o.status.success(), "reveal without --yes must fail");

    let o = usk(&vault, &["reveal", "openai", "--yes"], PW);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(out(&o).trim(), value);

    let o = usk(&vault, &["ls"], "wrong-password\n");
    assert_eq!(o.status.code(), Some(3), "wrong password exits 3");

    let o = usk(&vault, &["rm", "openai", "--yes"], PW);
    assert!(o.status.success());
    let o = usk(&vault, &["ls"], PW);
    assert!(out(&o).contains("No secrets yet"));

    // Recovery: set a new password from the phrase, then use it.
    let phrase = words.join(" ");
    let o = usk(
        &vault,
        &["recover", "--profile", "light"],
        &format!("{phrase}\nbrand-new-password-123\n"),
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = usk(&vault, &["ls"], "brand-new-password-123\n");
    assert!(o.status.success());
}

#[test]
fn import_from_env() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
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
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let t = out(&o);
    assert!(t.contains("STRIPE_SECRET_KEY") && t.contains("Stripe") && t.contains("DB_PASSWORD"));
    assert!(!t.contains("PORT"));
    assert!(!t.contains("sk_test_"));

    let o = usk(&vault, &["import", "--from-env", env.to_str().unwrap()], PW);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = usk(&vault, &["--json", "ls"], PW);
    let j: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    let names: Vec<&str> = j
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["db-password", "stripe-secret-key"]);
}
