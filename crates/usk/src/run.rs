//! `usk run --with VAR=secret -- <command>`: injection mode.
//!
//! The child process receives the plaintext in its environment, so this is the
//! weaker mode (docs/04, T2/T4). It exists for tools that cannot be proxied.
//! Guards: the secret must have `allow_injection`, every injection is audited,
//! the child's stdout/stderr are scrubbed, and shells get a warning.

use crate::client::Client;
use crate::io::CliError;
use serde_json::json;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use unseenkey_core::broker::scrub::{Guarded, Scrubber, StreamScrubber};
use unseenkey_core::crypto::SecretBytes;
use unseenkey_daemon::VaultPaths;
use zeroize::Zeroizing;

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
];

/// Parse `VAR=secret`.
fn parse_with(spec: &str) -> Result<(String, String), CliError> {
    let (var, secret) = spec
        .split_once('=')
        .ok_or_else(|| CliError::general(format!("--with expects VAR=secret, got {spec:?}")))?;
    if var.is_empty()
        || !var.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || secret.is_empty()
    {
        return Err(CliError::general(format!(
            "--with expects VAR=secret, got {spec:?}"
        )));
    }
    Ok((var.to_string(), secret.to_string()))
}

fn pump<R: Read + Send + 'static, W: Write + Send + 'static>(
    mut from: R,
    mut to: W,
    scrubber: Scrubber,
) -> std::thread::JoinHandle<usize> {
    std::thread::spawn(move || {
        let mut st = StreamScrubber::new(scrubber);
        let mut buf = [0u8; 8192];
        loop {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let out = st.push(&buf[..n]);
                    if !out.is_empty() && to.write_all(&out).is_err() {
                        break;
                    }
                    let _ = to.flush();
                }
            }
        }
        let tail = st.finish();
        if !tail.is_empty() {
            let _ = to.write_all(&tail);
        }
        let _ = to.flush();
        st.replaced
    })
}

/// Run `command` with the named secrets injected as environment variables.
/// Exits the process with the child's status.
pub fn run(paths: &VaultPaths, with: Vec<String>, command: Vec<String>) -> Result<(), CliError> {
    if command.is_empty() {
        return Err(CliError::general(
            "nothing to run; usage: usk run --with VAR=secret -- <command> [args]",
        ));
    }
    let specs: Vec<(String, String)> = with
        .iter()
        .map(|s| parse_with(s))
        .collect::<Result<_, _>>()?;
    if specs.is_empty() {
        return Err(CliError::general("pass at least one --with VAR=secret"));
    }
    let c = Client::connect(paths, true)?;
    c.ensure_unlocked()?;

    let cmdline = command.join(" ");
    let mut values: Vec<(String, String, Zeroizing<String>)> = Vec::new();
    for (var, secret) in &specs {
        let r = c.post(
            &format!("/v1/secrets/{secret}/inject"),
            json!({ "var": var, "command": cmdline }),
        )?;
        let value = Zeroizing::new(r["value"].as_str().unwrap_or("").to_string());
        values.push((var.clone(), secret.clone(), value));
    }

    // Scrub the child's output for the values it was given (and their encodings).
    let secrets: Vec<SecretBytes> = values
        .iter()
        .map(|(_, _, v)| SecretBytes::from(v.as_str()))
        .collect();
    let guarded: Vec<Guarded<'_>> = values
        .iter()
        .zip(&secrets)
        .map(|((_, name, _), v)| Guarded { name, value: v })
        .collect();
    let scrubber = Scrubber::new(&guarded);

    let program = &command[0];
    let base = std::path::Path::new(program)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(program)
        .to_ascii_lowercase();
    if SHELLS.contains(&base.as_str()) {
        eprintln!(
            "usk run: warning: {base} is a shell; anything it runs can read the injected variables. Prefer running the program directly."
        );
    }

    let mut cmd = Command::new(program);
    cmd.args(&command[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (var, _, value) in &values {
        cmd.env(var, value.as_str());
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| CliError::general(format!("cannot start {program}: {e}")))?;
    let out = pump(
        child.stdout.take().expect("piped"),
        std::io::stdout(),
        scrubber.clone(),
    );
    let err = pump(
        child.stderr.take().expect("piped"),
        std::io::stderr(),
        scrubber,
    );
    let status = child
        .wait()
        .map_err(|e| CliError::general(format!("waiting for {program}: {e}")))?;
    let replaced = out.join().unwrap_or(0) + err.join().unwrap_or(0);
    drop(values);
    if replaced > 0 {
        eprintln!("usk run: redacted {replaced} occurrence(s) of injected secrets in the program's output");
    }
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_with_specs() {
        assert_eq!(
            parse_with("OPENAI_API_KEY=openai").unwrap(),
            ("OPENAI_API_KEY".into(), "openai".into())
        );
        assert!(parse_with("novalue").is_err());
        assert!(parse_with("=x").is_err());
        assert!(parse_with("BAD-NAME=x").is_err());
        assert!(parse_with("X=").is_err());
    }
}
