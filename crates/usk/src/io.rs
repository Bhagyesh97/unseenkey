//! Input helpers: hidden password prompts and stdin handling.

use std::io::{self, BufRead, IsTerminal, Read, Write};
use unseenkey_core::crypto::SecretBytes;
use zeroize::Zeroize;

/// A CLI failure with an exit code.
#[derive(Debug)]
pub struct CliError {
    /// Process exit code.
    pub code: u8,
    /// Machine-readable code (`vault_locked`, `not_found`, ...).
    pub kind: String,
    /// Human message.
    pub message: String,
}

impl CliError {
    /// Any error with exit code 1.
    pub fn general(message: impl Into<String>) -> Self {
        Self::with_code(1, "error", message)
    }
    /// An error with a specific exit code and kind.
    pub fn with_code(code: u8, kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            kind: kind.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// Exit code when the vault is locked or the password is wrong.
pub const EXIT_LOCKED: u8 = 3;

/// Read a secret line: hidden prompt on a terminal, else one line from stdin.
pub fn read_secret_line(prompt: &str) -> Result<SecretBytes, CliError> {
    if io::stdin().is_terminal() {
        let mut s = rpassword::prompt_password(prompt)
            .map_err(|e| CliError::general(format!("cannot read input: {e}")))?;
        let out = SecretBytes::from_slice(s.trim_end_matches(['\r', '\n']).as_bytes());
        s.zeroize();
        Ok(out)
    } else {
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| CliError::general(format!("cannot read stdin: {e}")))?;
        let out = SecretBytes::from_slice(line.trim_end_matches(['\r', '\n']).as_bytes());
        line.zeroize();
        Ok(out)
    }
}

/// Read the rest of stdin as a secret value (for `--stdin`).
pub fn read_secret_rest() -> Result<SecretBytes, CliError> {
    let mut buf = Vec::new();
    io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .map_err(|e| CliError::general(format!("cannot read stdin: {e}")))?;
    while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        buf.pop();
    }
    Ok(SecretBytes::new(buf))
}

/// Ask a yes/no question.
pub fn confirm(question: &str) -> Result<bool, CliError> {
    print!("{question} [y/N] ");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::general(format!("cannot read input: {e}")))?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

/// Is stdin a terminal?
pub fn is_tty() -> bool {
    io::stdin().is_terminal()
}
