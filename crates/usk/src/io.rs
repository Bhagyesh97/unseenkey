//! Input helpers: hidden password prompts and stdin handling.

use std::io::{self, BufRead, IsTerminal, Read, Write};
use unseenkey_core::crypto::SecretBytes;
use zeroize::Zeroize;

/// A CLI failure with an exit code.
#[derive(Debug)]
pub struct CliError {
    pub code: u8,
    pub message: String,
}

impl CliError {
    pub fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    pub fn general(message: impl Into<String>) -> Self {
        Self::new(1, message)
    }
}

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
    // Strip one trailing newline, as editors and `echo` add one.
    while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        buf.pop();
    }
    Ok(SecretBytes::new(buf))
}

/// Ask a yes/no question on a terminal; non-terminal input reads one line.
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

pub fn is_tty() -> bool {
    io::stdin().is_terminal()
}
