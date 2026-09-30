//! `usk`: the Unseenkey command line.
//!
//! Rules: values are never accepted as command-line arguments (shell history),
//! never printed except by `reveal`, and the password is read from a hidden
//! prompt or, when stdin is not a terminal, from the first line of stdin.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    match usk::cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e.message);
            ExitCode::from(e.code)
        }
    }
}
