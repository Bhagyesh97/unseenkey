//! `usk`: the Unseenkey command line.
//!
//! M1.1 scope: vault lifecycle and secret management, talking to the core
//! library directly. The daemon (`uskd`) and handles arrive in M1.2–M1.4.
//!
//! Rules: values are never accepted as command-line arguments (shell history),
//! never printed except by `reveal`, and the password is read from a hidden
//! prompt or, when stdin is not a terminal, from the first line of stdin.

#![forbid(unsafe_code)]

mod cli;
mod io;

use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e.message);
            ExitCode::from(e.code)
        }
    }
}
