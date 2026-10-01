//! The Unseenkey daemon.
//!
//! Holds the unlocked vault in memory and serves a loopback-only HTTP API for
//! the CLI, the desktop app and (from M1.4) the broker routes. This crate is a
//! library so the `usk` binary can run it in-process (`usk daemon run`) and so
//! tests can start it on an ephemeral port.
//!
//! Security properties enforced here (see `docs/04-threat-model.md`):
//! - INV-6: any request carrying browser-origin headers is rejected.
//! - INV-3: management routes require the per-session bearer token.
//! - Plaintext never appears in logs; only method, path and status are logged.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod api;
pub mod config;
pub mod guard;
pub mod paths;
pub mod proxy;
pub mod server;
pub mod state;
pub mod token;

pub use config::{Config, DaemonConfig};
pub use paths::VaultPaths;
pub use server::{serve, Running, ServeError, ServeOptions};
