//! Library half of the `usk` binary, so `uskd` and tests can reuse it.
//!
//! `unsafe` is denied everywhere except the reviewed [`platform`] module.

#![deny(unsafe_code)]

pub mod cli;
pub mod client;
pub mod daemon;
pub mod guard;
pub mod io;
pub mod mcp;
pub mod platform;
pub mod project;
pub mod run;
