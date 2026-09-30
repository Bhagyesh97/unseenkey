//! Unseenkey core.
//!
//! Everything that touches a secret lives here so that the daemon, the CLI,
//! the desktop app and the browser (via WASM) run the same audited code.
//!
//! Rules enforced by this crate (see `docs/10-tech-stack.md`):
//! - no `unsafe` outside a reviewed `platform` module (none yet);
//! - no network listeners, no CLI;
//! - plaintext lives in [`crypto::SecretBytes`], which zeroizes on drop and
//!   never prints or serializes its contents.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod crypto;
