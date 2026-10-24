//! Unseenkey core.
//!
//! Everything that touches a secret lives here so that the daemon, the CLI,
//! the desktop app and the browser (via WASM) run the same audited code.
//!
//! Rules enforced by this crate (see `docs/10-tech-stack.md`):
//! - no `unsafe` outside the reviewed `crypto::platform` module (memory locking);
//! - no network listeners, no CLI;
//! - plaintext lives in [`crypto::SecretBytes`], which zeroizes on drop and
//!   never prints or serializes its contents, or in the vault's zeroizing
//!   payload types that exist only on the encryption path.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod audit;
pub mod broker;
pub mod crypto;
pub mod handles;
pub mod ids;
pub mod import;
pub mod policy;
pub mod presets;
pub mod projects;
pub mod providers;
pub mod storage;
pub mod time;
pub mod vault;
