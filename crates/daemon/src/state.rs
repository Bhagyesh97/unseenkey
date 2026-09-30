//! Shared daemon state.

use std::collections::HashSet;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch, Mutex};
use unseenkey_core::crypto::hash::Digest;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;

/// The vault type the daemon holds.
pub type DaemonVault = Vault<SqliteStorage, SystemClock>;

/// Events pushed to `/v1/events` subscribers. Never carry secret material.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// The vault was unlocked.
    Unlocked,
    /// The vault was locked (`reason`: `request`, `idle`, `shutdown`).
    Locked {
        /// Why.
        reason: &'static str,
    },
    /// A secret was created, updated or deleted.
    SecretChanged {
        /// Secret id (hex).
        id: String,
        /// `created`, `updated`, `deleted`.
        change: &'static str,
    },
    /// A value was revealed.
    Revealed {
        /// Secret id (hex).
        id: String,
    },
}

/// Everything handlers share.
pub struct AppState {
    /// The vault, locked or unlocked.
    pub vault: Mutex<DaemonVault>,
    /// Hash of the session token.
    pub token_hash: Digest,
    /// `Host` header values we accept (`127.0.0.1:port`, `localhost:port`, `[::1]:port`).
    pub allowed_hosts: HashSet<String>,
    /// Last authenticated request, for idle locking.
    pub last_activity: Mutex<Instant>,
    /// Recent unlock attempts, for rate limiting.
    pub unlock_attempts: Mutex<Vec<Instant>>,
    /// Event broadcaster.
    pub events: broadcast::Sender<Event>,
    /// Daemon start time.
    pub started: Instant,
    /// Idle lock timeout; zero disables.
    pub idle_lock: Duration,
    /// Becomes `true` once a shutdown was requested (API or signal).
    pub shutdown: watch::Sender<bool>,
}

impl AppState {
    /// Ask the server to stop. Idempotent.
    pub fn request_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Record activity for the idle timer.
    pub async fn touch(&self) {
        *self.last_activity.lock().await = Instant::now();
    }

    /// Broadcast an event; dropped if nobody listens.
    pub fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    /// Sliding-window rate limit: at most `max` attempts per `window`.
    pub async fn unlock_allowed(&self, max: usize, window: Duration) -> bool {
        let now = Instant::now();
        let mut attempts = self.unlock_attempts.lock().await;
        attempts.retain(|t| now.duration_since(*t) < window);
        if attempts.len() >= max {
            return false;
        }
        attempts.push(now);
        true
    }
}
