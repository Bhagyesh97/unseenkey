//! Shared daemon state.

use std::collections::{HashMap, VecDeque};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, watch, Mutex};
use unseenkey_core::broker::scrub::{Guarded, Scrubber};
use unseenkey_core::crypto::hash::Digest;
use unseenkey_core::ids::Id;
use unseenkey_core::policy::Usage;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;

/// The vault type the daemon holds.
pub type DaemonVault = Vault<SqliteStorage, SystemClock>;

/// Process-wide copy of the scrubber for the log writer, which exists before
/// any [`AppState`] does.
static REDACTOR: OnceLock<RwLock<Scrubber>> = OnceLock::new();

fn redactor_cell() -> &'static RwLock<Scrubber> {
    REDACTOR.get_or_init(|| RwLock::new(Scrubber::empty()))
}

/// Replace the process-wide redactor.
pub fn set_redactor(s: Scrubber) {
    *redactor_cell().write().unwrap_or_else(|e| e.into_inner()) = s;
}

/// Scrub `data` with the process-wide redactor.
pub fn redact(data: &[u8]) -> Vec<u8> {
    redactor_cell()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .scrub(data)
        .0
}

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
    /// A handle was used through the broker.
    Use {
        /// Secret name.
        secret: String,
        /// Handle label.
        label: String,
        /// Upstream status.
        status: u16,
    },
    /// The egress guard blocked a request.
    EgressBlocked {
        /// Secret whose handle was used.
        secret: String,
        /// Names of the secrets found in the request.
        leaked: Vec<String>,
    },
}

/// Sliding request counters for one handle.
#[derive(Debug, Default)]
pub struct UsageWindow {
    minute: VecDeque<Instant>,
    day: VecDeque<Instant>,
}

impl UsageWindow {
    fn prune(&mut self, now: Instant) {
        while self
            .minute
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
        {
            self.minute.pop_front();
        }
        while self
            .day
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(86_400))
        {
            self.day.pop_front();
        }
    }
}

/// Everything handlers share.
pub struct AppState {
    /// The vault, locked or unlocked.
    pub vault: Mutex<DaemonVault>,
    /// Hash of the session token.
    pub token_hash: Digest,
    /// `Host` header values we accept (`127.0.0.1:port`, `localhost:port`, `[::1]:port`).
    pub allowed_hosts: std::collections::HashSet<String>,
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
    /// Secret values to guard, rebuilt on unlock and on secret changes.
    pub scrubber: RwLock<Scrubber>,
    /// Per-handle sliding windows.
    pub usage: Mutex<HashMap<Id, UsageWindow>>,
    /// Outbound HTTP client (rustls, no redirects).
    pub http: reqwest::Client,
    /// Logical host → origin to actually connect to (tests, staging).
    pub upstream_overrides: HashMap<String, String>,
    /// `http://127.0.0.1:<port>`, for setup snippets.
    pub base_url: String,
}

impl AppState {
    /// Record activity for the idle timer.
    pub async fn touch(&self) {
        *self.last_activity.lock().await = Instant::now();
    }

    /// Ask the server to stop. Idempotent.
    pub fn request_shutdown(&self) {
        let _ = self.shutdown.send(true);
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

    /// Current usage snapshot for a handle (before counting this request).
    pub async fn usage_for(&self, handle: &Id, total: u64) -> Usage {
        let now = Instant::now();
        let mut map = self.usage.lock().await;
        let w = map.entry(*handle).or_default();
        w.prune(now);
        Usage {
            last_minute: w.minute.len() as u32,
            last_day: w.day.len() as u32,
            total,
        }
    }

    /// Count a request for a handle.
    pub async fn record_use(&self, handle: &Id) {
        let now = Instant::now();
        let mut map = self.usage.lock().await;
        let w = map.entry(*handle).or_default();
        w.minute.push_back(now);
        w.day.push_back(now);
    }

    /// Rebuild the scrubber from every secret in the (unlocked) vault.
    /// Called with the vault lock already held. Synchronous on purpose: no
    /// await may happen while a reference to the vault guard is alive.
    pub fn rebuild_scrubber(&self, vault: &DaemonVault) {
        let mut values = Vec::new();
        if let Ok(list) = vault.list() {
            for meta in list {
                if meta.no_scrub {
                    continue;
                }
                if let Ok(r) = vault.reveal(&meta.secret_id) {
                    values.push((meta.name.clone(), r.value));
                    for (k, v) in r.fields {
                        values.push((format!("{}.{k}", meta.name), v));
                    }
                }
            }
        }
        let guarded: Vec<Guarded<'_>> = values
            .iter()
            .map(|(n, v)| Guarded { name: n, value: v })
            .collect();
        let scrubber = Scrubber::new(&guarded);
        set_redactor(scrubber.clone());
        *self.scrubber.write().unwrap_or_else(|e| e.into_inner()) = scrubber;
    }

    /// Drop all guarded values (on lock).
    pub fn clear_scrubber(&self) {
        set_redactor(Scrubber::empty());
        *self.scrubber.write().unwrap_or_else(|e| e.into_inner()) = Scrubber::empty();
    }

    /// A snapshot of the current scrubber.
    pub fn scrubber_snapshot(&self) -> Scrubber {
        self.scrubber
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}
