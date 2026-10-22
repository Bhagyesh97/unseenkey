//! Shared daemon state.

use std::collections::{HashMap, VecDeque};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, oneshot, watch, Mutex};
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
    /// A request or access request is waiting for the owner.
    ApprovalRequested {
        /// Approval id (hex).
        id: String,
        /// Handle label.
        label: String,
        /// Secret name.
        secret: String,
        /// Caller identity.
        caller: String,
        /// Method (empty for access requests).
        method: String,
        /// Path or scope.
        path: String,
        /// What is being asked.
        scope: String,
    },
    /// An approval was decided.
    ApprovalDecided {
        /// Approval id (hex).
        id: String,
        /// Allowed?
        allowed: bool,
    },
    /// A handle behaved unusually, or a canary was used.
    Anomaly {
        /// Handle id (hex).
        id: String,
        /// Handle label.
        label: String,
        /// Secret name.
        secret: String,
        /// `denial_burst` or `canary`.
        kind: String,
        /// One sentence for the owner.
        detail: String,
        /// What was done: `alert`, `throttle`, `approve`, `pause`, `lock`.
        response: &'static str,
    },
}

/// Policy refusals on one handle this many times within
/// [`DENIAL_BURST_WINDOW`] are an incident: a tool probing for what it may do.
pub const DENIAL_BURST_THRESHOLD: usize = 10;
/// The window for [`DENIAL_BURST_THRESHOLD`].
pub const DENIAL_BURST_WINDOW: Duration = Duration::from_secs(60);
/// After an incident on a handle, no second one is raised for this long
/// (the owner's resume clears it).
pub const ANOMALY_COOLDOWN: Duration = Duration::from_secs(60 * 60);
/// Requests a minute a throttled handle still gets.
pub const THROTTLE_PER_MINUTE: u32 = 6;

/// Policy refusals for one handle, for the burst detector.
#[derive(Debug, Default)]
pub struct DenialWindow {
    times: VecDeque<Instant>,
    last_incident: Option<Instant>,
}

/// A request parked until the owner decides.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingApproval {
    /// Id (hex in JSON).
    pub id: Id,
    /// `request` (a proxied call is waiting) or `access` (MCP `request_access`).
    pub kind: String,
    /// Handle.
    pub handle_id: Id,
    /// Handle label.
    pub label: String,
    /// Secret name.
    pub secret: String,
    /// Caller identity.
    pub caller: String,
    /// Method (empty for access requests).
    pub method: String,
    /// Host (empty for access requests).
    pub host: String,
    /// Path (empty for access requests).
    pub path: String,
    /// Human description of what approval covers.
    pub scope: String,
    /// Rule text remembered when the owner answers "always".
    pub remember_key: Option<String>,
    /// Unix ms.
    pub created_at: i64,
    /// Unix ms after which the request gives up.
    pub expires_at: i64,
}

/// Pending approvals, parked until the owner decides or they time out.
#[derive(Default)]
pub struct Approvals {
    pending: std::collections::HashMap<Id, (PendingApproval, oneshot::Sender<(bool, bool)>)>,
}

/// Sliding request counters for one handle.
#[derive(Debug, Default)]
pub struct UsageWindow {
    minute: VecDeque<Instant>,
    day: VecDeque<Instant>,
}

impl UsageWindow {
    /// A window rebuilt from audit timestamps (Unix ms, oldest first), as it
    /// would look had the daemon counted those requests itself at `now`.
    fn seeded(uses: &[i64], now_ms: i64, now: Instant) -> Self {
        let mut w = Self::default();
        for &ts in uses {
            let age = Duration::from_millis((now_ms - ts).max(0) as u64);
            let at = now.checked_sub(age).unwrap_or(now);
            if age < Duration::from_secs(60) {
                w.minute.push_back(at);
            }
            if age < Duration::from_secs(86_400) {
                w.day.push_back(at);
            }
        }
        w
    }

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
    /// Last authenticated or brokered request, for idle locking.
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
    /// Per-handle policy refusals, for the burst detector.
    pub denials: Mutex<HashMap<Id, DenialWindow>>,
    /// Outbound HTTP client (rustls, no redirects).
    pub http: reqwest::Client,
    /// Logical host → origin to actually connect to (tests, staging).
    pub upstream_overrides: HashMap<String, String>,
    /// `http://127.0.0.1:<port>`, for setup snippets.
    pub base_url: String,
    /// Parked requests and remembered decisions.
    pub approvals: Mutex<Approvals>,
    /// Registered MCP clients.
    pub callers: crate::callers::Callers,
    /// Whether the MCP `store_secret` tool is enabled.
    pub mcp_allow_store: bool,
    /// OAuth access tokens held for `oauth2_client` secrets. Memory only.
    pub oauth: Mutex<crate::oauth::TokenCache>,
    /// The same tokens for the scrubber: (`<secret>.access_token`, value).
    pub live_tokens: RwLock<Vec<(String, unseenkey_core::crypto::SecretBytes)>>,
}

impl AppState {
    /// Lock the vault if it is unlocked: audit with `reason`, drop keys, clear
    /// the scrubber, notify subscribers. Shared by the API, the idle timer and
    /// the OS hooks. Returns whether anything changed.
    pub async fn lock_vault(&self, reason: &'static str) -> bool {
        {
            let mut v = self.vault.lock().await;
            if v.is_locked() {
                return false;
            }
            let _ = v.audit(
                unseenkey_core::audit::kinds::LOCK,
                serde_json::json!({ "reason": reason }),
            );
            v.lock();
        }
        self.clear_scrubber();
        self.live_tokens
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.oauth.lock().await.clear();
        self.emit(Event::Locked { reason });
        tracing::info!(reason, "vault locked");
        true
    }

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

    /// Replace every handle's sliding windows with what the audit log says
    /// happened in the last day (`uses` from `Vault::recent_uses`, oldest
    /// first). Called on unlock, so per-minute and per-day caps hold across a
    /// daemon restart instead of starting from zero.
    pub async fn seed_usage(&self, uses: &[(Id, i64)], now_ms: i64) {
        let now = Instant::now();
        let mut by_handle: HashMap<Id, Vec<i64>> = HashMap::new();
        for (id, ts) in uses {
            by_handle.entry(*id).or_default().push(*ts);
        }
        let mut map = self.usage.lock().await;
        map.clear();
        for (id, times) in by_handle {
            map.insert(id, UsageWindow::seeded(&times, now_ms, now));
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

    /// Count a policy refusal for a handle. Returns how many refusals the
    /// last minute holds when that count just reached the threshold and no
    /// incident was raised on the handle in the last hour; `None` otherwise.
    pub async fn record_denial(&self, handle: &Id) -> Option<usize> {
        let now = Instant::now();
        let mut map = self.denials.lock().await;
        let w = map.entry(*handle).or_default();
        while w
            .times
            .front()
            .is_some_and(|t| now.duration_since(*t) >= DENIAL_BURST_WINDOW)
        {
            w.times.pop_front();
        }
        w.times.push_back(now);
        if w.times.len() < DENIAL_BURST_THRESHOLD {
            return None;
        }
        if w.last_incident
            .is_some_and(|t| now.duration_since(t) < ANOMALY_COOLDOWN)
        {
            return None;
        }
        w.last_incident = Some(now);
        let n = w.times.len();
        w.times.clear();
        Some(n)
    }

    /// Forget a handle's refusals and cool-down (when the owner resumes it).
    pub async fn reset_denials(&self, handle: &Id) {
        self.denials.lock().await.remove(handle);
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
        // Access tokens obtained for OAuth secrets are guarded like stored values.
        values.extend(
            self.live_tokens
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .cloned(),
        );
        let guarded: Vec<Guarded<'_>> = values
            .iter()
            .map(|(n, v)| Guarded { name: n, value: v })
            .collect();
        let scrubber = Scrubber::new(&guarded);
        set_redactor(scrubber.clone());
        *self.scrubber.write().unwrap_or_else(|e| e.into_inner()) = scrubber;
    }

    /// Park a request; the receiver resolves with (allowed, remember).
    pub async fn approval_create(&self, p: PendingApproval) -> oneshot::Receiver<(bool, bool)> {
        let (tx, rx) = oneshot::channel();
        self.approvals.lock().await.pending.insert(p.id, (p, tx));
        rx
    }

    /// Forget a pending approval (after a decision or timeout).
    pub async fn approval_remove(&self, id: &Id) {
        self.approvals.lock().await.pending.remove(id);
    }

    /// Pending approvals, oldest first.
    pub async fn approvals_pending(&self) -> Vec<PendingApproval> {
        let mut v: Vec<PendingApproval> = self
            .approvals
            .lock()
            .await
            .pending
            .values()
            .map(|(p, _)| p.clone())
            .collect();
        v.sort_by_key(|p| p.created_at);
        v
    }

    /// Decide a pending approval. `None` if unknown (already decided or expired).
    pub async fn approval_decide(
        &self,
        id: &Id,
        allow: bool,
        remember: bool,
    ) -> Option<PendingApproval> {
        let (p, tx) = self.approvals.lock().await.pending.remove(id)?;
        let _ = tx.send((allow, remember));
        self.emit(Event::ApprovalDecided {
            id: id.to_hex(),
            allowed: allow,
        });
        Some(p)
    }

    /// Guard an access token just obtained for an OAuth secret (replacing the
    /// previous one). The caller rebuilds the scrubber.
    pub fn set_live_token(&self, secret_name: &str, token: unseenkey_core::crypto::SecretBytes) {
        let name = format!("{secret_name}.access_token");
        let mut live = self.live_tokens.write().unwrap_or_else(|e| e.into_inner());
        live.retain(|(n, _)| *n != name);
        live.push((name, token));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_window_matches_what_counting_would_have_given() {
        let now_ms = 1_000_000_000_000;
        let now = Instant::now();
        // Three requests in the last minute, two more earlier today, one
        // yesterday (out of the day window), one with a clock skewed into
        // the future (counted as "now").
        let uses = [
            now_ms - 90_000_000,
            now_ms - 3_600_000,
            now_ms - 120_000,
            now_ms - 59_000,
            now_ms - 30_000,
            now_ms - 1,
            now_ms + 5_000,
        ];
        let mut w = UsageWindow::seeded(&uses, now_ms, now);
        assert_eq!(w.minute.len(), 4);
        assert_eq!(w.day.len(), 6);
        // The entries age like real ones.
        w.prune(now + Duration::from_secs(2));
        assert_eq!(w.minute.len(), 3);
        assert_eq!(w.day.len(), 6);
        assert!(UsageWindow::seeded(&[], now_ms, now).day.is_empty());
    }
}
