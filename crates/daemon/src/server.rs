//! Start and stop the daemon.

use crate::api;
use crate::guard::{ingress_guard, require_token};
use crate::paths::VaultPaths;
use crate::proxy;
use crate::state::AppState;
use crate::token::{self, SessionToken};
use axum::middleware::from_fn_with_state;
use axum::routing::{any, get, post};
use axum::Router;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, watch, Mutex};
use tokio::task::JoinHandle;
use unseenkey_core::audit::kinds;
use unseenkey_core::broker::scrub::Scrubber;
use unseenkey_core::presets;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;

/// Startup failures.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Refusing to listen anywhere but loopback.
    #[error("refusing to listen on non-loopback address {0}")]
    NotLoopback(String),
    /// Bad listen string.
    #[error("invalid listen address {0}")]
    BadAddress(String),
    /// Socket error.
    #[error("cannot bind {0}: {1}")]
    Bind(String, std::io::Error),
    /// Vault problems.
    #[error(transparent)]
    Vault(#[from] unseenkey_core::vault::VaultError),
    /// Storage problems.
    #[error(transparent)]
    Storage(#[from] unseenkey_core::storage::StorageError),
    /// Runtime file problems.
    #[error("cannot write {0}: {1}")]
    File(PathBuf, std::io::Error),
}

/// How to start.
#[derive(Debug, Clone)]
pub struct ServeOptions {
    /// The vault file (must exist).
    pub vault_path: PathBuf,
    /// Loopback `host:port`; port 0 for ephemeral.
    pub listen: String,
    /// Idle lock in minutes; 0 disables.
    pub idle_lock_minutes: u64,
    /// Write `daemon.token`, `daemon.addr`, `daemon.pid` next to the vault.
    pub write_runtime_files: bool,
    /// Logical host → origin to connect to instead (tests and staging only).
    pub upstream_overrides: Vec<(String, String)>,
    /// Enable the MCP `store_secret` tool.
    pub mcp_allow_store: bool,
    /// Lock when the machine suspends or wakes from a suspend.
    pub lock_on_sleep: bool,
    /// Lock when the interactive session locks (Windows only for now).
    pub lock_on_session_lock: bool,
}

/// A running daemon.
pub struct Running {
    /// Bound address.
    pub addr: SocketAddr,
    token: SessionToken,
    state: Arc<AppState>,
    handle: JoinHandle<()>,
    paths: Option<VaultPaths>,
}

impl Running {
    /// Plaintext session token (tests and in-process clients).
    pub fn token(&self) -> &str {
        self.token.plain()
    }

    /// Request shutdown and wait for the server to finish.
    pub async fn shutdown(self) {
        self.state.request_shutdown();
        self.wait().await;
    }

    /// Lock the vault now (for hosts that get their own OS signals).
    pub async fn lock_vault(&self, reason: &'static str) -> bool {
        self.state.lock_vault(reason).await
    }

    /// Resolves once a shutdown has been requested (by the API or [`Running::shutdown`]).
    pub async fn shutdown_requested(&self) {
        let mut rx = self.state.shutdown.subscribe();
        let _ = rx.wait_for(|v| *v).await;
    }

    /// Wait until the server stops (after a shutdown request).
    pub async fn wait(self) {
        let _ = self.handle.await;
        {
            let mut v = self.state.vault.lock().await;
            if !v.is_locked() {
                let _ = v.audit(kinds::LOCK, serde_json::json!({ "reason": "shutdown" }));
            }
            v.lock();
        }
        if let Some(p) = &self.paths {
            let _ = std::fs::remove_file(&p.token);
            let _ = std::fs::remove_file(&p.addr);
            let _ = std::fs::remove_file(&p.pid);
        }
        tracing::info!("daemon stopped");
    }
}

fn allowed_hosts(addr: SocketAddr) -> HashSet<String> {
    let port = addr.port();
    [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ]
    .into_iter()
    .collect()
}

/// Open the vault (locked), bind the loopback socket and start serving.
pub async fn serve(opts: ServeOptions) -> Result<Running, ServeError> {
    let requested: SocketAddr = opts
        .listen
        .parse()
        .map_err(|_| ServeError::BadAddress(opts.listen.clone()))?;
    if !requested.ip().is_loopback() {
        return Err(ServeError::NotLoopback(opts.listen.clone()));
    }
    // Providers the owner added without rebuilding: `<vault dir>/presets/<id>.toml`.
    let (user_presets, problems) =
        presets::load_user_dir(&VaultPaths::from_vault_file(&opts.vault_path).presets);
    if !user_presets.is_empty() {
        tracing::info!(presets = ?user_presets, "user presets loaded");
    }
    for p in problems {
        tracing::warn!("user preset skipped: {p}");
    }
    let storage = SqliteStorage::open(&opts.vault_path)?;
    let vault = Vault::open(storage, SystemClock)?;
    // reqwest is built without a default TLS provider; use ring (pure Rust).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|e| ServeError::Bind("http client".into(), std::io::Error::other(e)))?;

    let listener = TcpListener::bind(requested)
        .await
        .map_err(|e| ServeError::Bind(opts.listen.clone(), e))?;
    let addr = listener
        .local_addr()
        .map_err(|e| ServeError::Bind(opts.listen.clone(), e))?;

    let token = SessionToken::generate();
    let (events, _) = broadcast::channel(64);
    let state = Arc::new(AppState {
        vault: Mutex::new(vault),
        token_hash: token.hash(),
        allowed_hosts: allowed_hosts(addr),
        last_activity: Mutex::new(Instant::now()),
        unlock_attempts: Mutex::new(Vec::new()),
        events,
        started: Instant::now(),
        idle_lock: Duration::from_secs(opts.idle_lock_minutes * 60),
        shutdown: watch::channel(false).0,
        scrubber: RwLock::new(Scrubber::empty()),
        usage: Mutex::new(HashMap::new()),
        denials: Mutex::new(HashMap::new()),
        http,
        upstream_overrides: opts.upstream_overrides.iter().cloned().collect(),
        base_url: format!("http://127.0.0.1:{}", addr.port()),
        approvals: Mutex::new(Default::default()),
        callers: crate::callers::Callers::load(
            &VaultPaths::from_vault_file(&opts.vault_path)
                .mcp
                .join("clients.json"),
        ),
        mcp_allow_store: opts.mcp_allow_store,
        oauth: Mutex::new(Default::default()),
        live_tokens: RwLock::new(Vec::new()),
    });

    let paths = if opts.write_runtime_files {
        let p = VaultPaths::from_vault_file(&opts.vault_path);
        token::write_token_file(&p.token, &token)
            .map_err(|e| ServeError::File(p.token.clone(), e))?;
        std::fs::write(&p.addr, addr.to_string())
            .map_err(|e| ServeError::File(p.addr.clone(), e))?;
        std::fs::write(&p.pid, std::process::id().to_string())
            .map_err(|e| ServeError::File(p.pid.clone(), e))?;
        Some(p)
    } else {
        None
    };

    let v1 = Router::new()
        .route("/status", get(api::status))
        .route("/unlock", post(api::unlock))
        .route("/lock", post(api::lock))
        .route(
            "/unlock-methods",
            get(api::unlock_methods_list).post(api::unlock_methods_add),
        )
        .route(
            "/unlock-methods/{id}",
            axum::routing::delete(api::unlock_methods_remove),
        )
        .route("/secrets", get(api::list_secrets).post(api::create_secret))
        .route(
            "/secrets/{r}",
            get(api::get_secret)
                .patch(api::patch_secret)
                .delete(api::delete_secret),
        )
        .route("/secrets/{r}/reveal", post(api::reveal_secret))
        .route("/secrets/{r}/inject", post(api::inject_secret))
        .route("/events", get(api::events))
        .route("/handles", get(api::list_handles).post(api::create_handle))
        .route(
            "/handles/{r}",
            get(api::get_handle)
                .patch(api::patch_handle)
                .delete(api::revoke_handle),
        )
        .route("/handles/{r}/forget", post(api::forget_handle_rules))
        .route("/handles/{r}/resume", post(api::resume_handle))
        .route("/audit", get(api::audit_list))
        .route("/audit/verify", get(api::audit_verify))
        .route("/approvals", get(api::approvals_list))
        .route("/approvals/{id}", post(api::approvals_decide))
        .route("/callers", get(api::callers_list).post(api::callers_create))
        .route(
            "/callers/{name}",
            axum::routing::delete(api::callers_remove),
        )
        .route("/shutdown", post(api::shutdown))
        .route_layer(from_fn_with_state(state.clone(), require_token));

    let app = Router::new()
        .route("/healthz", get(api::healthz))
        .route("/p/{preset}", any(proxy::proxy))
        // AWS JSON and query protocols POST to the endpoint root: `/p/aws/`.
        .route("/p/{preset}/", any(proxy::proxy))
        .route("/p/{preset}/{*rest}", any(proxy::proxy))
        .route("/mcp", post(crate::mcp::mcp_http).get(crate::mcp::mcp_get))
        .nest("/v1", v1)
        .fallback(api::not_found)
        .layer(from_fn_with_state(state.clone(), ingress_guard))
        .with_state(state.clone());

    // Idle lock timer.
    if !state.idle_lock.is_zero() {
        let s = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                let idle = s.last_activity.lock().await.elapsed();
                if idle >= s.idle_lock {
                    s.lock_vault("idle").await;
                }
            }
        });
    }

    // OS hooks: suspend and session lock. Each fires on its own thread and
    // hands the lock to the runtime; `lock_vault` is a no-op when already locked.
    if opts.lock_on_sleep || opts.lock_on_session_lock {
        let (on_sleep, on_session) = (opts.lock_on_sleep, opts.lock_on_session_lock);
        let s = state.clone();
        let rt = tokio::runtime::Handle::current();
        if let Err(e) = crate::platform::watch_system(move |reason| {
            let wanted = (reason == crate::platform::REASON_SLEEP && on_sleep)
                || (reason == crate::platform::REASON_SESSION_LOCK && on_session);
            if wanted {
                let s = s.clone();
                rt.spawn(async move {
                    s.lock_vault(reason).await;
                });
            }
        }) {
            tracing::warn!(error = %e, "system lock notifications unavailable");
        }
    }
    if opts.lock_on_sleep {
        let s = state.clone();
        let rt = tokio::runtime::Handle::current();
        crate::platform::watch_resume(move || {
            let s = s.clone();
            rt.spawn(async move {
                s.lock_vault(crate::platform::REASON_SLEEP).await;
            });
        });
    }

    let mut shutdown_rx = state.shutdown.subscribe();
    let handle = tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            let _ = shutdown_rx.wait_for(|v| *v).await;
        });
        if let Err(e) = server.await {
            tracing::error!(error = %e, "server error");
        }
    });
    tracing::info!(%addr, "daemon listening");

    Ok(Running {
        addr,
        token,
        state,
        handle,
        paths,
    })
}
