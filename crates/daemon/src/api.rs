//! `/v1` management API handlers.

use crate::state::{AppState, Event};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::ids::Id;
use unseenkey_core::providers;
use unseenkey_core::vault::{NewSecret, SecretKind, SecretMeta, VaultError};
use zeroize::Zeroizing;

/// JSON error body: `{ "error": code, "message": text }`.
#[derive(Debug)]
pub struct ApiError {
    /// HTTP status.
    pub status: StatusCode,
    /// Stable machine-readable code.
    pub code: &'static str,
    /// Human text. Never contains secret material.
    pub message: String,
}

impl ApiError {
    /// Build an error.
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": self.code, "message": self.message });
        (self.status, Json(body)).into_response()
    }
}

impl From<VaultError> for ApiError {
    fn from(e: VaultError) -> Self {
        use StatusCode as S;
        let (status, code) = match &e {
            VaultError::Locked => (S::UNAUTHORIZED, "vault_locked"),
            VaultError::WrongCredential => (S::UNAUTHORIZED, "wrong_password"),
            VaultError::NotFound => (S::NOT_FOUND, "not_found"),
            VaultError::NameExists(_) => (S::CONFLICT, "name_exists"),
            VaultError::InvalidName => (S::BAD_REQUEST, "invalid_name"),
            VaultError::Recovery => (S::BAD_REQUEST, "invalid_recovery_phrase"),
            VaultError::WeakKdf => (S::BAD_REQUEST, "weak_kdf"),
            VaultError::NoVault => (S::NOT_FOUND, "no_vault"),
            VaultError::AlreadyExists => (S::CONFLICT, "vault_exists"),
            VaultError::UnsupportedFormat(_) => (S::INTERNAL_SERVER_ERROR, "unsupported_format"),
            VaultError::Corrupt(_) => (S::INTERNAL_SERVER_ERROR, "corrupt_record"),
            VaultError::Storage(_) => (S::INTERNAL_SERVER_ERROR, "storage_error"),
            VaultError::Crypto(_) => (S::INTERNAL_SERVER_ERROR, "crypto_error"),
        };
        ApiError::new(status, code, e.to_string())
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

/// `GET /healthz`
pub async fn healthz() -> &'static str {
    "ok"
}

/// `GET /v1/status`
#[derive(Serialize)]
pub struct Status {
    /// Locked?
    pub locked: bool,
    /// Vault id (hex).
    pub vault_id: String,
    /// Daemon version.
    pub version: &'static str,
    /// Seconds since start.
    pub uptime_s: u64,
    /// Number of secrets, when unlocked.
    pub secrets: Option<usize>,
    /// Idle lock timeout in minutes (0 = off).
    pub idle_lock_minutes: u64,
}

/// `GET /v1/status`
pub async fn status(State(s): State<Arc<AppState>>) -> ApiResult<Status> {
    let v = s.vault.lock().await;
    Ok(Json(Status {
        locked: v.is_locked(),
        vault_id: v.vault_id().to_hex(),
        version: env!("CARGO_PKG_VERSION"),
        uptime_s: s.started.elapsed().as_secs(),
        secrets: if v.is_locked() { None } else { Some(v.len()) },
        idle_lock_minutes: s.idle_lock.as_secs() / 60,
    }))
}

/// `POST /v1/unlock` body.
#[derive(Deserialize)]
pub struct UnlockRequest {
    /// The vault password. Zeroized after use (JSON parser buffers excepted).
    pub password: Zeroizing<String>,
}

/// `POST /v1/unlock`
pub async fn unlock(
    State(s): State<Arc<AppState>>,
    Json(req): Json<UnlockRequest>,
) -> ApiResult<serde_json::Value> {
    if !s.unlock_allowed(5, Duration::from_secs(60)).await {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many unlock attempts; wait a minute",
        ));
    }
    let pw = SecretBytes::from_slice(req.password.as_bytes());
    let mut v = s.vault.lock().await;
    // Argon2id takes up to a second: keep it off the async threads.
    tokio::task::block_in_place(|| {
        v.reload_header()?;
        v.unlock_with_password(&pw)
    })?;
    s.emit(Event::Unlocked);
    tracing::info!("vault unlocked");
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `POST /v1/lock`
pub async fn lock(State(s): State<Arc<AppState>>) -> ApiResult<serde_json::Value> {
    s.vault.lock().await.lock();
    s.emit(Event::Locked { reason: "request" });
    tracing::info!("vault locked by request");
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `GET /v1/secrets`
pub async fn list_secrets(State(s): State<Arc<AppState>>) -> ApiResult<Vec<SecretMeta>> {
    let v = s.vault.lock().await;
    Ok(Json(v.list()?.into_iter().cloned().collect()))
}

/// `POST /v1/secrets` body.
#[derive(Deserialize)]
pub struct CreateSecret {
    /// Unique name.
    pub name: String,
    /// Secret type; auto-detected when omitted.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    /// The value.
    pub value: Zeroizing<String>,
    /// Extra fields.
    #[serde(default)]
    pub fields: BTreeMap<String, Zeroizing<String>>,
    /// Provider id; auto-detected when omitted.
    pub provider: Option<String>,
    /// Allowed hosts; defaults from the provider.
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Notes.
    pub notes: Option<String>,
}

/// `POST /v1/secrets` response.
#[derive(Serialize)]
pub struct Created {
    /// Secret id (hex).
    pub id: String,
    /// Name.
    pub name: String,
    /// Kind.
    #[serde(rename = "type")]
    pub kind: String,
    /// Provider id.
    pub provider: Option<String>,
    /// Locked upstreams.
    pub upstreams: Vec<String>,
    /// What the value looked like.
    pub detected: Option<Detected>,
}

/// Detection summary.
#[derive(Serialize)]
pub struct Detected {
    /// Provider id.
    pub provider: String,
    /// Human name.
    pub display: String,
    /// Extra note.
    pub note: String,
}

/// `POST /v1/secrets`
pub async fn create_secret(
    State(s): State<Arc<AppState>>,
    Json(req): Json<CreateSecret>,
) -> Result<(StatusCode, Json<Created>), ApiError> {
    if req.value.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "empty_value",
            "value is empty",
        ));
    }
    let detected = providers::detect(req.value.as_bytes());
    let provider = req
        .provider
        .clone()
        .or_else(|| detected.map(|d| d.provider.to_string()));
    let kind = match &req.kind {
        Some(k) => SecretKind::parse(k).ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_type",
                format!("unknown type {k:?}"),
            )
        })?,
        None => detected.map(|d| d.kind).unwrap_or(SecretKind::ApiKey),
    };
    let upstreams = if req.upstreams.is_empty() {
        provider
            .as_deref()
            .and_then(providers::provider)
            .map(|d| d.upstreams.iter().map(|u| u.to_string()).collect())
            .unwrap_or_default()
    } else {
        req.upstreams.clone()
    };
    let fields = req
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), SecretBytes::from_slice(v.as_bytes())))
        .collect();
    let new = NewSecret {
        name: req.name.clone(),
        kind,
        value: SecretBytes::from_slice(req.value.as_bytes()),
        fields,
        provider: provider.clone(),
        upstreams: upstreams.clone(),
        tags: req.tags.clone(),
        notes: req.notes.clone(),
    };
    let id = s.vault.lock().await.add(new)?;
    s.emit(Event::SecretChanged {
        id: id.to_hex(),
        change: "created",
    });
    tracing::info!(secret = %id, "secret created");
    Ok((
        StatusCode::CREATED,
        Json(Created {
            id: id.to_hex(),
            name: req.name.trim().to_string(),
            kind: kind.as_str().to_string(),
            provider,
            upstreams,
            detected: detected.map(|d| Detected {
                provider: d.provider.into(),
                display: d.display.into(),
                note: d.note.into(),
            }),
        }),
    ))
}

/// Resolve `{ref}`: a 32-hex id or a name.
fn resolve(v: &crate::state::DaemonVault, r: &str) -> Result<Id, ApiError> {
    if let Some(id) = Id::from_hex(r) {
        if v.get(&id).is_ok() {
            return Ok(id);
        }
    }
    Ok(v.get_by_name(r)?.secret_id)
}

/// `GET /v1/secrets/{ref}`
pub async fn get_secret(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
) -> ApiResult<SecretMeta> {
    let v = s.vault.lock().await;
    let id = resolve(&v, &r)?;
    Ok(Json(v.get(&id)?.clone()))
}

/// `PATCH /v1/secrets/{ref}` body. Every field optional.
#[derive(Deserialize, Default)]
pub struct PatchSecret {
    /// Rename.
    pub name: Option<String>,
    /// Replace tags.
    pub tags: Option<Vec<String>>,
    /// Replace upstreams.
    pub upstreams: Option<Vec<String>>,
    /// Replace notes.
    pub notes: Option<Option<String>>,
    /// Set the provider.
    pub provider: Option<Option<String>>,
    /// Allow env injection.
    pub allow_injection: Option<bool>,
    /// Exclude from scrubbing.
    pub no_scrub: Option<bool>,
    /// New value (creates a new version).
    pub value: Option<Zeroizing<String>>,
    /// New fields, used with `value`.
    #[serde(default)]
    pub fields: BTreeMap<String, Zeroizing<String>>,
}

/// `PATCH /v1/secrets/{ref}`
pub async fn patch_secret(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
    Json(p): Json<PatchSecret>,
) -> ApiResult<SecretMeta> {
    let mut v = s.vault.lock().await;
    let id = resolve(&v, &r)?;
    if let Some(value) = &p.value {
        if value.is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "empty_value",
                "value is empty",
            ));
        }
        let fields = p
            .fields
            .iter()
            .map(|(k, val)| (k.clone(), SecretBytes::from_slice(val.as_bytes())))
            .collect();
        v.update_value(&id, SecretBytes::from_slice(value.as_bytes()), fields)?;
    }
    let has_meta = p.name.is_some()
        || p.tags.is_some()
        || p.upstreams.is_some()
        || p.notes.is_some()
        || p.provider.is_some()
        || p.allow_injection.is_some()
        || p.no_scrub.is_some();
    if has_meta {
        v.update_meta(&id, |m| {
            if let Some(n) = p.name.clone() {
                m.name = n;
            }
            if let Some(t) = p.tags.clone() {
                m.tags = t;
            }
            if let Some(u) = p.upstreams.clone() {
                m.upstreams = u;
            }
            if let Some(n) = p.notes.clone() {
                m.notes = n;
            }
            if let Some(pr) = p.provider.clone() {
                m.provider = pr;
            }
            if let Some(a) = p.allow_injection {
                m.allow_injection = a;
            }
            if let Some(n) = p.no_scrub {
                m.no_scrub = n;
            }
        })?;
    }
    s.emit(Event::SecretChanged {
        id: id.to_hex(),
        change: "updated",
    });
    Ok(Json(v.get(&id)?.clone()))
}

/// `DELETE /v1/secrets/{ref}`
pub async fn delete_secret(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
) -> ApiResult<serde_json::Value> {
    let mut v = s.vault.lock().await;
    let id = resolve(&v, &r)?;
    v.delete(&id)?;
    s.emit(Event::SecretChanged {
        id: id.to_hex(),
        change: "deleted",
    });
    tracing::info!(secret = %id, "secret deleted");
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `POST /v1/secrets/{ref}/reveal` body.
#[derive(Deserialize)]
pub struct RevealRequest {
    /// Must be `true`.
    pub confirm: bool,
    /// Why (recorded in the audit log from M1.4).
    pub reason: Option<String>,
}

/// `POST /v1/secrets/{ref}/reveal` response. The only route that returns plaintext.
#[derive(Serialize)]
pub struct RevealResponse {
    /// Value as text, or `hex:…` for binary.
    pub value: Zeroizing<String>,
    /// Extra fields.
    pub fields: BTreeMap<String, Zeroizing<String>>,
}

fn text_or_hex(b: &SecretBytes) -> Zeroizing<String> {
    Zeroizing::new(match std::str::from_utf8(b.expose()) {
        Ok(s) => s.to_string(),
        Err(_) => format!("hex:{}", hex_of(b.expose())),
    })
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `POST /v1/secrets/{ref}/reveal`
pub async fn reveal_secret(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
    Json(req): Json<RevealRequest>,
) -> ApiResult<RevealResponse> {
    if !req.confirm {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "confirm_required",
            "set confirm=true to reveal a value",
        ));
    }
    let v = s.vault.lock().await;
    let id = resolve(&v, &r)?;
    let revealed = v.reveal(&id)?;
    s.emit(Event::Revealed { id: id.to_hex() });
    tracing::info!(secret = %id, reason = req.reason.as_deref().unwrap_or(""), "secret revealed");
    Ok(Json(RevealResponse {
        value: text_or_hex(&revealed.value),
        fields: revealed
            .fields
            .iter()
            .map(|(k, val)| (k.clone(), text_or_hex(val)))
            .collect(),
    }))
}

/// `GET /v1/events` (server-sent events)
pub async fn events(
    State(s): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = s.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|e| {
        e.ok()
            .and_then(|ev| serde_json::to_string(&ev).ok())
            .map(|json| Ok(SseEvent::default().data(json)))
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

/// `POST /v1/shutdown`
pub async fn shutdown(State(s): State<Arc<AppState>>) -> ApiResult<serde_json::Value> {
    s.request_shutdown();
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Fallback for unknown routes.
pub async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such route")
}
