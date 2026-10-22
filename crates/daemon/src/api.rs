//! `/v1` management API handlers.

use crate::state::{AppState, Event};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use unseenkey_core::audit::kinds;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::handles::{Anomaly, AnomalyResponse, HandleRecord, HandleStatus};
use unseenkey_core::ids::Id;
use unseenkey_core::policy::{explain, Policy};
use unseenkey_core::presets;
use unseenkey_core::providers;
use unseenkey_core::vault::HandleOptions;
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
            VaultError::UnlockMethodNotFound => (S::NOT_FOUND, "unlock_method_not_found"),
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
            VaultError::HandleNotFound => (S::NOT_FOUND, "handle_not_found"),
            VaultError::LabelExists(_) => (S::CONFLICT, "label_exists"),
            VaultError::PolicyWidensHosts => (S::BAD_REQUEST, "policy_widens_hosts"),
            VaultError::InvalidPolicy(_) => (S::BAD_REQUEST, "invalid_policy"),
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

/// `POST /v1/unlock` body: either the password, or a device unlock method's
/// `wrap_id` with the 32-byte KEK (base64) the device derived for it.
#[derive(Deserialize)]
pub struct UnlockRequest {
    /// The vault password. Zeroized after use (JSON parser buffers excepted).
    #[serde(default)]
    pub password: Option<Zeroizing<String>>,
    /// Device unlock method id (hex), from `GET /v1/unlock-methods`.
    #[serde(default)]
    pub wrap_id: Option<String>,
    /// The method's KEK, base64, 32 bytes. Zeroized after use.
    #[serde(default)]
    pub kek: Option<Zeroizing<String>>,
}

fn decode_b64_32(s: &str, what: &str) -> Result<Zeroizing<[u8; 32]>, ApiError> {
    use base64::Engine as _;
    let bytes = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .map_err(|_| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid",
                    format!("{what}: not base64"),
                )
            })?,
    );
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid",
            format!("{what}: expected 32 bytes"),
        )
    })?;
    Ok(Zeroizing::new(arr))
}

/// `POST /v1/unlock`
pub async fn unlock(
    State(s): State<Arc<AppState>>,
    Json(req): Json<UnlockRequest>,
) -> ApiResult<serde_json::Value> {
    let shape_ok = matches!(
        (&req.password, &req.wrap_id, &req.kek),
        (Some(_), None, None) | (None, Some(_), Some(_))
    );
    if !shape_ok {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid",
            "send either password, or wrap_id and kek",
        ));
    }
    if !s.unlock_allowed(5, Duration::from_secs(60)).await {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many unlock attempts; wait a minute",
        ));
    }
    let mut v = s.vault.lock().await;
    let method = match (&req.password, &req.wrap_id, &req.kek) {
        (Some(password), None, None) => {
            let pw = SecretBytes::from_slice(password.as_bytes());
            // Argon2id takes up to a second: keep it off the async threads.
            tokio::task::block_in_place(|| {
                v.reload_header()?;
                v.unlock_with_password(&pw)
            })?;
            "password"
        }
        (None, Some(wrap_id), Some(kek)) => {
            let id = Id::from_hex(wrap_id.trim()).ok_or_else(|| {
                ApiError::new(
                    StatusCode::NOT_FOUND,
                    "unlock_method_not_found",
                    "no such unlock method",
                )
            })?;
            let kek = decode_b64_32(kek, "kek")?;
            let kek = SecretBytes::from_slice(kek.as_slice());
            v.reload_header()?;
            v.unlock_with_kek(&id, &kek)?;
            "device"
        }
        _ => unreachable!("shape checked above"),
    };
    if let Some(problem) = v.audit_head_problem() {
        tracing::warn!(
            ?problem,
            "the audit log was cut short or rewritten while the vault was locked; see the audit_tampered event"
        );
    }
    let _ = v.audit(kinds::UNLOCK, serde_json::json!({ "method": method }));
    s.rebuild_scrubber(&v);
    drop(v);
    s.emit(Event::Unlocked);
    tracing::info!("vault unlocked");
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `POST /v1/lock`
///
/// The body is taken even though it is ignored: a handler that answers while
/// request bytes are still unread makes hyper close the connection with data
/// pending, and Windows then discards the response already sent to the
/// client ("connection aborted"). Seen intermittently on CI.
pub async fn lock(
    State(s): State<Arc<AppState>>,
    _body: axum::body::Bytes,
) -> ApiResult<serde_json::Value> {
    s.lock_vault("request").await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `GET /v1/unlock-methods` — device unlock methods. Readable while locked:
/// the desktop app needs the salt before it can unlock.
pub async fn unlock_methods_list(
    State(s): State<Arc<AppState>>,
) -> ApiResult<Vec<serde_json::Value>> {
    use base64::Engine as _;
    let mut v = s.vault.lock().await;
    // Another process may have enrolled or removed a method.
    let _ = v.reload_header();
    Ok(Json(
        v.key_wraps()
            .iter()
            .map(|w| {
                serde_json::json!({
                    "id": w.id.to_hex(), "kind": w.kind, "label": w.label,
                    "salt": base64::engine::general_purpose::STANDARD.encode(w.salt),
                    "created_at": w.created_at,
                })
            })
            .collect(),
    ))
}

/// `POST /v1/unlock-methods` body.
#[derive(Deserialize)]
pub struct AddUnlockMethod {
    /// `hello`, `touchid`, `passkey`.
    pub kind: String,
    /// Human label (machine, account).
    pub label: String,
    /// The public challenge the device signs, base64, 32 bytes.
    pub salt: String,
    /// The KEK derived from the device's answer, base64, 32 bytes. Zeroized after use.
    pub kek: Zeroizing<String>,
}

/// `POST /v1/unlock-methods` — enroll a device unlock method (vault must be unlocked).
pub async fn unlock_methods_add(
    State(s): State<Arc<AppState>>,
    Json(req): Json<AddUnlockMethod>,
) -> ApiResult<serde_json::Value> {
    let kind = req.kind.trim();
    if kind.is_empty()
        || kind.len() > 32
        || !kind
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid",
            "kind: use a-z, 0-9, _",
        ));
    }
    let label = req.label.trim();
    if label.len() > 120 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "invalid",
            "label too long",
        ));
    }
    let salt = decode_b64_32(&req.salt, "salt")?;
    let kek = decode_b64_32(&req.kek, "kek")?;
    let kek = SecretBytes::from_slice(kek.as_slice());
    let mut v = s.vault.lock().await;
    let id = v.add_key_wrap(kind, label, *salt, &kek)?;
    let _ = v.audit(
        kinds::UNLOCK_METHOD_ADDED,
        serde_json::json!({ "id": id.to_hex(), "kind": kind, "label": label }),
    );
    tracing::info!(kind, "device unlock method enrolled");
    Ok(Json(serde_json::json!({ "id": id.to_hex() })))
}

/// `DELETE /v1/unlock-methods/{id}` — remove a device unlock method (vault must be unlocked).
pub async fn unlock_methods_remove(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let id = Id::from_hex(id.trim()).ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "unlock_method_not_found",
            "no such unlock method",
        )
    })?;
    let mut v = s.vault.lock().await;
    v.remove_key_wrap(&id)?;
    let _ = v.audit(
        kinds::UNLOCK_METHOD_REMOVED,
        serde_json::json!({ "id": id.to_hex() }),
    );
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
    // AWS credentials arrive as several values at once (key id, secret access
    // key, perhaps a session token), pasted in one of a handful of shapes.
    let aws_text = providers::parse_aws_credentials(&req.value);
    // An OAuth client (refresh token + client id) pasted as JSON or key=value lines.
    let oauth_text = if aws_text.is_none() {
        providers::parse_oauth2_client(&req.value)
    } else {
        None
    };
    let detected = if aws_text.is_some() {
        providers::provider("aws").copied()
    } else {
        providers::detect(req.value.as_bytes())
    };
    let kind = match &req.kind {
        Some(k) => SecretKind::parse(k).ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid_type",
                format!("unknown type {k:?}"),
            )
        })?,
        None if oauth_text.is_some() => SecretKind::Oauth2Client,
        None => detected.map(|d| d.kind).unwrap_or(SecretKind::ApiKey),
    };
    let provider = req
        .provider
        .clone()
        .or_else(|| detected.map(|d| d.provider.to_string()))
        .or_else(|| (kind == SecretKind::AwsCredentials).then(|| "aws".to_string()));
    let is_aws = kind == SecretKind::AwsCredentials || provider.as_deref() == Some("aws");
    let kind = if is_aws && req.kind.is_none() {
        SecretKind::AwsCredentials
    } else {
        kind
    };
    let mut upstreams: Vec<String> = if req.upstreams.is_empty() {
        provider
            .as_deref()
            .and_then(providers::provider)
            .map(|d| d.upstreams.iter().map(|u| u.to_string()).collect())
            .unwrap_or_default()
    } else {
        req.upstreams.clone()
    };
    upstreams = normalize_upstreams(&upstreams)?;
    let mut fields: BTreeMap<String, SecretBytes> = req
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), SecretBytes::from_slice(v.as_bytes())))
        .collect();
    let mut value = SecretBytes::from_slice(req.value.as_bytes());
    // Stored shape for AWS: the secret access key is the value, the key id and
    // any session token are fields.
    if is_aws && !fields.contains_key("access_key_id") {
        let Some(c) = &aws_text else {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "aws_credentials_incomplete",
                "AWS needs an access key id and a secret access key. Paste both (two lines, a ~/.aws/credentials section, the console's CSV, or the JSON printed by `aws sts`), or send the secret access key as the value with a field access_key_id.",
            ));
        };
        value = SecretBytes::from_slice(c.secret_access_key.as_bytes());
        fields.insert(
            "access_key_id".into(),
            SecretBytes::from_slice(c.access_key_id.as_bytes()),
        );
        if let Some(token) = &c.session_token {
            fields.insert(
                "session_token".into(),
                SecretBytes::from_slice(token.as_bytes()),
            );
        }
    }
    // Stored shape for an OAuth client: the refresh token is the value; client
    // id, client secret, token URL and scope are fields.
    if kind == SecretKind::Oauth2Client {
        if !fields.contains_key("client_id") {
            let Some(c) = &oauth_text else {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "oauth_client_incomplete",
                    "an OAuth client needs a client id, a refresh token and a token URL. Paste the JSON your OAuth tooling wrote (client_id, client_secret, refresh_token, token_uri), or send the refresh token as the value with fields client_id and token_url.",
                ));
            };
            value = SecretBytes::from_slice(c.refresh_token.as_bytes());
            let mut put = |name: &str, v: &str| {
                fields.insert(name.to_string(), SecretBytes::from_slice(v.as_bytes()));
            };
            put("client_id", &c.client_id);
            if let Some(v) = &c.client_secret {
                put("client_secret", v);
            }
            if let Some(v) = &c.token_url {
                put("token_url", v);
            }
            if let Some(v) = &c.scope {
                put("scope", v);
            }
        }
        let token_url = fields
            .get("token_url")
            .and_then(|v| core::str::from_utf8(v.expose()).ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "oauth_client_incomplete",
                    "an OAuth client needs its token URL (field token_url): where the refresh token is exchanged",
                )
            })?;
        // https only (plain http for loopback), and a real URL.
        let token_host = unseenkey_core::broker::Upstream::parse(&token_url)
            .ok()
            .filter(|_| token_url.contains("://") && reqwest::Url::parse(&token_url).is_ok())
            .map(|u| u.host)
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_token_url",
                    "token_url must be an https URL",
                )
            })?;
        if upstreams.is_empty() && token_url == providers::GOOGLE_TOKEN_URL {
            upstreams = vec!["*.googleapis.com".to_string()];
        }
        if upstreams.is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "upstream_required",
                "an OAuth client needs the API host(s) it is used with: pass upstreams",
            ));
        }
        // The token endpoint is somewhere the secret is sent: put it on the list.
        if !unseenkey_core::policy::eval::host_allowed(&upstreams, &token_host) {
            upstreams.push(token_host);
        }
    }
    let new = NewSecret {
        name: req.name.clone(),
        kind,
        value,
        fields,
        provider: provider.clone(),
        upstreams: upstreams.clone(),
        tags: req.tags.clone(),
        notes: req.notes.clone(),
    };
    let id = {
        let mut v = s.vault.lock().await;
        let id = v.add(new)?;
        let _ = v.audit(
            kinds::SECRET_CREATED,
            serde_json::json!({ "id": id.to_hex(), "name": req.name.trim(), "provider": provider }),
        );
        s.rebuild_scrubber(&v);
        id
    };
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

/// Hosts as the owner typed them (`https://api.example.com/v1/`, `API.EXAMPLE.COM`,
/// `*.example.com`) become what the host lock compares: a lower-case host, or
/// a wildcard pattern left as is.
fn normalize_upstreams(list: &[String]) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = Vec::new();
    for raw in list {
        let s = raw.trim();
        if s.is_empty() {
            continue;
        }
        let host = if s.contains('*') {
            s.trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_ascii_lowercase()
        } else {
            unseenkey_core::broker::Upstream::parse(s)
                .map_err(|e| {
                    ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_upstream",
                        format!("{raw:?}: {e}; give a host such as api.example.com"),
                    )
                })?
                .host
        };
        if !out.contains(&host) {
            out.push(host);
        }
    }
    Ok(out)
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
    let mut upstreams = match &p.upstreams {
        Some(u) => Some(normalize_upstreams(u)?),
        None => None,
    };
    // A new provider must exist, and brings its hosts along unless the owner
    // named hosts in the same call.
    if let Some(Some(pid)) = &p.provider {
        let preset = presets::get(pid).ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "unknown_provider",
                format!("no preset {pid:?}; `usk presets` lists them"),
            )
        })?;
        if upstreams.is_none() && !preset.upstreams.is_empty() {
            upstreams = Some(preset.upstreams.clone());
        }
    }
    if has_meta {
        v.update_meta(&id, |m| {
            if let Some(n) = p.name.clone() {
                m.name = n;
            }
            if let Some(t) = p.tags.clone() {
                m.tags = t;
            }
            if let Some(u) = upstreams.clone() {
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
    let _ = v.audit(
        kinds::SECRET_UPDATED,
        serde_json::json!({ "id": id.to_hex(), "value_changed": p.value.is_some() }),
    );
    if p.value.is_some() || p.no_scrub.is_some() {
        s.rebuild_scrubber(&v);
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
    let _ = v.audit(
        kinds::SECRET_DELETED,
        serde_json::json!({ "id": id.to_hex() }),
    );
    s.rebuild_scrubber(&v);
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
    let mut v = s.vault.lock().await;
    let id = resolve(&v, &r)?;
    let revealed = v.reveal(&id)?;
    let _ = v.audit(
        kinds::REVEAL,
        serde_json::json!({ "id": id.to_hex(), "reason": req.reason.as_deref().unwrap_or("") }),
    );
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

/// `POST /v1/shutdown` (the body is consumed for the same reason as in `lock`)
pub async fn shutdown(
    State(s): State<Arc<AppState>>,
    _body: axum::body::Bytes,
) -> ApiResult<serde_json::Value> {
    // Signal after this response has been written, so the client sees a clean reply
    // instead of a dropped connection.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        s.request_shutdown();
    });
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `POST /v1/secrets/{ref}/inject` body.
#[derive(Deserialize)]
pub struct InjectRequest {
    /// Environment variable the value will be placed in (audited).
    pub var: Option<String>,
    /// Command line being started (audited; never the value).
    pub command: Option<String>,
}

/// `POST /v1/secrets/{ref}/inject` — plaintext for `usk run`. Only for secrets
/// with `allow_injection`; every call is audited as `inject`.
pub async fn inject_secret(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
    Json(req): Json<InjectRequest>,
) -> ApiResult<RevealResponse> {
    let mut v = s.vault.lock().await;
    let id = resolve(&v, &r)?;
    let meta = v.get(&id)?.clone();
    if !meta.allow_injection {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "injection_not_allowed",
            format!(
                "injection is off for {n}; the process would see the value. Enable it with: usk secret set {n} --allow-injection true",
                n = meta.name
            ),
        ));
    }
    let revealed = v.reveal(&id)?;
    let _ = v.audit(
        kinds::INJECT,
        serde_json::json!({
            "id": id.to_hex(), "name": meta.name,
            "var": req.var.as_deref().unwrap_or(""),
            "command": req.command.as_deref().unwrap_or(""),
        }),
    );
    tracing::info!(secret = %id, var = req.var.as_deref().unwrap_or(""), "secret injected into a process");
    Ok(Json(RevealResponse {
        value: text_or_hex(&revealed.value),
        fields: revealed
            .fields
            .iter()
            .map(|(k, val)| (k.clone(), text_or_hex(val)))
            .collect(),
    }))
}

// ---------- handles ----------

/// `POST /v1/handles` body.
#[derive(Deserialize)]
pub struct CreateHandle {
    /// Secret name or id.
    pub secret: String,
    /// Label; defaults to the secret name.
    pub label: Option<String>,
    /// A preset policy such as `stripe:payments`. When omitted and `policy` is
    /// absent, the provider's first (recommended) policy is used, or "full" for
    /// secrets without a provider.
    pub preset_policy: Option<String>,
    /// An inline policy document.
    pub policy: Option<Policy>,
    /// Expiry in days from now.
    pub expires_in_days: Option<u32>,
    /// Give the handle the shape of the provider's own keys (D-26), for tools
    /// that refuse anything else. Off by default: the canonical `usk_h_…` form
    /// cannot be mistaken for a key.
    #[serde(default)]
    pub camouflage: bool,
    /// Requests per day, replacing the policy's own limit. A hard stop.
    pub cap_per_day: Option<u32>,
    /// Requests per minute, replacing the policy's own limit.
    pub cap_per_minute: Option<u32>,
    /// A canary: a handle that never works. Any use at all means whoever sent
    /// it has the file it was planted in; the response is `on_anomaly`
    /// (`lock` unless told otherwise).
    #[serde(default)]
    pub canary: bool,
    /// What unusual activity does to the handle: `alert`, `throttle`
    /// (default), `approve`, `pause` or `lock`.
    pub on_anomaly: Option<AnomalyResponse>,
}

/// What a handle looks like to owners. Never includes the handle string
/// except in the creation response.
#[derive(Serialize)]
pub struct HandleView {
    /// Handle id (hex).
    pub id: String,
    /// Label.
    pub label: String,
    /// Secret name.
    pub secret: String,
    /// Secret id (hex).
    pub secret_id: String,
    /// Provider id.
    pub provider: Option<String>,
    /// Plain-English policy.
    pub policy_explanation: String,
    /// The policy itself.
    pub policy: Policy,
    /// Unix ms.
    pub created_at: i64,
    /// Unix ms.
    pub expires_at: Option<i64>,
    /// Unix ms.
    pub revoked_at: Option<i64>,
    /// Uses.
    pub use_count: u64,
    /// Unix ms.
    pub last_used_at: Option<i64>,
    /// Usable now?
    pub active: bool,
    /// Rules the owner approved with "allow always"; cleared when the policy changes.
    pub remembered: Vec<String>,
    /// A tripwire rather than a working handle.
    pub canary: bool,
    /// What unusual activity does to it.
    pub on_anomaly: AnomalyResponse,
    /// Standing right now: `normal`, `throttled` (with `until`),
    /// `approval_required` or `paused`.
    pub status: HandleStatus,
    /// The incident behind `status`, until the owner resumes the handle.
    pub last_anomaly: Option<Anomaly>,
}

/// Creation response: the only place the handle string appears.
#[derive(Serialize)]
pub struct HandleCreated {
    /// The view.
    #[serde(flatten)]
    pub view: HandleView,
    /// The handle string. Shown once.
    pub handle: String,
    /// Environment variables an SDK needs, when the provider has a preset.
    pub env: BTreeMap<String, String>,
    /// Base URL for this provider through the local broker.
    pub base_url: Option<String>,
}

fn handle_view(v: &crate::state::DaemonVault, h: &HandleRecord, now: i64) -> HandleView {
    let (secret, provider) = v
        .get(&h.secret_id)
        .map(|m| (m.name.clone(), m.provider.clone()))
        .unwrap_or_else(|_| ("(deleted)".into(), None));
    HandleView {
        id: h.handle_id.to_hex(),
        label: h.label.clone(),
        secret,
        secret_id: h.secret_id.to_hex(),
        provider,
        policy_explanation: explain(&h.policy),
        policy: h.policy.clone(),
        created_at: h.created_at,
        expires_at: h.expires_at,
        revoked_at: h.revoked_at,
        use_count: h.use_count,
        last_used_at: h.last_used_at,
        active: h.is_active(now),
        remembered: h.remembered.clone(),
        canary: h.canary,
        on_anomaly: h.on_anomaly,
        status: h.status_at(now),
        last_anomaly: h.last_anomaly.clone(),
    }
}

fn now_ms() -> i64 {
    unseenkey_core::time::Clock::now_unix_ms(&unseenkey_core::time::SystemClock)
}

fn resolve_handle(v: &crate::state::DaemonVault, r: &str) -> Result<Id, ApiError> {
    if let Some(id) = Id::from_hex(r) {
        if v.handle(&id).is_ok() {
            return Ok(id);
        }
    }
    Ok(v.handle_by_label(r)?.handle_id)
}

/// `POST /v1/handles`
pub async fn create_handle(
    State(s): State<Arc<AppState>>,
    Json(req): Json<CreateHandle>,
) -> Result<(StatusCode, Json<HandleCreated>), ApiError> {
    let mut v = s.vault.lock().await;
    let secret_id = resolve(&v, &req.secret)?;
    let meta = v.get(&secret_id)?.clone();
    let mut policy = match (&req.policy, &req.preset_policy) {
        // A canary never resolves, so its policy is the empty one: it can do nothing.
        _ if req.canary => Policy::default(),
        (Some(p), _) => p.clone(),
        (None, Some(spec)) => presets::policy_ref(spec)
            .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "invalid_policy", e.to_string()))?,
        (None, None) => match meta.provider.as_deref().and_then(presets::get) {
            Some(p) => p
                .policies
                .first()
                .and_then(|pp| p.policy(&pp.id))
                .unwrap_or_else(Policy::allow_all),
            None => Policy::allow_all(),
        },
    };
    for (cap, slot) in [
        (req.cap_per_day, &mut policy.limits.requests_per_day),
        (req.cap_per_minute, &mut policy.limits.requests_per_minute),
    ] {
        if let Some(n) = cap {
            if n == 0 {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_cap",
                    "a cap must be at least 1; revoke the handle to stop it entirely",
                ));
            }
            *slot = Some(n);
        }
    }
    let opts = HandleOptions {
        canary: req.canary,
        on_anomaly: req.on_anomaly.unwrap_or(if req.canary {
            AnomalyResponse::Lock
        } else {
            AnomalyResponse::Throttle
        }),
    };
    let label = req
        .label
        .clone()
        .filter(|l| !l.trim().is_empty())
        .unwrap_or_else(|| meta.name.clone());
    let now = now_ms();
    let expires_at = req.expires_in_days.map(|d| now + d as i64 * 86_400_000);
    let format = if req.camouflage {
        // The format can depend on the kind of key (live or test, project or
        // legacy), so look at the real one.
        let real = v.reveal(&secret_id)?;
        let format = meta
            .provider
            .as_deref()
            .and_then(presets::get)
            .and_then(|p| p.handle_format_for(real.value.expose()));
        Some(format.ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "no_camouflage_format",
                "there is no key-shaped handle format for this provider and kind of key; create a normal handle",
            )
        })?)
    } else {
        None
    };
    let (record, plain) = v.create_handle_with(
        &secret_id,
        &label,
        policy,
        expires_at,
        format.as_ref(),
        opts,
    )?;
    let _ = v.audit(
        kinds::HANDLE_CREATED,
        serde_json::json!({
            "id": record.handle_id.to_hex(), "label": record.label, "secret": meta.name,
            "expires_at": expires_at, "camouflage": req.camouflage, "canary": record.canary,
            "on_anomaly": record.on_anomaly.as_str(),
            "cap_per_day": record.policy.limits.requests_per_day,
            "cap_per_minute": record.policy.limits.requests_per_minute,
        }),
    );
    let view = handle_view(&v, &record, now);
    drop(v);
    let preset = meta.provider.as_deref().and_then(presets::get);
    let base_url = preset.map(|p| format!("{}/p/{}{}", s.base_url, p.id, p.base_path));
    let mut env = BTreeMap::new();
    if let (Some(p), Some(b)) = (preset, &base_url) {
        if let Some(var) = p.env.get("base_url") {
            env.insert(var.clone(), b.clone());
        }
        // Bearer-kind secrets (e.g. Claude Code's OAuth token) go in the
        // provider's bearer variable when it declares one.
        let key_var = if meta.kind == SecretKind::BearerToken {
            p.env.get("oauth_token").or_else(|| p.env.get("api_key"))
        } else {
            p.env.get("api_key")
        };
        if let Some(var) = key_var {
            env.insert(var.clone(), plain.clone());
        }
        // Variables the SDK insists on that carry nothing secret.
        for (name, value) in &p.env_static {
            env.insert(name.clone(), value.clone());
        }
    }
    tracing::info!(handle = %record.handle_id, label = %record.label, "handle created");
    Ok((
        StatusCode::CREATED,
        Json(HandleCreated {
            view,
            handle: plain,
            env,
            base_url,
        }),
    ))
}

/// `GET /v1/handles`
pub async fn list_handles(State(s): State<Arc<AppState>>) -> ApiResult<Vec<HandleView>> {
    let v = s.vault.lock().await;
    let now = now_ms();
    Ok(Json(
        v.handles()?
            .into_iter()
            .map(|h| handle_view(&v, h, now))
            .collect(),
    ))
}

/// `GET /v1/handles/{ref}`
pub async fn get_handle(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
) -> ApiResult<HandleView> {
    let v = s.vault.lock().await;
    let id = resolve_handle(&v, &r)?;
    Ok(Json(handle_view(&v, v.handle(&id)?, now_ms())))
}

/// `PATCH /v1/handles/{ref}` body.
#[derive(Deserialize)]
pub struct PatchHandle {
    /// Replace the policy with a preset policy.
    pub preset_policy: Option<String>,
    /// Replace the policy with an inline document.
    pub policy: Option<Policy>,
    /// Change what unusual activity does to the handle.
    pub on_anomaly: Option<AnomalyResponse>,
}

/// `PATCH /v1/handles/{ref}`
pub async fn patch_handle(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
    Json(p): Json<PatchHandle>,
) -> ApiResult<HandleView> {
    let mut v = s.vault.lock().await;
    let id = resolve_handle(&v, &r)?;
    let policy = match (&p.policy, &p.preset_policy) {
        (Some(pol), _) => Some(pol.clone()),
        (None, Some(spec)) => Some(presets::policy_ref(spec).map_err(|e| {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_policy", e.to_string())
        })?),
        (None, None) if p.on_anomaly.is_some() => None,
        (None, None) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid",
                "pass policy, preset_policy or on_anomaly",
            ))
        }
    };
    if let Some(policy) = policy {
        v.set_handle_policy(&id, policy)?;
        let _ = v.audit(
            kinds::POLICY_CHANGED,
            serde_json::json!({ "id": id.to_hex() }),
        );
    }
    if let Some(r) = p.on_anomaly {
        v.set_handle_response(&id, r)?;
        let _ = v.audit(
            kinds::POLICY_CHANGED,
            serde_json::json!({ "id": id.to_hex(), "on_anomaly": r.as_str() }),
        );
    }
    Ok(Json(handle_view(&v, v.handle(&id)?, now_ms())))
}

/// `POST /v1/handles/{ref}/resume` — back to normal after an incident: the
/// throttle, approval mode or pause ends and the burst detector starts afresh.
pub async fn resume_handle(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
) -> ApiResult<HandleView> {
    let mut v = s.vault.lock().await;
    let id = resolve_handle(&v, &r)?;
    let changed = v.resume_handle(&id)?;
    s.reset_denials(&id).await;
    if changed {
        let _ = v.audit(
            kinds::HANDLE_RESUMED,
            serde_json::json!({ "id": id.to_hex() }),
        );
        tracing::info!(handle = %id, "handle resumed");
    }
    Ok(Json(handle_view(&v, v.handle(&id)?, now_ms())))
}

/// `POST /v1/handles/{ref}/forget` body.
#[derive(Deserialize, Default)]
pub struct ForgetRules {
    /// Only this rule (e.g. `POST /v1/refunds`); all remembered rules when absent.
    pub rule: Option<String>,
}

/// `POST /v1/handles/{ref}/forget` — clear "allow always" decisions.
pub async fn forget_handle_rules(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
    body: Option<Json<ForgetRules>>,
) -> ApiResult<serde_json::Value> {
    let rule = body.and_then(|Json(b)| b.rule);
    let mut v = s.vault.lock().await;
    let id = resolve_handle(&v, &r)?;
    let removed = v.forget_rules(&id, rule.as_deref())?;
    if removed > 0 {
        let _ = v.audit(
            kinds::APPROVAL_FORGOTTEN,
            serde_json::json!({ "id": id.to_hex(), "rule": rule, "removed": removed }),
        );
    }
    Ok(Json(serde_json::json!({ "ok": true, "removed": removed })))
}

/// `DELETE /v1/handles/{ref}` — revoke.
pub async fn revoke_handle(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
) -> ApiResult<serde_json::Value> {
    let mut v = s.vault.lock().await;
    let id = resolve_handle(&v, &r)?;
    v.revoke_handle(&id)?;
    let _ = v.audit(
        kinds::HANDLE_REVOKED,
        serde_json::json!({ "id": id.to_hex() }),
    );
    tracing::info!(handle = %id, "handle revoked");
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ---------- approvals ----------

/// `GET /v1/approvals` — pending requests waiting for the owner.
pub async fn approvals_list(State(s): State<Arc<AppState>>) -> ApiResult<Vec<Value>> {
    let now = unseenkey_core::time::Clock::now_unix_ms(&unseenkey_core::time::SystemClock);
    let items = s
        .approvals_pending()
        .await
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "id": p.id.to_hex(), "kind": p.kind, "handle_id": p.handle_id.to_hex(), "label": p.label,
                "secret": p.secret, "caller": p.caller, "method": p.method, "host": p.host, "path": p.path,
                "scope": p.scope, "remember_key": p.remember_key, "created_at": p.created_at,
                "expires_at": p.expires_at, "seconds_left": ((p.expires_at - now) / 1000).max(0),
            })
        })
        .collect();
    Ok(Json(items))
}

/// `POST /v1/approvals/{id}` body.
#[derive(Deserialize)]
pub struct Decide {
    /// `allow` or `deny`.
    pub decision: String,
    /// Remember for this handle and rule (only meaningful with `allow`).
    #[serde(default)]
    pub remember: bool,
}

/// `POST /v1/approvals/{id}`
pub async fn approvals_decide(
    State(s): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(d): Json<Decide>,
) -> ApiResult<serde_json::Value> {
    let allow = match d.decision.as_str() {
        "allow" => true,
        "deny" => false,
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "invalid",
                "decision must be allow or deny",
            ))
        }
    };
    // Accept "latest" as the newest pending id.
    let id = if id == "latest" {
        match s.approvals_pending().await.last() {
            Some(p) => p.id,
            None => {
                return Err(ApiError::new(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "nothing is waiting for approval",
                ))
            }
        }
    } else {
        Id::from_hex(&id)
            .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid", "bad approval id"))?
    };
    match s.approval_decide(&id, allow, d.remember).await {
        Some(p) => Ok(Json(
            serde_json::json!({ "ok": true, "id": id.to_hex(), "allowed": allow, "label": p.label, "secret": p.secret }),
        )),
        None => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such pending approval (already decided or expired)",
        )),
    }
}

// ---------- callers (MCP clients) ----------

/// `POST /v1/callers` body.
#[derive(Deserialize)]
pub struct CreateCaller {
    /// Client name, e.g. `cursor`, `claude-code`.
    pub name: String,
}

/// `POST /v1/callers` — register an MCP client; returns its token once.
pub async fn callers_create(
    State(s): State<Arc<AppState>>,
    Json(req): Json<CreateCaller>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let now = unseenkey_core::time::Clock::now_unix_ms(&unseenkey_core::time::SystemClock);
    let token = s
        .callers
        .create(&req.name, now)
        .map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, "invalid_caller", e.to_string()))?;
    tracing::info!(caller = %req.name, "mcp client registered");
    Ok((
        StatusCode::CREATED,
        Json(
            serde_json::json!({ "name": req.name, "caller": format!("mcp:{}", req.name), "token": token }),
        ),
    ))
}

/// `GET /v1/callers`
pub async fn callers_list(State(s): State<Arc<AppState>>) -> ApiResult<Vec<Value>> {
    Ok(Json(
        s.callers
            .list()
            .into_iter()
            .map(|(n, e)| serde_json::json!({ "name": n, "caller": format!("mcp:{n}"), "created_at": e.created_at, "last_seen_at": e.last_seen_at }))
            .collect(),
    ))
}

/// `DELETE /v1/callers/{name}`
pub async fn callers_remove(
    State(s): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> ApiResult<Value> {
    let removed = s
        .callers
        .remove(&name)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "io", e.to_string()))?;
    if !removed {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such caller",
        ));
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ---------- audit ----------

/// `GET /v1/audit` query.
#[derive(Deserialize)]
pub struct AuditQuery {
    /// Start at this sequence number.
    #[serde(default)]
    pub since: u64,
    /// Only this kind.
    pub kind: Option<String>,
    /// At most this many (default 100, max 1000).
    pub limit: Option<usize>,
}

/// `GET /v1/audit`
pub async fn audit_list(
    State(s): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<AuditQuery>,
) -> ApiResult<Vec<unseenkey_core::audit::AuditEvent>> {
    let v = s.vault.lock().await;
    let limit = q.limit.unwrap_or(100).min(1000);
    Ok(Json(v.audit_events(q.since, q.kind.as_deref(), limit)?))
}

/// `GET /v1/audit/verify`
pub async fn audit_verify(State(s): State<Arc<AppState>>) -> ApiResult<serde_json::Value> {
    let v = s.vault.lock().await;
    let report = v.audit_verify()?;
    Ok(Json(serde_json::json!({
        "ok": report.ok(), "rows": report.rows, "first_broken": report.first_broken, "contiguous": report.contiguous,
        "head": report.head, "head_checked": report.head_checked(),
    })))
}

/// Fallback for unknown routes.
pub async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such route")
}
