//! `/p/<preset>/…` — the broker pipeline (docs/07).
//!
//! 1. ingress guard (outer layer) · 2. handle resolution · 3. caller context ·
//! 4. policy (with approvals) · 5. credential materialisation · 6. host lock ·
//! 7. egress guard · 8. forward · 9. scrub · 10. audit before the first byte ·
//! 11. respond.
//!
//! [`execute`] is the pipeline proper; the HTTP handler [`proxy`] and the MCP
//! `call_api` tool both feed it. The vault lock is held only in two short
//! phases, never while waiting for an approval or for the upstream.

use crate::api::ApiError;
use crate::state::{AppState, DaemonVault, Event, PendingApproval, THROTTLE_PER_MINUTE};
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio_stream::Stream;
use unseenkey_core::audit::kinds;
use unseenkey_core::broker::adapters::{self, Injection};
use unseenkey_core::broker::scrub::StreamScrubber;
use unseenkey_core::broker::sigv4;
use unseenkey_core::broker::{
    check_host, is_stripped, split_path_query, BrokerError, Upstream, STRIP_REQUEST_HEADERS,
    STRIP_RESPONSE_HEADERS,
};
use unseenkey_core::handles::{Anomaly, AnomalyResponse, HandleRecord, HandleStatus};
use unseenkey_core::ids::Id;
use unseenkey_core::policy::{
    evaluate, ApprovalScope, Decision, DenyReason, Request as PolicyRequest,
};
use unseenkey_core::presets::{self, Auth, Preset};
use unseenkey_core::vault::{SecretKind, SecretMeta};
use zeroize::Zeroizing;

/// Largest request body we buffer.
pub const MAX_BODY: usize = 32 * 1024 * 1024;

/// Caller identity for loopback requests without a registered caller token.
pub const LOCAL_CALLER: &str = "local";

fn err(status: StatusCode, code: &'static str, msg: impl Into<String>) -> Response {
    ApiError::new(status, code, msg).into_response()
}

fn broker_err(e: BrokerError) -> Response {
    let status = match e {
        BrokerError::HostNotAllowed(_) | BrokerError::UnknownPlaceholder(_) => {
            StatusCode::FORBIDDEN
        }
        _ => StatusCode::BAD_REQUEST,
    };
    err(status, e.code(), e.to_string())
}

/// Find the handle in the place the preset's SDK would put its key.
fn extract_handle(preset: &Preset, headers: &HeaderMap, query: Option<&str>) -> Option<String> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let bearer = || {
        header("authorization").and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            (scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("basic"))
                .then(|| rest.trim().to_string())
        })
    };
    let from_query = |param: &str| {
        query.and_then(|q| {
            q.split('&').find_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                (k == param).then(|| v.to_string())
            })
        })
    };
    if let Some(h) = header("x-usk-handle") {
        return Some(h);
    }
    let primary = match &preset.auth {
        Auth::Bearer { .. } | Auth::Basic => bearer(),
        Auth::Header { name } => header(name),
        Auth::Query { param } => from_query(param),
        // AWS SDKs put their access key id (our handle) inside the SigV4 scope.
        Auth::AwsSigv4 => header("authorization")
            .and_then(|v| sigv4::parse_authorization(&v))
            .map(|scope| scope.access_key_id),
        Auth::Template => None,
    };
    primary
        .or_else(bearer)
        .or_else(|| header("x-api-key"))
        .or_else(|| from_query("key"))
}

/// What an AWS request does, for the audit log: the `X-Amz-Target` header of
/// JSON-protocol services or the `Action` parameter of query-protocol ones.
/// REST services such as S3 say it with the method and path already.
fn aws_action(headers: &HeaderMap, query: Option<&str>, body: &[u8]) -> Option<String> {
    fn clean(s: &str) -> Option<String> {
        let s: String = s
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
            .take(128)
            .collect();
        (!s.is_empty()).then_some(s)
    }
    fn from_pairs(s: &str) -> Option<String> {
        s.split('&')
            .find_map(|kv| kv.strip_prefix("Action="))
            .and_then(clean)
    }
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(target) = header("x-amz-target") {
        return clean(target);
    }
    if let Some(action) = query.and_then(from_pairs) {
        return Some(action);
    }
    let form =
        header("content-type").is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"));
    if form && body.len() <= 64 * 1024 {
        return core::str::from_utf8(body).ok().and_then(from_pairs);
    }
    None
}

fn set_header(headers: &mut reqwest::header::HeaderMap, name: &str, value: &str) {
    if let (Ok(n), Ok(v)) = (
        reqwest::header::HeaderName::from_bytes(name.as_bytes()),
        reqwest::header::HeaderValue::from_str(value),
    ) {
        headers.insert(n, v);
    }
}

/// Remove the query parameter that carried the handle (so it is not forwarded).
fn strip_query_param(query: Option<&str>, param: &str) -> Option<String> {
    let q = query?;
    let kept: Vec<&str> = q
        .split('&')
        .filter(|kv| kv.split_once('=').map(|(k, _)| k) != Some(param))
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join("&"))
    }
}

/// Response body that scrubs secrets as chunks arrive.
struct ScrubBody {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    scrub: StreamScrubber,
    done: bool,
}

impl Stream for ScrubBody {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.done {
                return Poll::Ready(None);
            }
            match self.inner.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => {
                    let out = self.scrub.push(&chunk);
                    if !out.is_empty() {
                        return Poll::Ready(Some(Ok(Bytes::from(out))));
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    self.done = true;
                    return Poll::Ready(Some(Err(std::io::Error::other(e.to_string()))));
                }
                Poll::Ready(None) => {
                    self.done = true;
                    let tail = self.scrub.finish();
                    if !tail.is_empty() {
                        return Poll::Ready(Some(Ok(Bytes::from(tail))));
                    }
                    return Poll::Ready(None);
                }
            }
        }
    }
}

/// An incident on a handle, before it is recorded.
struct Incident {
    /// `denial_burst` or `canary`.
    kind: &'static str,
    /// One sentence for the owner.
    detail: String,
}

/// Record an incident: the audit event, the handle's new standing and the
/// owner's notification. Returns whether the vault must be locked, which the
/// caller does once it has released the vault guard.
#[allow(clippy::too_many_arguments)]
fn raise_incident(
    s: &AppState,
    vault: &mut DaemonVault,
    handle: &HandleRecord,
    secret: &str,
    call: &CallRequest,
    host: &str,
    path: &str,
    now: i64,
    incident: Incident,
) -> bool {
    let response = handle.on_anomaly;
    let kind = if incident.kind == "canary" {
        kinds::CANARY_TRIPPED
    } else {
        kinds::ANOMALY
    };
    let _ = vault.audit(
        kind,
        json!({
            "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": secret,
            "caller": call.caller, "host": host, "method": call.method, "path": path,
            "kind": incident.kind, "detail": incident.detail, "response": response.as_str(),
        }),
    );
    if let Err(e) = vault.set_handle_incident(
        &handle.handle_id,
        Anomaly {
            kind: incident.kind.to_string(),
            detail: incident.detail.clone(),
            at: now,
            response,
        },
    ) {
        tracing::warn!(error = %e, "could not persist the incident on the handle");
    }
    tracing::warn!(
        handle = %handle.handle_id, label = %handle.label, kind = incident.kind,
        response = response.as_str(), "{}", incident.detail
    );
    s.emit(Event::Anomaly {
        id: handle.handle_id.to_hex(),
        label: handle.label.clone(),
        secret: secret.to_string(),
        kind: incident.kind.to_string(),
        detail: incident.detail,
        response: response.as_str(),
    });
    response == AnomalyResponse::Lock
}

/// After a policy refusal: feed the burst detector and, when it fires, raise
/// the incident. Consumes the vault guard so the lock response can run.
#[allow(clippy::too_many_arguments)]
async fn after_denial(
    s: &Arc<AppState>,
    mut vault: tokio::sync::MutexGuard<'_, DaemonVault>,
    handle: &HandleRecord,
    secret: &str,
    call: &CallRequest,
    host: &str,
    path: &str,
    now: i64,
) {
    let Some(n) = s.record_denial(&handle.handle_id).await else {
        return;
    };
    let lock = raise_incident(
        s,
        &mut vault,
        handle,
        secret,
        call,
        host,
        path,
        now,
        Incident {
            kind: "denial_burst",
            detail: format!("{n} requests refused by policy within a minute"),
        },
    );
    drop(vault);
    if lock {
        s.lock_vault("anomaly").await;
    }
}

/// How the caller identified the handle.
pub enum HandleRef {
    /// The handle string as presented by an SDK.
    Presented(String),
    /// A handle the daemon resolved itself (MCP `call_api`).
    Resolved(Id),
}

/// A request to broker, already parsed.
pub struct CallRequest {
    /// Provider preset for the route.
    pub preset: &'static Preset,
    /// HTTP method as sent.
    pub method: String,
    /// Path without query, relative to the provider origin.
    pub path: String,
    /// Query string, if any.
    pub query: Option<String>,
    /// Caller-supplied headers (will be filtered).
    pub headers: HeaderMap,
    /// Request body.
    pub body: Bytes,
    /// Explicit upstream (`X-Usk-Upstream` or `/p/<preset>/@<host>/…`), required
    /// for generic and wildcard presets.
    pub upstream_spec: Option<String>,
    /// `(region, service)` from the caller's own SigV4 header, for AWS.
    pub aws_scope: Option<(String, String)>,
    /// Caller identity for policy and audit.
    pub caller: String,
}

/// Handle `/p/{preset}` and `/p/{preset}/{*rest}`.
pub async fn proxy(State(s): State<Arc<AppState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let uri: Uri = parts.uri.clone();
    let full_path = uri.path().to_string();
    let query = uri.query().map(str::to_string);

    // /p/<preset>/<rest>
    let mut segs = full_path.trim_start_matches('/').splitn(3, '/');
    let _p = segs.next();
    let preset_id = segs.next().unwrap_or("").to_string();
    let rest = segs.next().unwrap_or("");
    // `/p/<preset>/@<host>/<path>` names the upstream in the URL, for SDKs that
    // can change their base URL but cannot add an `X-Usk-Upstream` header. The
    // host lock applies to it exactly as to the header.
    let (path_upstream, path) = match rest.strip_prefix('@') {
        Some(r) => {
            let (host, tail) = r.split_once('/').unwrap_or((r, ""));
            (Some(host.to_string()), format!("/{tail}"))
        }
        None => (None, format!("/{rest}")),
    };
    let Some(preset) = presets::get(&preset_id) else {
        return err(
            StatusCode::NOT_FOUND,
            "unknown_preset",
            format!("no provider preset {preset_id:?}"),
        );
    };
    // SigV4A has no handle we could read out of it; refuse it by name rather
    // than as an unknown handle.
    let authz = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if matches!(preset.auth, Auth::AwsSigv4) && sigv4::is_sigv4a(authz) {
        return err(
            StatusCode::BAD_REQUEST,
            "sigv4a_unsupported",
            "multi-region (SigV4A) signing is not supported; use a regional endpoint",
        );
    }
    let Some(handle_str) = extract_handle(preset, &parts.headers, query.as_deref()) else {
        return err(
            StatusCode::UNAUTHORIZED,
            "unknown_handle",
            "no handle found where this provider expects its key",
        );
    };
    let mut upstream_spec = parts
        .headers
        .get("x-usk-upstream")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or(path_upstream.filter(|h| !h.is_empty()));
    // AWS: the SDK's own SigV4 header says which region and service it signed
    // for; that picks the endpoint unless one was named explicitly.
    let mut aws_scope = None;
    if matches!(preset.auth, Auth::AwsSigv4) {
        if let Some(scope) = sigv4::parse_authorization(authz) {
            if upstream_spec.is_none() {
                match sigv4::host_for(&scope.service, &scope.region) {
                    Some(host) => upstream_spec = Some(host),
                    None => {
                        return err(
                            StatusCode::BAD_REQUEST,
                            "aws_host_required",
                            format!(
                                "cannot tell which endpoint serves {:?} in {:?}; point the SDK at {}/p/aws/@<host>",
                                scope.service, scope.region, s.base_url
                            ),
                        )
                    }
                }
            }
            aws_scope = Some((scope.region, scope.service));
        }
    }
    let body = match axum::body::to_bytes(body, MAX_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return err(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                "request body exceeds 32 MiB",
            )
        }
    };
    let call = CallRequest {
        preset,
        method: parts.method.as_str().to_string(),
        path,
        query,
        headers: parts.headers,
        body,
        upstream_spec,
        aws_scope,
        caller: LOCAL_CALLER.to_string(),
    };
    execute(s, HandleRef::Presented(handle_str), call).await
}

fn now_ms() -> i64 {
    unseenkey_core::time::Clock::now_unix_ms(&unseenkey_core::time::SystemClock)
}

/// Run the pipeline. Returns the upstream's (scrubbed) response, or an error
/// response from the broker itself.
pub async fn execute(s: Arc<AppState>, handle_ref: HandleRef, call: CallRequest) -> Response {
    let started = Instant::now();
    let preset = call.preset;
    let query = call.query.as_deref();

    // Resolve upstream target.
    let upstream_spec = match &call.upstream_spec {
        Some(u) => u.clone(),
        None => match preset.upstreams.first() {
            Some(h) if !h.contains('*') => h.clone(),
            _ => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "upstream_required",
                    "this provider needs an X-Usk-Upstream header naming the host",
                )
            }
        },
    };
    let upstream = match Upstream::parse(&upstream_spec) {
        Ok(u) => u,
        Err(e) => return broker_err(e),
    };
    let (pol_path, _) = split_path_query(&call.path);
    let pol_path = pol_path.to_string();
    let now = now_ms();

    // Phase 1 (vault lock): handle, secret, host lock, policy.
    let (handle, meta, decision): (HandleRecord, SecretMeta, Decision) = {
        let mut vault = s.vault.lock().await;
        if vault.is_locked() {
            return err(
                StatusCode::UNAUTHORIZED,
                "vault_locked",
                "unlock the vault first",
            );
        }
        let handle = match &handle_ref {
            HandleRef::Presented(str) => match vault.handle_by_string(str) {
                Ok(Some(h)) => h.clone(),
                _ => return err(StatusCode::UNAUTHORIZED, "unknown_handle", "unknown handle"),
            },
            HandleRef::Resolved(id) => match vault.handle(id) {
                Ok(h) => h.clone(),
                Err(_) => return err(StatusCode::UNAUTHORIZED, "unknown_handle", "unknown handle"),
            },
        };
        // A canary is a tripwire, not a key: whoever presented it has the
        // file it was planted in. From outside it looks like an unknown handle.
        if handle.canary && handle.revoked_at.is_none() {
            let secret = vault
                .get(&handle.secret_id)
                .map(|m| m.name.clone())
                .unwrap_or_default();
            let lock = raise_incident(
                    &s,
                    &mut vault,
                    &handle,
                    &secret,
                    &call,
                    &upstream.host,
                    &pol_path,
                    now,
                    Incident {
                        kind: "canary",
                        detail: format!(
                            "the canary {:?} was used ({} {} on {}): whoever sent it has the file it was planted in",
                            handle.label, call.method, pol_path, upstream.host
                        ),
                    },
                );
            drop(vault);
            if lock {
                s.lock_vault("canary").await;
            }
            return err(StatusCode::UNAUTHORIZED, "unknown_handle", "unknown handle");
        }
        if handle.revoked_at.is_some() {
            return err(
                StatusCode::UNAUTHORIZED,
                "handle_revoked",
                "this handle was revoked",
            );
        }
        if handle.expires_at.is_some_and(|e| now >= e) {
            return err(
                StatusCode::UNAUTHORIZED,
                "handle_expired",
                "this handle has expired",
            );
        }
        let meta = match vault.get(&handle.secret_id) {
            Ok(m) => m.clone(),
            Err(_) => {
                return err(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "the handle's secret no longer exists",
                )
            }
        };
        // Standing after an incident. These refusals are consequences, so
        // they do not feed the burst detector.
        let standing = handle.status_at(now);
        if standing == HandleStatus::Paused {
            let _ = vault.audit(
                kinds::DENY,
                json!({
                    "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": meta.name,
                    "caller": call.caller, "reason": "paused", "host": upstream.host,
                    "method": call.method, "path": pol_path,
                }),
            );
            return err(
                    StatusCode::FORBIDDEN,
                    "handle_paused",
                    "this handle is paused after unusual activity; the owner can resume it (usk handle resume)",
                );
        }
        // Host lock (INV-2) on the logical host, before any override.
        if let Err(e) = check_host(&meta.upstreams, &handle.policy.upstreams, &upstream.host) {
            let _ = vault.audit(
                kinds::DENY,
                json!({
                    "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": meta.name,
                    "caller": call.caller, "reason": e.code(), "host": upstream.host,
                    "method": call.method, "path": pol_path,
                }),
            );
            after_denial(
                &s,
                vault,
                &handle,
                &meta.name,
                &call,
                &upstream.host,
                &pol_path,
                now,
            )
            .await;
            return broker_err(e);
        }
        let usage = s.usage_for(&handle.handle_id, handle.use_count).await;
        if matches!(standing, HandleStatus::Throttled { .. })
            && usage.last_minute >= THROTTLE_PER_MINUTE
        {
            let _ = vault.audit(
                kinds::DENY,
                json!({
                    "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": meta.name,
                    "caller": call.caller, "reason": "throttled", "host": upstream.host,
                    "method": call.method, "path": pol_path,
                }),
            );
            return err(
                    StatusCode::TOO_MANY_REQUESTS,
                    "throttled",
                    format!(
                        "this handle is throttled after unusual activity: at most {THROTTLE_PER_MINUTE} requests a minute until the owner resumes it or the hour passes"
                    ),
                );
        }
        let preq = PolicyRequest {
            method: &call.method,
            path: &pol_path,
            host: &upstream.host,
            body_len: Some(call.body.len() as u64),
            caller: Some(&call.caller),
        };
        let decision = evaluate(&handle.policy, &preq, now, usage);
        if let Decision::Deny(reason) = &decision {
            let status = match reason {
                DenyReason::RateLimitedMinute | DenyReason::RateLimitedDay => {
                    StatusCode::TOO_MANY_REQUESTS
                }
                _ => StatusCode::FORBIDDEN,
            };
            let _ = vault.audit(
                kinds::DENY,
                json!({
                    "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": meta.name,
                    "caller": call.caller, "reason": reason.code(), "detail": reason.message(),
                    "host": upstream.host, "method": call.method, "path": pol_path,
                }),
            );
            // Running into a cap is the cap doing its job, not probing.
            if !matches!(
                reason,
                DenyReason::RateLimitedMinute | DenyReason::RateLimitedDay
            ) {
                after_denial(
                    &s,
                    vault,
                    &handle,
                    &meta.name,
                    &call,
                    &upstream.host,
                    &pol_path,
                    now,
                )
                .await;
            }
            return err(status, reason.code(), reason.message());
        }
        // In approval mode every request waits for the owner, whatever the
        // policy would have remembered.
        let decision = if standing == HandleStatus::ApprovalRequired {
            match decision {
                Decision::Allow(rule) | Decision::NeedsApproval { rule, .. } => {
                    Decision::NeedsApproval {
                        rule,
                        scope: ApprovalScope::ThisRequest,
                    }
                }
                d => d,
            }
        } else {
            decision
        };
        (handle, meta, decision)
    };

    // Approval, if the policy asks for one. The vault lock is not held while waiting.
    if let Decision::NeedsApproval { scope, .. } = &decision {
        let remember_key = match scope {
            ApprovalScope::ThisRequest => None,
            ApprovalScope::FirstUse(r) | ApprovalScope::Path(r) => Some(r.to_string()),
        };
        // Remembered decisions live in the handle record, so they survive
        // restarts and disappear with the handle or its policy.
        let already = match &remember_key {
            Some(k) => handle.remembered.iter().any(|r| r == k),
            None => false,
        };
        if !already {
            let scope_text = match scope {
                ApprovalScope::ThisRequest
                    if handle.status_at(now) == HandleStatus::ApprovalRequired =>
                {
                    "this request (approval mode after unusual activity)".to_string()
                }
                ApprovalScope::ThisRequest => "this request".to_string(),
                ApprovalScope::FirstUse(r) => format!("first use of {r}"),
                ApprovalScope::Path(r) => format!("{r}"),
            };
            let timeout = Duration::from_secs(handle.policy.approval.timeout_seconds as u64);
            let pending = PendingApproval {
                id: Id::new_v7(now),
                kind: "request".into(),
                handle_id: handle.handle_id,
                label: handle.label.clone(),
                secret: meta.name.clone(),
                caller: call.caller.clone(),
                method: call.method.clone(),
                host: upstream.host.clone(),
                path: pol_path.clone(),
                scope: scope_text.clone(),
                remember_key: remember_key.clone(),
                created_at: now,
                expires_at: now + timeout.as_millis() as i64,
            };
            let approval_id = pending.id;
            {
                let mut vault = s.vault.lock().await;
                let _ = vault.audit(kinds::APPROVAL_REQUIRED, json!({
                    "approval": approval_id.to_hex(), "handle": handle.handle_id.to_hex(),
                    "label": handle.label, "secret": meta.name, "caller": call.caller,
                    "host": upstream.host, "method": call.method, "path": pol_path, "scope": scope_text,
                }));
            }
            let rx = s.approval_create(pending.clone()).await;
            s.emit(Event::ApprovalRequested {
                id: approval_id.to_hex(),
                label: handle.label.clone(),
                secret: meta.name.clone(),
                caller: call.caller.clone(),
                method: call.method.clone(),
                path: pol_path.clone(),
                scope: scope_text.clone(),
            });
            let outcome = tokio::time::timeout(timeout, rx).await;
            s.approval_remove(&approval_id).await;
            let (allowed, remember, code, msg) = match outcome {
                Ok(Ok((true, remember))) => (true, remember, "", ""),
                Ok(Ok((false, _))) => (
                    false,
                    false,
                    "approval_denied",
                    "the owner denied this request",
                ),
                Ok(Err(_)) | Err(_) => (
                    false,
                    false,
                    "approval_timeout",
                    "no decision was made in time",
                ),
            };
            {
                let mut vault = s.vault.lock().await;
                let _ = vault.audit(
                    kinds::APPROVAL_DECIDED,
                    json!({
                        "approval": approval_id.to_hex(), "handle": handle.handle_id.to_hex(),
                        "label": handle.label, "secret": meta.name, "caller": call.caller,
                        "allowed": allowed, "remembered": remember && remember_key.is_some(),
                        "method": call.method, "path": pol_path,
                    }),
                );
            }
            if !allowed {
                return err(StatusCode::FORBIDDEN, code, msg);
            }
            if remember {
                if let Some(k) = &remember_key {
                    let mut vault = s.vault.lock().await;
                    if let Err(e) = vault.remember_rule(&handle.handle_id, k) {
                        tracing::warn!(error = %e, "could not persist the remembered approval");
                    }
                }
            }
        }
    }

    // Phase 2 (vault lock): egress guard, credential, counters.
    let revealed =
        {
            let mut vault = s.vault.lock().await;
            if vault.is_locked() {
                return err(
                    StatusCode::UNAUTHORIZED,
                    "vault_locked",
                    "the vault was locked while waiting",
                );
            }
            let scrubber = s.scrubber_snapshot();
            let mut hits = scrubber.find(&call.body);
            for (name, value) in call.headers.iter() {
                if is_stripped(name.as_str(), STRIP_REQUEST_HEADERS) {
                    continue;
                }
                hits.extend(scrubber.find(value.as_bytes()));
            }
            hits.extend(scrubber.find(call.path.as_bytes()));
            if let Some(q) = query {
                hits.extend(scrubber.find(q.as_bytes()));
            }
            if !hits.is_empty() {
                hits.dedup();
                let _ = vault.audit(kinds::EGRESS_BLOCKED, json!({
                "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": meta.name,
                "caller": call.caller, "leaked": hits, "host": upstream.host,
                "method": call.method, "path": pol_path,
            }));
                s.emit(Event::EgressBlocked {
                    secret: meta.name.clone(),
                    leaked: hits.clone(),
                });
                return err(
                    StatusCode::FORBIDDEN,
                    "egress_blocked",
                    format!(
                        "the request contains stored secret(s) in plaintext: {}",
                        hits.join(", ")
                    ),
                );
            }
            let revealed = match vault.reveal(&handle.secret_id) {
                Ok(r) => r,
                Err(e) => return ApiError::from(e).into_response(),
            };
            s.record_use(&handle.handle_id).await;
            let _ = vault.touch_handle(&handle.handle_id, now);
            revealed
        };

    // A bearer-kind secret (OAuth token, PAT) is always sent as `Authorization:
    // Bearer`, even for providers whose API keys travel in another header or in
    // the query string. Template and basic styles keep their own shape.
    let auth = match (&preset.auth, meta.kind) {
        (Auth::Header { .. } | Auth::Query { .. }, SecretKind::BearerToken) => Auth::Bearer {
            also_headers: Vec::new(),
        },
        // An OAuth client's handle stands where an access token goes.
        (_, SecretKind::Oauth2Client) => Auth::Bearer {
            also_headers: Vec::new(),
        },
        (a, _) => a.clone(),
    };

    // OAuth: what travels upstream is a short-lived access token, obtained
    // with the stored refresh token and kept in memory.
    let oauth_access = if meta.kind == SecretKind::Oauth2Client {
        match crate::oauth::access_token(&s, &meta, &revealed, now_ms()).await {
            Ok(token) => Some(token),
            Err(e) => {
                let mut vault = s.vault.lock().await;
                let _ = vault.audit(kinds::USE, json!({
                    "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": meta.name,
                    "caller": call.caller, "host": upstream.host, "method": call.method, "path": call.path,
                    "status": e.status.as_u16(), "error": e.code, "latency_ms": started.elapsed().as_millis() as u64,
                }));
                return err(e.status, e.code, e.message);
            }
        }
    } else {
        None
    };

    // Materialise credentials.
    let injection = match (&oauth_access, &auth) {
        (Some(token), _) => Injection {
            headers: vec![(
                "authorization".to_string(),
                Zeroizing::new(format!("Bearer {}", token.as_str())),
            )],
            query: Vec::new(),
        },
        (None, Auth::Template) => Injection::default(),
        (None, auth) => match adapters::inject(auth, &revealed) {
            Ok(i) => i,
            Err(e) => return broker_err(e),
        },
    };
    let resolver = |name: &str| (name == meta.name).then(|| revealed.value.clone());
    let (out_path, out_query, out_body) = if matches!(auth, Auth::Template) {
        let (p, _) = match adapters::substitute(call.path.as_bytes(), resolver) {
            Ok(v) => v,
            Err(e) => return broker_err(e),
        };
        let q = match query {
            Some(q) => match adapters::substitute(q.as_bytes(), resolver) {
                Ok((v, _)) => Some(v),
                Err(e) => return broker_err(e),
            },
            None => None,
        };
        let (b, _) = match adapters::substitute(&call.body, resolver) {
            Ok(v) => v,
            Err(e) => return broker_err(e),
        };
        (
            String::from_utf8_lossy(&p).into_owned(),
            q.map(|v| String::from_utf8_lossy(&v).into_owned()),
            Bytes::copy_from_slice(&b),
        )
    } else {
        // Strip the query parameter that carried the handle, if the SDK put it there.
        let q = match &preset.auth {
            Auth::Query { param } => strip_query_param(query, param),
            _ => query.map(str::to_string),
        };
        (call.path.clone(), q, call.body.clone())
    };

    // AWS: tidy the path and query into the form that will be signed and sent,
    // and undo aws-chunked framing (its per-chunk signatures were made with
    // the SDK's placeholder key).
    let mut aws_trailers: Vec<(String, String)> = Vec::new();
    let (out_path, out_query, out_body) = if matches!(auth, Auth::AwsSigv4) {
        let header = |name: &str| call.headers.get(name).and_then(|v| v.to_str().ok());
        let chunked = header("x-amz-content-sha256").is_some_and(|v| v.starts_with("STREAMING-"))
            || header("content-encoding")
                .is_some_and(|v| v.to_ascii_lowercase().contains("aws-chunked"));
        let body = if chunked {
            match sigv4::decode_aws_chunked(&out_body) {
                Ok(d) => {
                    aws_trailers = d.trailers;
                    Bytes::from(d.body)
                }
                Err(e) => return broker_err(e),
            }
        } else {
            out_body
        };
        (
            sigv4::wire_path(&out_path),
            out_query
                .map(|q| sigv4::wire_query(&q))
                .filter(|q| !q.is_empty()),
            body,
        )
    } else {
        (out_path, out_query, out_body)
    };

    // Build the upstream URL, honouring test/staging overrides only after the host lock.
    let origin = s
        .upstream_overrides
        .get(&upstream.host)
        .cloned()
        .unwrap_or_else(|| upstream.origin());
    let mut url = format!("{origin}{out_path}");
    let mut qparts: Vec<String> = out_query.into_iter().filter(|q| !q.is_empty()).collect();
    // (for AWS the query is signed below from the final URL, exactly as sent)
    for (k, v) in &injection.query {
        let enc = percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
        qparts.push(format!("{k}={enc}"));
    }
    if !qparts.is_empty() {
        url.push('?');
        url.push_str(&qparts.join("&"));
    }

    let method =
        reqwest::Method::from_bytes(call.method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in call.headers.iter() {
        if is_stripped(name.as_str(), STRIP_REQUEST_HEADERS) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            headers.append(n, v);
        }
    }
    // Template mode: substitute placeholders inside header values too.
    if matches!(auth, Auth::Template) {
        let mut replaced = reqwest::header::HeaderMap::new();
        for (name, value) in headers.iter() {
            match adapters::substitute(value.as_bytes(), resolver) {
                Ok((v, _)) => {
                    if let Ok(hv) = reqwest::header::HeaderValue::from_bytes(&v) {
                        replaced.append(name.clone(), hv);
                    }
                }
                Err(e) => return broker_err(e),
            }
        }
        headers = replaced;
    }
    for (name, value) in &injection.headers {
        let secret_header: Zeroizing<String> = value.clone();
        if let (Ok(n), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(name.as_bytes()),
            reqwest::header::HeaderValue::from_str(&secret_header),
        ) {
            headers.insert(n, v);
        }
    }
    // AWS: sign the request exactly as it will go on the wire.
    let mut aws_audit: Option<(String, Option<String>)> = None;
    if matches!(auth, Auth::AwsSigv4) {
        let creds = match adapters::aws_credentials(&revealed) {
            Ok(c) => c,
            Err(e) => return broker_err(e),
        };
        let Some((region, service)) = call.aws_scope.clone().or_else(|| {
            sigv4::scope_for_host(&upstream.host).map(|(service, region)| (region, service))
        }) else {
            return err(
                StatusCode::BAD_REQUEST,
                "aws_scope_required",
                "cannot tell the AWS service and region for this host; use an AWS SDK or a regional endpoint",
            );
        };
        // The URL type normalises a few things (dot segments, for one); sign
        // what it will actually send.
        let Ok(parsed) = reqwest::Url::parse(&url) else {
            return err(
                StatusCode::BAD_REQUEST,
                "malformed_request",
                "invalid request URL",
            );
        };
        aws_audit = Some((
            format!("{service}/{region}"),
            aws_action(&call.headers, query, &call.body),
        ));
        for name in [
            "x-amz-date",
            "x-amz-content-sha256",
            "x-amz-security-token",
            "x-amz-trailer",
            "x-amz-decoded-content-length",
        ] {
            headers.remove(name);
        }
        let encoding = headers
            .get(reqwest::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if let Some(encoding) = encoding {
            headers.remove(reqwest::header::CONTENT_ENCODING);
            if let Some(rest) = sigv4::strip_aws_chunked(&encoding) {
                set_header(&mut headers, "content-encoding", &rest);
            }
        }
        for (name, value) in &aws_trailers {
            set_header(&mut headers, name, value);
        }
        let amz_date = sigv4::amz_date(now_ms());
        let payload_hash = sigv4::payload_hash(&out_body);
        set_header(&mut headers, "x-amz-date", &amz_date);
        set_header(&mut headers, "x-amz-content-sha256", &payload_hash);
        if let Some(token) = &creds.session_token {
            set_header(&mut headers, "x-amz-security-token", token);
        }
        let host_header = match upstream.port {
            Some(p) => format!("{}:{p}", upstream.host),
            None => upstream.host.clone(),
        };
        let mut to_sign = vec![("host".to_string(), host_header)];
        for (name, value) in headers.iter() {
            let n = name.as_str();
            if n == "content-type" || n.starts_with("x-amz-") {
                if let Ok(v) = value.to_str() {
                    to_sign.push((n.to_string(), v.to_string()));
                }
            }
        }
        let signed = sigv4::sign(
            &sigv4::Credentials {
                access_key_id: &creds.access_key_id,
                secret_access_key: &creds.secret_access_key,
                session_token: creds.session_token.as_deref().map(String::as_str),
            },
            &region,
            &service,
            &amz_date,
            &sigv4::Request {
                method: &call.method,
                path: parsed.path(),
                query: parsed.query(),
                headers: &to_sign,
                payload_hash: &payload_hash,
            },
        );
        set_header(&mut headers, "authorization", &signed.authorization);
    }

    if !headers.contains_key(reqwest::header::USER_AGENT) {
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_static(concat!(
                "unseenkey/",
                env!("CARGO_PKG_VERSION")
            )),
        );
    }

    let upstream_resp = match s
        .http
        .request(method.clone(), &url)
        .headers(headers)
        .body(out_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let mut vault = s.vault.lock().await;
            let _ = vault.audit(kinds::USE, json!({
                "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": meta.name,
                "caller": call.caller, "host": upstream.host, "method": call.method, "path": call.path,
                "status": 502, "error": "upstream_unreachable", "latency_ms": started.elapsed().as_millis() as u64,
            }));
            let msg = if e.is_connect() {
                "could not connect to the upstream"
            } else if e.is_timeout() {
                "the upstream timed out"
            } else {
                "the upstream request failed"
            };
            return err(StatusCode::BAD_GATEWAY, "upstream_error", msg);
        }
    };

    let status = upstream_resp.status();
    let mut resp_headers = HeaderMap::new();
    let scrubber = s.scrubber_snapshot();
    let mut scrubbed_headers = 0usize;
    for (name, value) in upstream_resp.headers().iter() {
        if is_stripped(name.as_str(), STRIP_RESPONSE_HEADERS) {
            continue;
        }
        let (clean, n) = scrubber.scrub(value.as_bytes());
        scrubbed_headers += n;
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(&clean),
        ) {
            resp_headers.append(hn, hv);
        }
    }

    // Audit before the first response byte (INV-4). Failure means no response.
    {
        let mut vault = s.vault.lock().await;
        let mut event = json!({
            "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": meta.name,
            "caller": call.caller, "host": upstream.host, "method": call.method,
            "path": call.path, "status": status.as_u16(), "bytes_in": call.body.len(),
            "latency_ms": started.elapsed().as_millis() as u64, "scrubbed_headers": scrubbed_headers,
        });
        if let Some((scope, action)) = &aws_audit {
            event["aws"] = json!(scope);
            if let Some(action) = action {
                event["action"] = json!(action);
            }
        }
        let audit = vault.audit(kinds::USE, event);
        if audit.is_err() {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "audit_failure",
                "could not record this request; refusing to proceed",
            );
        }
    }
    s.emit(Event::Use {
        secret: meta.name.clone(),
        label: handle.label.clone(),
        status: status.as_u16(),
    });

    let body = ScrubBody {
        inner: Box::pin(upstream_resp.bytes_stream()),
        scrub: StreamScrubber::new(scrubber),
        done: false,
    };
    let mut response = Response::new(Body::from_stream(body));
    *response.status_mut() =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    *response.headers_mut() = resp_headers;
    response.headers_mut().insert(
        "x-usk-handle-id",
        HeaderValue::from_str(&handle.handle_id.to_hex()).unwrap_or(HeaderValue::from_static("")),
    );
    response
}
