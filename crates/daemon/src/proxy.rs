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
use crate::state::{AppState, Event, PendingApproval};
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
use unseenkey_core::broker::{
    check_host, is_stripped, split_path_query, BrokerError, Upstream, STRIP_REQUEST_HEADERS,
    STRIP_RESPONSE_HEADERS,
};
use unseenkey_core::handles::HandleRecord;
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
        Auth::Template | Auth::AwsSigv4 => None,
    };
    primary
        .or_else(bearer)
        .or_else(|| header("x-api-key"))
        .or_else(|| from_query("key"))
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
    /// Explicit upstream (`X-Usk-Upstream`), required for generic/wildcard presets.
    pub upstream_spec: Option<String>,
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
    let path = format!("/{rest}");
    let Some(preset) = presets::get(&preset_id) else {
        return err(
            StatusCode::NOT_FOUND,
            "unknown_preset",
            format!("no provider preset {preset_id:?}"),
        );
    };
    let Some(handle_str) = extract_handle(preset, &parts.headers, query.as_deref()) else {
        return err(
            StatusCode::UNAUTHORIZED,
            "unknown_handle",
            "no handle found where this provider expects its key",
        );
    };
    let upstream_spec = parts
        .headers
        .get("x-usk-upstream")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);
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
    let (handle, meta, decision): (HandleRecord, SecretMeta, Decision) =
        {
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
                    Err(_) => {
                        return err(StatusCode::UNAUTHORIZED, "unknown_handle", "unknown handle")
                    }
                },
            };
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
            // Host lock (INV-2) on the logical host, before any override.
            if let Err(e) = check_host(&meta.upstreams, &handle.policy.upstreams, &upstream.host) {
                let _ = vault.audit(kinds::DENY, json!({
                "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": meta.name,
                "caller": call.caller, "reason": e.code(), "host": upstream.host,
                "method": call.method, "path": pol_path,
            }));
                return broker_err(e);
            }
            let usage = s.usage_for(&handle.handle_id, handle.use_count).await;
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
                let _ = vault.audit(kinds::DENY, json!({
                "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": meta.name,
                "caller": call.caller, "reason": reason.code(), "detail": reason.message(),
                "host": upstream.host, "method": call.method, "path": pol_path,
            }));
                return err(status, reason.code(), reason.message());
            }
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
        (a, _) => a.clone(),
    };

    // Materialise credentials.
    let injection = match &auth {
        Auth::Template => Injection::default(),
        auth => match adapters::inject(auth, &revealed) {
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

    // Build the upstream URL, honouring test/staging overrides only after the host lock.
    let origin = s
        .upstream_overrides
        .get(&upstream.host)
        .cloned()
        .unwrap_or_else(|| upstream.origin());
    let mut url = format!("{origin}{out_path}");
    let mut qparts: Vec<String> = out_query.into_iter().filter(|q| !q.is_empty()).collect();
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
        let audit = vault.audit(kinds::USE, json!({
            "handle": handle.handle_id.to_hex(), "label": handle.label, "secret": meta.name,
            "caller": call.caller, "host": upstream.host, "method": call.method,
            "path": call.path, "status": status.as_u16(), "bytes_in": call.body.len(),
            "latency_ms": started.elapsed().as_millis() as u64, "scrubbed_headers": scrubbed_headers,
        }));
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
