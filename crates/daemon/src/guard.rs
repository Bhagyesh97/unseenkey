//! Ingress guard and token authentication middleware.

use crate::api::ApiError;
use crate::state::AppState;
use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, HOST, ORIGIN, REFERER};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// Headers a browser attaches to every request from a page. Curl, Rust and
/// Python SDKs and the CLI never send them, so their presence means "a web
/// page did this". `Sec-Fetch-Mode` is deliberately *not* in this list:
/// Node's `fetch` (undici), and therefore the OpenAI/Anthropic Node SDKs and
/// Claude Code, send `sec-fetch-mode: cors` on every request, while browsers
/// always add `Sec-Fetch-Site`/`Sec-Fetch-Dest` (and `Origin` cross-site)
/// alongside it.
const BROWSER_MARKERS: &[&str] = &[
    "sec-fetch-site",
    "sec-fetch-dest",
    "sec-fetch-user",
    "sec-ch-ua",
];

/// Reject browser-originated requests and unexpected `Host` values (INV-6).
pub async fn ingress_guard(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let headers = req.headers();
    let browser = headers.contains_key(ORIGIN)
        || headers.contains_key(REFERER)
        || BROWSER_MARKERS.iter().any(|h| headers.contains_key(*h));
    if browser {
        // Method and path only; the browser test suite counts these lines.
        tracing::info!(method = %req.method(), path = req.uri().path(), "browser-origin request rejected");
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "browser_origin_rejected",
            "requests from web pages are not accepted by the local daemon",
        )
        .into_response();
    }
    let host_ok = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| state.allowed_hosts.contains(h))
        .unwrap_or(false);
    if !host_ok {
        return ApiError::new(
            StatusCode::FORBIDDEN,
            "host_rejected",
            "unexpected Host header",
        )
        .into_response();
    }
    next.run(req).await
}

/// Reads that clients make on their own, on a timer or on a stream: the app
/// polls status and approvals every few seconds and keeps the event stream
/// open. Counting them as activity kept the vault unlocked for as long as the
/// app was open, so the idle lock never fired.
pub fn is_background(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::GET
        && matches!(
            path,
            "/v1/status"
                | "/v1/approvals"
                | "/v1/events"
                | "/v1/callers"
                | "/status"
                | "/approvals"
                | "/events"
                | "/callers"
        )
}

/// Require `Authorization: Bearer <session token>` on management routes (INV-3).
pub async fn require_token(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let presented = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    match presented {
        Some(t) if crate::token::verify(&state.token_hash, t) => {
            if !is_background(req.method(), req.uri().path()) {
                state.touch().await;
            }
            next.run(req).await
        }
        _ => ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid session token; read it from daemon.token",
        )
        .into_response(),
    }
}

#[cfg(test)]
mod idle_tests {
    use super::is_background;
    use axum::http::Method;

    #[test]
    fn polling_does_not_keep_the_vault_awake() {
        for p in [
            "/v1/status",
            "/v1/approvals",
            "/v1/events",
            "/v1/callers",
            "/status",
        ] {
            assert!(is_background(&Method::GET, p), "{p}");
        }
        // Anything the owner does still counts.
        assert!(!is_background(&Method::POST, "/v1/approvals"));
        assert!(!is_background(&Method::GET, "/v1/secrets"));
        assert!(!is_background(&Method::GET, "/v1/audit"));
        assert!(!is_background(&Method::POST, "/v1/unlock"));
    }
}
