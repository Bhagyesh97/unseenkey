//! Ingress guard and token authentication middleware.

use crate::api::ApiError;
use crate::state::AppState;
use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, HOST, ORIGIN, REFERER};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

/// Headers a browser attaches to cross-site or same-site requests. Curl, SDKs
/// and the CLI never send them, so their presence means "a web page did this".
const BROWSER_MARKERS: &[&str] = &[
    "sec-fetch-mode",
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
            state.touch().await;
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
