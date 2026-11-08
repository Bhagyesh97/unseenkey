//! "Paste and done": recognise a pasted key and test a stored one.
//!
//! Recognition never sends the key anywhere: it looks at the key's shape,
//! then at the name the user gave it. Testing sends the key to exactly one
//! place, the read-only request in the secret's own provider preset, on a
//! host the secret is locked to.

use crate::api::{resolve_secret, ApiError};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use unseenkey_core::audit::kinds;
use unseenkey_core::broker::{adapters, BrokerError};
use unseenkey_core::presets::{self, Auth, Preset};
use unseenkey_core::providers;
use unseenkey_core::vault::{Revealed, SecretKind, SecretMeta};
use zeroize::Zeroizing;

/// What a pasted key looks like.
#[derive(Debug, Clone, Serialize)]
pub struct Recognised {
    /// Provider preset id.
    pub provider: String,
    /// Human name.
    pub display: String,
    /// `shape` (the key itself says so) or `name` (only the name suggests it).
    pub how: &'static str,
    /// Extra note ("live key").
    pub note: String,
    /// Whether the provider has a harmless test request.
    pub testable: bool,
}

/// Recognise a key from its value, then from its name. Sends nothing anywhere.
pub fn recognise(value: Option<&str>, name: Option<&str>) -> Option<Recognised> {
    let testable = |id: &str| presets::get(id).is_some_and(|p| p.verify.is_some());
    if let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) {
        if let Some(d) = providers::detect(v.as_bytes()) {
            return Some(Recognised {
                provider: d.provider.to_string(),
                display: d.display.to_string(),
                how: "shape",
                note: d.note.to_string(),
                testable: testable(d.provider),
            });
        }
        if let Some(p) = presets::detect_by_prefix(v) {
            return Some(Recognised {
                provider: p.id.clone(),
                display: p.display.clone(),
                how: "shape",
                note: String::new(),
                testable: p.verify.is_some(),
            });
        }
    }
    let p = presets::guess_by_name(name?)?;
    Some(Recognised {
        provider: p.id.clone(),
        display: p.display.clone(),
        how: "name",
        note: String::new(),
        testable: p.verify.is_some(),
    })
}

/// `POST /v1/detect` body.
#[derive(Deserialize)]
pub struct DetectRequest {
    /// The pasted value, if any.
    pub value: Option<Zeroizing<String>>,
    /// The name or variable it came with, if any.
    pub name: Option<String>,
}

/// `POST /v1/detect`: what is this key? Nothing is stored or sent.
pub async fn detect(Json(req): Json<DetectRequest>) -> Json<serde_json::Value> {
    let r = recognise(
        req.value.as_deref().map(|v| v.as_str()),
        req.name.as_deref(),
    );
    Json(json!({ "recognised": r }))
}

/// Outcome of a test.
#[derive(Debug, Serialize)]
pub struct TestResult {
    /// Whether a request was sent at all.
    pub tested: bool,
    /// `true` accepted, `false` refused, `null` unknown or not tested.
    pub ok: Option<bool>,
    /// HTTP status the provider answered with.
    pub status: Option<u16>,
    /// Provider display name.
    pub provider: Option<String>,
    /// Plain words for the owner.
    pub message: String,
}

fn not_tested(provider: Option<&Preset>, message: impl Into<String>) -> Json<TestResult> {
    Json(TestResult {
        tested: false,
        ok: None,
        status: None,
        provider: provider.map(|p| p.display.clone()),
        message: message.into(),
    })
}

/// A service account is tested by signing in: Google checks the key and the
/// scopes. It does not show what the account was added to; each API decides that.
async fn test_service_account(
    s: &Arc<AppState>,
    meta: &SecretMeta,
    revealed: &Revealed,
) -> Json<TestResult> {
    let display = meta
        .provider
        .as_deref()
        .and_then(presets::get)
        .map(|p| p.display.clone());
    let attempt = {
        s.oauth.lock().await.forget(&meta.secret_id);
        crate::oauth::access_token(s, meta, revealed, crate::proxy::now_ms()).await
    };
    let (ok, message) = match attempt {
        Ok(_) => (
            Some(true),
            "Google accepted the key and these scopes. Each API still checks what the service account was added to.".to_string(),
        ),
        Err(e) if e.code == "scope_required" => {
            return Json(TestResult {
                tested: false,
                ok: None,
                status: None,
                provider: display,
                message: e.message,
            })
        }
        Err(e) if e.refused => (Some(false), format!("Google refused it: {}. A key deleted in Google Cloud needs a new file: `usk rm {name}`, then `usk add {name} --file <key.json> --scope <scope>`.", e.message, name = meta.name)),
        Err(e) => (None, e.message),
    };
    {
        let mut v = s.vault.lock().await;
        let _ = v.audit(
            kinds::KEY_TESTED,
            json!({ "id": meta.secret_id.to_hex(), "secret": meta.name, "provider": meta.provider, "ok": ok }),
        );
    }
    tracing::info!(secret = %meta.secret_id, ok = ?ok, "key tested");
    Json(TestResult {
        tested: true,
        ok,
        status: None,
        provider: display,
        message,
    })
}

/// `POST /v1/secrets/{ref}/test`: one read-only request with the real key.
pub async fn test_secret(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
) -> Result<Json<TestResult>, ApiError> {
    let (meta, revealed) = {
        let v = s.vault.lock().await;
        let id = resolve_secret(&v, &r)?;
        (v.get(&id)?.clone(), v.reveal(&id)?)
    };
    if meta.kind == SecretKind::GcpServiceAccount {
        return Ok(test_service_account(&s, &meta, &revealed).await);
    }
    let Some(preset) = meta.provider.as_deref().and_then(presets::get) else {
        return Ok(not_tested(
            None,
            "this key has no provider, so there is nothing to test it against; choose one under Edit settings",
        ));
    };
    let Some(verify) = &preset.verify else {
        return Ok(not_tested(
            Some(preset),
            format!(
                "{} has no request that tests a key without doing something, so it was not tested",
                preset.display
            ),
        ));
    };
    let auth = match (&preset.auth, meta.kind) {
        (Auth::Template | Auth::AwsSigv4, _) => {
            return Ok(not_tested(
                Some(preset),
                format!("{} keys cannot be tested here yet", preset.display),
            ))
        }
        (
            _,
            SecretKind::Oauth2Client | SecretKind::AwsCredentials | SecretKind::GcpServiceAccount,
        ) => {
            return Ok(not_tested(
                Some(preset),
                "this kind of credential cannot be tested here yet",
            ))
        }
        (
            Auth::Header { .. } | Auth::Query { .. } | Auth::Scheme { .. },
            SecretKind::BearerToken,
        ) => Auth::Bearer {
            also_headers: Vec::new(),
        },
        (a, _) => a.clone(),
    };
    if let Some(t) = preset
        .tenant
        .as_ref()
        .filter(|_| preset.pin_needed(&meta.upstreams))
    {
        return Ok(not_tested(
            Some(preset),
            format!(
                "it goes nowhere until you name your {}: `usk secret set {} --upstream {}`",
                t.label, meta.name, t.example
            ),
        ));
    }
    let host = verify
        .host
        .clone()
        .or_else(|| preset.pinned_host(&meta.upstreams).map(str::to_string))
        .unwrap_or_else(|| preset.upstreams[0].clone());
    // The host lock holds for tests too: never send the key where it may not go.
    if !unseenkey_core::policy::eval::host_allowed(&meta.upstreams, &host) {
        return Ok(not_tested(
            Some(preset),
            format!(
                "this key is locked to {} and the test goes to {host}, so it was not sent",
                meta.upstreams.join(", ")
            ),
        ));
    }
    let injection = match adapters::inject(&auth, &revealed) {
        Ok(i) => i,
        Err(BrokerError::MissingUsername) => {
            let (user, _) = preset.pair_labels().unwrap_or(("Username", ""));
            return Ok(not_tested(
                Some(preset),
                format!(
                    "{} keys come in two parts and the {user} is missing. Add it with `usk secret set {} --username <value>`.",
                    preset.display, meta.name
                ),
            ));
        }
        Err(e) => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "cannot_test",
                e.to_string(),
            ))
        }
    };
    let origin = s
        .upstream_overrides
        .get(&host)
        .cloned()
        .unwrap_or_else(|| format!("https://{host}"));
    // Some providers put the account in the path.
    let fill = |template: &str| -> Result<String, ApiError> {
        match &auth {
            Auth::Basic { username, .. } if template.contains("{username}") => {
                let user =
                    adapters::basic_username(username.as_deref(), &revealed).map_err(|e| {
                        ApiError::new(StatusCode::BAD_REQUEST, "cannot_test", e.to_string())
                    })?;
                let user = percent_encoding::utf8_percent_encode(
                    &user,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                Ok(template.replace("{username}", &user.to_string()))
            }
            _ => Ok(template.to_string()),
        }
    };
    let path = fill(&verify.path)?;
    let also_path = verify.also_path.as_deref().map(fill).transpose()?;
    let display = preset.display.clone();
    let mut outcome: (Option<bool>, Option<u16>, String) = (None, None, String::new());
    for (attempt, path) in std::iter::once(path).chain(also_path).enumerate() {
        // Presets are checked when loaded. The key does not go out on that alone.
        if !path.starts_with('/') {
            return Ok(not_tested(
                Some(preset),
                "the preset's test path does not start with /, so the key was not sent".to_string(),
            ));
        }
        let mut url = format!("{origin}{path}");
        for (k, v) in &injection.query {
            let enc = percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC);
            url.push(if url.contains('?') { '&' } else { '?' });
            url.push_str(&format!("{k}={enc}"));
        }
        let method =
            reqwest::Method::from_bytes(verify.method.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut req = s
            .http
            .request(method, &url)
            .timeout(Duration::from_secs(15))
            .header(
                "user-agent",
                concat!("unseenkey/", env!("CARGO_PKG_VERSION")),
            );
        for (k, v) in &verify.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        for (k, v) in &injection.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        outcome = match req.send().await {
            Ok(resp) => {
                let code = resp.status().as_u16();
                match code {
                    200..=299 => (Some(true), Some(code), format!("{display} accepted the key.")),
                    // The first address said no. At the second, 403 can mean a good
                    // key that may not list what this address lists.
                    403 if attempt > 0 => (None, Some(code), format!("{display} answered HTTP {code}, which does not say whether the key works: it may not have permission for this test.")),
                    401 | 403 => (
                        Some(false),
                        Some(code),
                        format!(
                            "{display} refused this key (HTTP {code}). Check that you copied all of it, that it has not expired or been revoked, and that it is the right kind of key (some providers have separate keys for sending and for reading)."
                        ),
                    ),
                    _ => (None, Some(code), format!("{display} answered HTTP {code}, which does not say whether the key works.")),
                }
            }
            // The error's own text holds the URL, and a key may travel in the URL.
            Err(e) => (
                None,
                None,
                format!("could not reach {host}: {}", e.without_url()),
            ),
        };
        if outcome.0 != Some(false) {
            break;
        }
    }
    let (ok, status, message) = outcome;
    {
        let mut v = s.vault.lock().await;
        let _ = v.audit(
            kinds::KEY_TESTED,
            json!({ "id": meta.secret_id.to_hex(), "secret": meta.name, "provider": preset.id, "host": host, "status": status, "ok": ok }),
        );
    }
    tracing::info!(secret = %meta.secret_id, status = ?status, ok = ?ok, "key tested");
    Ok(Json(TestResult {
        tested: true,
        ok,
        status,
        provider: Some(display),
        message,
    }))
}
