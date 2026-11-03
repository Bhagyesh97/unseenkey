//! OAuth2: trading a stored credential for short-lived access tokens.
//!
//! Two kinds of secret work this way.
//!
//! A secret of kind `oauth2_client` holds a refresh token, a client id, an
//! optional client secret and the provider's token URL. Callers present a
//! handle where an access token would go; the broker keeps a current access
//! token in memory, fetches a new one when it is about to expire, and sends
//! that upstream. Neither the refresh token nor the access token is ever
//! returned to the caller.
//!
//! A secret of kind `gcp_service_account` holds a Google key file and its
//! scopes. There is no refresh token: the broker signs a short JWT with the
//! file's key and trades that (RFC 7523). The key itself never travels.
//!
//! The token endpoint is a second place the secret travels to, so it is held
//! to the same host lock as any other destination: its host must be in the
//! secret's own `upstreams` (a handle's policy may narrow what the *handle*
//! reaches, not where the secret refreshes).

use crate::state::AppState;
use axum::http::StatusCode;
use base64::Engine;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use unseenkey_core::audit::kinds;
use unseenkey_core::broker::adapters;
use unseenkey_core::broker::{check_host, Upstream};
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::ids::Id;
use unseenkey_core::vault::{Revealed, SecretKind, SecretMeta};
use zeroize::Zeroizing;

/// Refresh this long before the stated expiry.
const SKEW_MS: i64 = 60_000;
/// Lifetime assumed when the provider does not state one.
const DEFAULT_LIFETIME_S: i64 = 3600;
/// Largest token response we read.
const MAX_RESPONSE: usize = 64 * 1024;
/// Lifetime requested for a service account's signed token request; Google's limit.
const ASSERTION_LIFETIME_S: i64 = 3600;
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

struct Cached {
    /// Value version of the secret the token was obtained with.
    version: u64,
    token: Zeroizing<String>,
    expires_at: i64,
}

/// Access tokens currently held, by secret. Memory only; emptied on lock.
#[derive(Default)]
pub struct TokenCache {
    tokens: HashMap<Id, Cached>,
}

impl TokenCache {
    /// Forget every token.
    pub fn clear(&mut self) {
        self.tokens.clear();
    }

    /// Forget one secret's token, so the next use asks the provider again.
    pub fn forget(&mut self, secret: &Id) {
        self.tokens.remove(secret);
    }
}

/// Why no access token could be produced.
pub struct OauthError {
    /// HTTP status for the caller.
    pub status: StatusCode,
    /// Stable error code.
    pub code: &'static str,
    /// Message for the caller (never contains secret material).
    pub message: String,
    /// The provider answered and said no (as opposed to not being reached).
    pub refused: bool,
}

fn fail(status: StatusCode, code: &'static str, message: impl Into<String>) -> OauthError {
    OauthError {
        status,
        code,
        message: message.into(),
        refused: false,
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{k}={}",
                percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Read a PEM private key. Google's key files hold PKCS#8 RSA keys.
fn rsa_key(pem: &str) -> Option<ring::rsa::KeyPair> {
    let body: Zeroizing<String> = Zeroizing::new(
        pem.lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("-----"))
            .collect(),
    );
    let der = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .ok()?,
    );
    ring::rsa::KeyPair::from_pkcs8(&der).ok()
}

/// Whether `pem` is a key the broker can sign with.
pub fn is_signing_key(pem: &str) -> bool {
    rsa_key(pem).is_some()
}

/// The signed request for an access token (RFC 7523, RS256).
fn assertion(
    account: &adapters::ServiceAccount,
    scope: &str,
    now: i64,
) -> Result<Zeroizing<String>, OauthError> {
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let Some(key) = rsa_key(&account.private_key) else {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "secret_shape",
            "the key file's private_key is not a PKCS#8 RSA key",
        ));
    };
    let mut header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
    if let Some(id) = &account.private_key_id {
        header["kid"] = serde_json::json!(id);
    }
    let issued = now / 1000;
    let claims = serde_json::json!({
        "iss": account.client_email,
        "scope": scope,
        "aud": account.token_url,
        "iat": issued,
        "exp": issued + ASSERTION_LIFETIME_S,
    });
    let signing_input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        signing_input.as_bytes(),
        &mut signature,
    )
    .map_err(|_| {
        fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "signing_failed",
            "could not sign the token request",
        )
    })?;
    Ok(Zeroizing::new(format!(
        "{signing_input}.{}",
        b64(&signature)
    )))
}

/// What a secret trades for an access token.
enum Grant {
    Refresh(adapters::Oauth2Client),
    ServiceAccount(adapters::ServiceAccount, String),
}

/// Read the grant out of a secret.
fn grant(meta: &SecretMeta, revealed: &Revealed) -> Result<Grant, OauthError> {
    let shape = |e: unseenkey_core::broker::BrokerError| {
        fail(StatusCode::BAD_REQUEST, "secret_shape", e.to_string())
    };
    if meta.kind != SecretKind::GcpServiceAccount {
        return adapters::oauth2_client(revealed)
            .map(Grant::Refresh)
            .map_err(shape);
    }
    let account = adapters::service_account(revealed).map_err(shape)?;
    let Some(scope) = account.scope.clone() else {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "scope_required",
            format!(
                "{name} has no scopes yet, so it cannot sign in to Google. Ask the owner to set the ones it needs: `usk secret set {name} --scope <scope>`, for example webmasters.readonly",
                name = meta.name
            ),
        ));
    };
    Ok(Grant::ServiceAccount(account, scope))
}

/// A current access token for `meta`, from the cache or freshly obtained.
pub async fn access_token(
    s: &Arc<AppState>,
    meta: &SecretMeta,
    revealed: &Revealed,
    now: i64,
) -> Result<Zeroizing<String>, OauthError> {
    // One at a time: holding the cache also keeps a burst of requests from
    // each spending the (possibly single-use) refresh token.
    let mut cache = s.oauth.lock().await;
    if let Some(c) = cache.tokens.get(&meta.secret_id) {
        if c.version == meta.value_version && now < c.expires_at - SKEW_MS {
            return Ok(c.token.clone());
        }
    }

    let grant = grant(meta, revealed)?;
    let token_url = match &grant {
        Grant::Refresh(client) => client.token_url.as_str(),
        Grant::ServiceAccount(account, _) => account.token_url.as_str(),
    };
    let invalid = || {
        fail(
            StatusCode::BAD_REQUEST,
            "secret_shape",
            "the secret's token_url is not a valid https URL",
        )
    };
    let url = reqwest::Url::parse(token_url).map_err(|_| invalid())?;
    let upstream = Upstream::parse(token_url).map_err(|_| invalid())?;
    if check_host(&meta.upstreams, &[], &upstream.host).is_err() {
        return Err(fail(
            StatusCode::FORBIDDEN,
            "host_not_allowed",
            format!(
                "the token endpoint {} is not among this secret's allowed hosts",
                upstream.host
            ),
        ));
    }
    let origin = s
        .upstream_overrides
        .get(&upstream.host)
        .cloned()
        .unwrap_or_else(|| upstream.origin());
    let mut target = format!("{origin}{}", url.path());
    if let Some(q) = url.query() {
        target.push('?');
        target.push_str(q);
    }

    let mut request = s
        .http
        .post(&target)
        .timeout(Duration::from_secs(30))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::ACCEPT, "application/json");
    let body = match &grant {
        Grant::Refresh(client) => {
            let mut pairs: Vec<(&str, &str)> = vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", client.refresh_token.as_str()),
            ];
            if let Some(scope) = &client.scope {
                pairs.push(("scope", scope));
            }
            let basic;
            match (&client.client_secret, client.basic_auth) {
                (Some(secret), true) => {
                    basic = Zeroizing::new(format!(
                        "Basic {}",
                        base64::engine::general_purpose::STANDARD.encode(format!(
                            "{}:{}",
                            client.client_id.as_str(),
                            secret.as_str()
                        ))
                    ));
                    request = request.header(reqwest::header::AUTHORIZATION, basic.as_str());
                }
                (secret, _) => {
                    pairs.push(("client_id", client.client_id.as_str()));
                    if let Some(secret) = secret {
                        pairs.push(("client_secret", secret.as_str()));
                    }
                }
            }
            Zeroizing::new(form(&pairs))
        }
        Grant::ServiceAccount(account, scope) => {
            let jwt = assertion(account, scope, now)?;
            Zeroizing::new(form(&[
                ("grant_type", JWT_BEARER_GRANT),
                ("assertion", jwt.as_str()),
            ]))
        }
    };

    let unreachable = |what: &str| {
        fail(
            StatusCode::BAD_GATEWAY,
            "oauth_refresh_failed",
            format!("could not refresh the access token: {what}"),
        )
    };
    let resp = request
        .body(body.as_str().to_owned())
        .send()
        .await
        .map_err(|e| {
            unreachable(if e.is_timeout() {
                "the token endpoint timed out"
            } else {
                "the token endpoint could not be reached"
            })
        })?;
    let status = resp.status();
    let bytes = resp
        .bytes()
        .await
        .map_err(|_| unreachable("the token endpoint's answer was cut short"))?;
    if bytes.len() > MAX_RESPONSE {
        return Err(unreachable("the token endpoint's answer was too large"));
    }
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    let text = |key: &str| json.get(key).and_then(|v| v.as_str()).map(str::to_string);
    let Some(token) = text("access_token").filter(|t| !t.is_empty() && status.is_success()) else {
        // Say what the provider said, scrubbed, and nothing else.
        let said = [text("error"), text("error_description")]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(": ");
        let said: String = said.chars().filter(|c| !c.is_control()).take(300).collect();
        let (clean, _) = s.scrubber_snapshot().scrub(said.as_bytes());
        let said = String::from_utf8_lossy(&clean).into_owned();
        tracing::warn!(secret = %meta.secret_id, status = status.as_u16(), "oauth refresh refused");
        return Err(OauthError {
            refused: true,
            ..fail(
                StatusCode::BAD_GATEWAY,
                "oauth_refresh_failed",
                if said.is_empty() {
                    format!(
                        "the provider refused to refresh the access token (HTTP {})",
                        status.as_u16()
                    )
                } else {
                    format!("the provider refused to refresh the access token ({said})")
                },
            )
        });
    };
    let token = Zeroizing::new(token);
    let lifetime_s = json
        .get("expires_in")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_LIFETIME_S);

    // Vault work: store a rotated refresh token, and make the scrubber guard
    // the new access token like any other secret value.
    let mut version = meta.value_version;
    {
        let mut vault = s.vault.lock().await;
        let current = match &grant {
            Grant::Refresh(client) => Some(client.refresh_token.as_str()),
            Grant::ServiceAccount(..) => None,
        };
        if let Some(rotated) = current
            .and_then(|old| text("refresh_token").filter(|t| !t.is_empty() && t.as_str() != old))
        {
            let rotated = SecretBytes::from(rotated.as_str());
            let mut fields = revealed.fields.clone();
            let value = if fields.contains_key("refresh_token") {
                fields.insert("refresh_token".into(), rotated);
                revealed.value.clone()
            } else {
                rotated
            };
            match vault.update_value(&meta.secret_id, value, fields) {
                Ok(v) => {
                    version = v;
                    let _ = vault.audit(
                        kinds::SECRET_UPDATED,
                        serde_json::json!({ "id": meta.secret_id.to_hex(), "value_changed": true, "reason": "oauth_rotation" }),
                    );
                    tracing::info!(secret = %meta.secret_id, "rotated refresh token stored");
                }
                Err(e) => {
                    // The old refresh token may already be dead: do not pretend all is well.
                    tracing::error!(secret = %meta.secret_id, error = %e, "could not store rotated refresh token");
                    return Err(fail(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "oauth_rotation_failed",
                        "the provider issued a new refresh token and it could not be saved; re-add the secret",
                    ));
                }
            }
        }
        s.set_live_token(&meta.name, SecretBytes::from(token.as_str()));
        s.rebuild_scrubber(&vault);
    }
    cache.tokens.insert(
        meta.secret_id,
        Cached {
            version,
            token: token.clone(),
            expires_at: now + lifetime_s * 1000,
        },
    );
    tracing::info!(secret = %meta.secret_id, lifetime_s, "access token refreshed");
    Ok(token)
}
