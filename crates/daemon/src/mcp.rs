//! MCP server: JSON-RPC 2.0 over Streamable HTTP (`POST /mcp`). The `usk mcp`
//! stdio bridge forwards lines here, so there is one implementation.
//!
//! Tools never return secret values. `call_api` runs the full broker pipeline
//! ([`crate::proxy::execute`]) with the client's own identity (`mcp:<name>`)
//! and a per-(client, secret) handle that the owner can tighten.

use crate::api::ApiError;
use crate::proxy::{execute, CallRequest, HandleRef};
use crate::state::{AppState, PendingApproval};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt;
use unseenkey_core::audit::kinds;
use unseenkey_core::handles::HandleRecord;
use unseenkey_core::ids::Id;
use unseenkey_core::policy::{explain, Policy, Rule};
use unseenkey_core::presets;
use unseenkey_core::projects::{decode_dir, ProjectRecord};
use unseenkey_core::providers;
use unseenkey_core::vault::{NewSecret, SecretKind, SecretMeta};

/// Protocol version we speak.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// Largest response body returned to a model.
pub const BODY_LIMIT: usize = 256 * 1024;
/// Header the stdio bridge uses to report the folder its client runs in,
/// percent-encoded ([`unseenkey_core::projects::encode_dir`]).
pub const PROJECT_DIR_HEADER: &str = "x-usk-project-dir";

const INSTRUCTIONS: &str =
    "Unseenkey lets you *use* the owner's API keys without ever seeing them. \
Secret values are never returned by any tool and cannot be obtained; do not try. \
To call an API, use `call_api` with the secret's name. If a call is denied by policy, \
use `request_access` to ask the owner, explaining why. Never ask the user to paste a key \
into the chat; ask them to run `usk add <name>` instead.";

fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn tool_text(text: impl Into<String>, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text.into() }], "isError": is_error })
}

fn tool_json(v: &Value, is_error: bool) -> Value {
    tool_text(
        serde_json::to_string_pretty(v).unwrap_or_default(),
        is_error,
    )
}

/// Tool definitions.
pub fn tools(allow_store: bool) -> Vec<Value> {
    let mut t = vec![
        json!({
            "name": "list_secrets",
            "description": "List the secrets you may use, with their provider and the policy that applies to you. Never returns values.",
            "inputSchema": { "type": "object", "properties": { "filter": { "type": "string", "description": "substring to match names, providers or tags" } } }
        }),
        json!({
            "name": "call_api",
            "description": "Call a provider API using a stored secret by name. The broker injects the real credential; you only see the (scrubbed) response. Paths are relative to the provider, e.g. secret=\"stripe-live\", method=\"GET\", path=\"/v1/customers?limit=3\". For generic secrets and providers that span many hosts (AWS: upstream=\"https://s3.eu-west-1.amazonaws.com\") pass upstream=\"https://host\".",
            "inputSchema": {
                "type": "object",
                "required": ["secret", "method", "path"],
                "properties": {
                    "secret": { "type": "string" },
                    "method": { "type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] },
                    "path": { "type": "string", "description": "path with optional query, starting with /" },
                    "headers": { "type": "object", "additionalProperties": { "type": "string" } },
                    "body": { "description": "JSON object (sent as application/json) or a string sent as-is" },
                    "upstream": { "type": "string", "description": "only for generic secrets: https://host[:port]" }
                }
            }
        }),
        json!({
            "name": "request_access",
            "description": "Ask the owner to approve a request that policy gates behind approval (for example POST /v1/refunds), or to allow a host the secret is not yet locked to (pass upstream). Waits briefly for a decision. If the policy denies the path outright, the owner must change the policy; this tool will say so.",
            "inputSchema": {
                "type": "object",
                "required": ["secret", "reason"],
                "properties": {
                    "secret": { "type": "string" },
                    "reason": { "type": "string" },
                    "scope": { "type": "string", "description": "\"METHOD /path\" you want approved, e.g. \"POST /v1/refunds\"" },
                    "upstream": { "type": "string", "description": "a host the call was refused for (host_not_allowed): https://host; approval adds it to the secret's allowed hosts" }
                }
            }
        }),
        json!({
            "name": "explain_policy",
            "description": "Plain-English description of what you may do with a secret.",
            "inputSchema": { "type": "object", "required": ["secret"], "properties": { "secret": { "type": "string" } } }
        }),
    ];
    if allow_store {
        t.push(json!({
            "name": "store_secret",
            "description": "Move a key you found (for example in a file) into the vault. The value is never echoed back. Prefer asking the user to run `usk add`.",
            "inputSchema": {
                "type": "object",
                "required": ["name", "value"],
                "properties": { "name": { "type": "string" }, "value": { "type": "string" }, "provider": { "type": "string" } }
            }
        }));
    }
    t
}

/// Label convention for auto-created MCP handles.
fn mcp_label(caller: &str, secret: &str) -> String {
    format!("{caller}/{secret}")
}

/// The provider's recommended policy, or allow-all for secrets without a preset.
fn default_policy(provider: Option<&str>) -> Policy {
    provider
        .and_then(presets::get)
        .and_then(|p| {
            p.policies
                .iter()
                .find(|pp| pp.recommended)
                .or(p.policies.first())
                .and_then(|pp| p.policy(&pp.id))
        })
        .unwrap_or_else(Policy::allow_all)
}

/// Find the active handle this caller has for a secret.
fn find_handle(
    v: &crate::state::DaemonVault,
    caller: &str,
    secret_id: &Id,
    project: Option<Id>,
) -> Option<HandleRecord> {
    let now = unseenkey_core::time::Clock::now_unix_ms(&unseenkey_core::time::SystemClock);
    v.handles()
        .ok()?
        .into_iter()
        .find(|h| {
            h.secret_id == *secret_id
                && h.project == project
                && h.is_active(now)
                && h.policy.callers.len() == 1
                && h.policy.callers[0] == caller
        })
        .cloned()
}

/// Find or create the caller's handle for a secret. Returns the secret's
/// metadata with it, so callers never look the secret up a second time and
/// a handle whose secret is gone cannot read as "a secret without a preset".
fn ensure_handle(
    v: &mut crate::state::DaemonVault,
    caller: &str,
    secret_name: &str,
    project: Option<&ProjectRecord>,
) -> Result<(HandleRecord, SecretMeta), ApiError> {
    let meta = v.get_by_name(secret_name)?.clone();
    if let Some(p) = project {
        if !p.has_secret(&meta.secret_id) {
            return Err(not_in_project(&meta.name, p));
        }
    }
    let pid = project.map(|p| p.project_id);
    if let Some(h) = find_handle(v, caller, &meta.secret_id, pid) {
        return Ok((h, meta));
    }
    let mut policy = default_policy(meta.provider.as_deref());
    policy.callers = vec![caller.to_string()];
    let label = match project {
        Some(p) => format!("{caller}/{}/{}", p.name, meta.name),
        None => mcp_label(caller, &meta.name),
    };
    // A stale label from a revoked handle may exist; suffix if so.
    let label = if v
        .handle_by_label(&label)
        .is_ok_and(|h| h.revoked_at.is_none())
    {
        format!("{label}#{}", &Id::new_v7(0).to_hex()[..6])
    } else {
        label
    };
    let (record, _plain) = v.create_handle_with(
        &meta.secret_id,
        &label,
        policy,
        None,
        None,
        unseenkey_core::vault::HandleOptions {
            project: pid,
            ..Default::default()
        },
    )?;
    let _ = v.audit(
        kinds::HANDLE_CREATED,
        json!({ "id": record.handle_id.to_hex(), "label": record.label, "secret": meta.name, "caller": caller, "auto": true, "project": project.map(|p| p.name.clone()) }),
    );
    Ok((record, meta))
}

/// The project whose folder the client runs in, if it reported one and a
/// project covers it.
fn scope_of(v: &crate::state::DaemonVault, dir: Option<&str>) -> Option<ProjectRecord> {
    dir.and_then(|d| v.project_for_dir(d).ok().flatten().cloned())
}

/// Refusal for a secret outside the client's project.
fn not_in_project(secret: &str, p: &ProjectRecord) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "not_in_project",
        format!(
            "{secret:?} is not part of the project {:?} this folder belongs to; ask the owner to add it in Unseenkey > Projects (or `usk project attach {:?} {secret}`)",
            p.name, p.name
        ),
    )
}

/// A tool error for a secret name the vault does not have.
fn unknown_secret(name: &str) -> Value {
    tool_text(
        format!(
            "no secret named {name:?} in the vault; call list_secrets for the names, or ask the owner to run `usk add {name}`"
        ),
        true,
    )
}

async fn list_secrets(s: &Arc<AppState>, caller: &str, dir: Option<&str>, args: &Value) -> Value {
    let filter = args["filter"].as_str().map(|f| f.to_lowercase());
    let v = s.vault.lock().await;
    let list = match v.list() {
        Ok(l) => l,
        Err(e) => return tool_text(ApiError::from(e).message, true),
    };
    let project = scope_of(&v, dir);
    let pid = project.as_ref().map(|p| p.project_id);
    let items: Vec<Value> = list
        .into_iter()
        .filter(|m| project.as_ref().is_none_or(|p| p.has_secret(&m.secret_id)))
        .filter(|m| {
            filter.as_deref().is_none_or(|f| {
                m.name.to_lowercase().contains(f)
                    || m.provider.as_deref().unwrap_or("").contains(f)
                    || m.tags.iter().any(|t| t.to_lowercase().contains(f))
            })
        })
        .map(|m| {
            let (policy, existing) = match find_handle(&v, caller, &m.secret_id, pid) {
                Some(h) => (h.policy, true),
                None => (default_policy(m.provider.as_deref()), false),
            };
            json!({
                "name": m.name, "type": m.kind.as_str(), "provider": m.provider,
                "upstreams": m.upstreams, "tags": m.tags,
                "mcp": policy.mcp,
                "policy": explain(&policy),
                "policy_is_default": !existing,
                "project": project.as_ref().map(|p| p.name.clone()),
            })
        })
        .filter(|i| i["mcp"].as_bool().unwrap_or(true))
        .collect();
    tool_json(&json!(items), false)
}

async fn explain_policy(s: &Arc<AppState>, caller: &str, dir: Option<&str>, args: &Value) -> Value {
    let Some(name) = args["secret"].as_str() else {
        return tool_text("secret is required", true);
    };
    let v = s.vault.lock().await;
    let meta = match v.get_by_name(name) {
        Ok(m) => m.clone(),
        Err(_) => return unknown_secret(name),
    };
    let project = scope_of(&v, dir);
    if let Some(p) = &project {
        if !p.has_secret(&meta.secret_id) {
            return tool_text(not_in_project(&meta.name, p).message, true);
        }
    }
    let policy = find_handle(&v, caller, &meta.secret_id, project.map(|p| p.project_id))
        .map(|h| h.policy)
        .unwrap_or_else(|| default_policy(meta.provider.as_deref()));
    tool_json(
        &json!({ "secret": meta.name, "text": explain(&policy), "callers": policy.callers }),
        false,
    )
}

async fn call_api(s: &Arc<AppState>, caller: &str, dir: Option<&str>, args: &Value) -> Value {
    let (Some(name), Some(method), Some(path)) = (
        args["secret"].as_str(),
        args["method"].as_str(),
        args["path"].as_str(),
    ) else {
        return tool_text("secret, method and path are required", true);
    };
    if !path.starts_with('/') {
        return tool_text("path must start with /", true);
    }
    let (handle, provider) = {
        let mut v = s.vault.lock().await;
        if v.is_locked() {
            return tool_text(
                "the vault is locked; ask the user to run `usk unlock`",
                true,
            );
        }
        let project = scope_of(&v, dir);
        match ensure_handle(&mut v, caller, name, project.as_ref()) {
            Ok((h, meta)) => (h, meta.provider),
            Err(e) if e.code == "not_found" => return unknown_secret(name),
            Err(e) => return tool_text(e.message, true),
        }
    };
    if !handle.policy.mcp {
        return tool_text(
            format!("{name} is hidden from MCP clients by its policy"),
            true,
        );
    }
    let preset_id = provider.as_deref().unwrap_or("generic");
    let preset = presets::get(preset_id)
        .or_else(|| presets::get("generic"))
        .expect("generic preset exists");
    let upstream_spec = args["upstream"].as_str().map(str::to_string);
    if preset.id == "generic" && upstream_spec.is_none() {
        return tool_text(
            "this secret has no provider preset; pass upstream=\"https://host\"",
            true,
        );
    }
    if upstream_spec.is_none() && preset.upstreams.first().is_some_and(|h| h.contains('*')) {
        return tool_text(
            format!(
                "{} spans many hosts; pass upstream=\"https://<host>\" (allowed: {})",
                preset.display,
                preset.upstreams.join(", ")
            ),
            true,
        );
    }
    let mut headers = HeaderMap::new();
    if let Some(h) = args["headers"].as_object() {
        for (k, v) in h {
            if let (Ok(n), Some(Ok(val))) = (
                axum::http::HeaderName::from_bytes(k.as_bytes()),
                v.as_str().map(HeaderValue::from_str),
            ) {
                headers.insert(n, val);
            }
        }
    }
    let body: Bytes = match &args["body"] {
        Value::Null => Bytes::new(),
        Value::String(sv) => Bytes::from(sv.clone()),
        other => {
            if !headers.contains_key("content-type") {
                headers.insert("content-type", HeaderValue::from_static("application/json"));
            }
            Bytes::from(other.to_string())
        }
    };
    let (p, q) = unseenkey_core::broker::split_path_query(path);
    let call = CallRequest {
        preset,
        method: method.to_uppercase(),
        path: p.to_string(),
        query: q.map(str::to_string),
        headers,
        body,
        upstream_spec,
        aws_scope: None,
        caller: caller.to_string(),
    };
    let resp = execute(s.clone(), HandleRef::Resolved(handle.handle_id), call).await;
    let status = resp.status().as_u16();
    let mut out_headers = serde_json::Map::new();
    for (k, v) in resp.headers().iter() {
        let k = k.as_str();
        if k.starts_with("x-ratelimit")
            || matches!(
                k,
                "content-type"
                    | "content-length"
                    | "x-request-id"
                    | "request-id"
                    | "retry-after"
                    | "x-usk-handle-id"
            )
        {
            out_headers.insert(
                k.to_string(),
                Value::String(v.to_str().unwrap_or("").to_string()),
            );
        }
    }
    let mut stream = resp.into_body().into_data_stream();
    let mut collected: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(c) => {
                if collected.len() + c.len() > BODY_LIMIT {
                    collected.extend_from_slice(&c[..BODY_LIMIT - collected.len()]);
                    truncated = true;
                    break;
                }
                collected.extend_from_slice(&c);
            }
            Err(_) => break,
        }
    }
    let body_text = String::from_utf8_lossy(&collected).into_owned();
    // Broker-side refusals (4xx with our JSON error body) surface as tool errors.
    let broker_error = out_headers.get("x-usk-handle-id").is_none() && status >= 400;
    let result = json!({
        "status": status, "headers": out_headers, "body": body_text, "truncated": truncated,
    });
    tool_json(&result, broker_error)
}

async fn request_access(s: &Arc<AppState>, caller: &str, dir: Option<&str>, args: &Value) -> Value {
    let (Some(name), Some(reason)) = (args["secret"].as_str(), args["reason"].as_str()) else {
        return tool_text("secret and reason are required", true);
    };
    let scope = args["scope"]
        .as_str()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let now = unseenkey_core::time::Clock::now_unix_ms(&unseenkey_core::time::SystemClock);
    let (handle, secret, timeout_s) = {
        let mut v = s.vault.lock().await;
        if v.is_locked() {
            return tool_text(
                "the vault is locked; ask the user to run `usk unlock`",
                true,
            );
        }
        let project = scope_of(&v, dir);
        match ensure_handle(&mut v, caller, name, project.as_ref()) {
            Ok((h, meta)) => {
                let t = h.policy.approval.timeout_seconds;
                (h, meta.name, t)
            }
            Err(e) if e.code == "not_found" => return unknown_secret(name),
            Err(e) => return tool_text(e.message, true),
        }
    };
    // If the scope is a rule the policy denies outright, approval cannot help.
    let mut remember_key = None;
    if let Some(sc) = scope {
        match Rule::parse(sc) {
            Ok(rule) => {
                let denied = handle
                    .policy
                    .deny
                    .iter()
                    .any(|d| d.matches(rule.method.as_str(), rule.path.as_str()))
                    || !handle
                        .policy
                        .allow
                        .iter()
                        .any(|a| a.matches(rule.method.as_str(), rule.path.as_str()));
                if denied && rule.method != unseenkey_core::policy::Method::Any {
                    return tool_json(
                        &json!({
                            "status": "denied_by_policy",
                            "message": format!("{sc} is not allowed by the policy for {secret}; the owner would have to change it (usk handle policy \"{}\")", handle.label),
                        }),
                        true,
                    );
                }
                remember_key = Some(rule.to_string());
            }
            Err(e) => {
                return tool_text(
                    format!("scope must look like \"POST /v1/refunds\": {e}"),
                    true,
                )
            }
        }
    }
    // A host the secret is not locked to: the approval covers adding it.
    let mut new_host: Option<String> = None;
    if let Some(spec) = args["upstream"]
        .as_str()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let host = match unseenkey_core::broker::Upstream::parse(spec) {
            Ok(u) => u.host,
            Err(e) => return tool_text(format!("upstream: {e}"), true),
        };
        let allowed = {
            let v = s.vault.lock().await;
            v.get(&handle.secret_id)
                .map(|m| unseenkey_core::policy::eval::host_allowed(&m.upstreams, &host))
                .unwrap_or(false)
        };
        if !allowed {
            new_host = Some(host);
        }
    }
    let scope_text = match (scope, &new_host) {
        (Some(sc), Some(h)) => format!("{sc}, and allow the host {h}"),
        (Some(sc), None) => sc.to_string(),
        (None, Some(h)) => format!("allow the host {h}"),
        (None, None) => "general access".to_string(),
    };
    let pending = PendingApproval {
        id: Id::new_v7(now),
        kind: "access".into(),
        handle_id: handle.handle_id,
        label: handle.label.clone(),
        secret: secret.clone(),
        caller: caller.to_string(),
        method: String::new(),
        host: new_host.clone().unwrap_or_default(),
        path: String::new(),
        scope: scope_text,
        remember_key: remember_key.clone(),
        created_at: now,
        expires_at: now + (timeout_s as i64) * 1000,
    };
    let approval_id = pending.id;
    {
        let mut v = s.vault.lock().await;
        let _ = v.audit(kinds::ACCESS_REQUESTED, json!({
            "approval": approval_id.to_hex(), "handle": handle.handle_id.to_hex(), "label": handle.label,
            "secret": secret, "caller": caller, "scope": pending.scope, "reason": reason,
        }));
    }
    let rx = s.approval_create(pending.clone()).await;
    s.emit(crate::state::Event::ApprovalRequested {
        id: approval_id.to_hex(),
        label: handle.label.clone(),
        secret: secret.clone(),
        caller: caller.to_string(),
        method: String::new(),
        path: pending.scope.clone(),
        scope: format!("access request: {reason}"),
    });
    let wait = Duration::from_secs((timeout_s as u64).min(120));
    let outcome = tokio::time::timeout(wait, rx).await;
    s.approval_remove(&approval_id).await;
    let (status, allowed) = match outcome {
        Ok(Ok((true, remember))) => {
            let mut v = s.vault.lock().await;
            if remember {
                if let Some(k) = &remember_key {
                    if let Err(e) = v.remember_rule(&handle.handle_id, k) {
                        tracing::warn!(error = %e, "could not persist the remembered approval");
                    }
                }
            }
            if let Some(h) = &new_host {
                match v.update_meta(&handle.secret_id, |m| m.upstreams.push(h.clone())) {
                    Ok(()) => {
                        let _ = v.audit(kinds::SECRET_UPDATED, json!({
                            "id": handle.secret_id.to_hex(), "value_changed": false,
                            "upstream_added": h, "approval": approval_id.to_hex(), "caller": caller,
                        }));
                    }
                    Err(e) => tracing::warn!(error = %e, "could not add the approved host"),
                }
            }
            ("allowed", true)
        }
        Ok(Ok((false, _))) => ("denied", false),
        _ => ("pending", false),
    };
    {
        let mut v = s.vault.lock().await;
        let _ = v.audit(kinds::APPROVAL_DECIDED, json!({
            "approval": approval_id.to_hex(), "handle": handle.handle_id.to_hex(), "label": handle.label,
            "secret": secret, "caller": caller, "allowed": allowed, "status": status,
        }));
    }
    tool_json(
        &json!({
            "approval_id": approval_id.to_hex(), "status": status,
            "message": match status {
                "allowed" => match &new_host {
                    Some(h) => format!("approved, and {h} is now an allowed host for {secret}; retry the call now"),
                    None => "approved; retry the call now".to_string(),
                },
                "denied" => "the owner denied this".to_string(),
                _ => format!("no decision yet; the owner can run `usk approve {}`", approval_id.to_hex()),
            }
        }),
        false,
    )
}

async fn store_secret(s: &Arc<AppState>, caller: &str, dir: Option<&str>, args: &Value) -> Value {
    if !s.mcp_allow_store {
        return tool_text(
            "store_secret is disabled; ask the user to run `usk add <name>`",
            true,
        );
    }
    let (Some(name), Some(value)) = (
        args["secret"].as_str().or(args["name"].as_str()),
        args["value"].as_str(),
    ) else {
        return tool_text("name and value are required", true);
    };
    let detected = providers::detect(value.as_bytes());
    let provider = args["provider"]
        .as_str()
        .map(str::to_string)
        .or_else(|| detected.map(|d| d.provider.to_string()));
    let kind = detected.map(|d| d.kind).unwrap_or(SecretKind::ApiKey);
    let upstreams = provider
        .as_deref()
        .and_then(providers::provider)
        .map(|d| d.upstreams.iter().map(|u| u.to_string()).collect())
        .unwrap_or_default();
    let mut v = s.vault.lock().await;
    if v.is_locked() {
        return tool_text(
            "the vault is locked; ask the user to run `usk unlock`",
            true,
        );
    }
    let res = v.add(NewSecret {
        name: name.to_string(),
        kind,
        value: unseenkey_core::crypto::SecretBytes::from(value),
        fields: Default::default(),
        provider: provider.clone(),
        upstreams,
        tags: vec!["mcp".into()],
        notes: Some(format!("stored by MCP client {caller}")),
    });
    match res {
        Ok(id) => {
            let project = scope_of(&v, dir);
            if let Some(p) = &project {
                let _ = v.attach_secret(&p.project_id, &id);
            }
            let _ = v.audit(
                kinds::SECRET_CREATED,
                json!({ "id": id.to_hex(), "name": name, "provider": provider, "caller": caller, "project": project.map(|p| p.name) }),
            );
            s.rebuild_scrubber(&v);
            tool_json(
                &json!({ "ok": true, "name": name, "provider": provider }),
                false,
            )
        }
        Err(e) => tool_text(ApiError::from(e).message, true),
    }
}

/// Dispatch one JSON-RPC message. `None` for notifications.
/// Answer one JSON-RPC message for `caller`. `dir` is the folder the client
/// reported it runs in (see [`unseenkey_core::projects`]); inside a
/// project's folder the tools see only that project's secrets.
pub async fn handle_message(
    s: &Arc<AppState>,
    caller: &str,
    dir: Option<&str>,
    msg: &Value,
) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg["method"].as_str().unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let Some(id) = id else {
        // Notification: nothing to answer.
        return None;
    };
    let result = match method {
        "initialize" => json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": { "listChanged": false }, "resources": {}, "prompts": {} },
            "serverInfo": { "name": "unseenkey", "version": env!("CARGO_PKG_VERSION") },
            "instructions": INSTRUCTIONS,
        }),
        "ping" => json!({}),
        "tools/list" => json!({ "tools": tools(s.mcp_allow_store) }),
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match name {
                "list_secrets" => list_secrets(s, caller, dir, &args).await,
                "call_api" => call_api(s, caller, dir, &args).await,
                "request_access" => request_access(s, caller, dir, &args).await,
                "explain_policy" => explain_policy(s, caller, dir, &args).await,
                "store_secret" => store_secret(s, caller, dir, &args).await,
                other => return Some(rpc_error(id, -32602, format!("unknown tool {other:?}"))),
            }
        }
        "resources/list" => json!({ "resources": [
            { "uri": "usk://presets", "name": "Provider presets", "description": "Providers and their ready-made policies", "mimeType": "application/json" },
            { "uri": "usk://audit/recent", "name": "Recent audit events", "description": "Your last 50 broker events", "mimeType": "application/json" },
        ] }),
        "resources/read" => {
            let uri = params["uri"].as_str().unwrap_or("");
            match uri {
                "usk://presets" => {
                    let v: Vec<Value> = presets::all().map(|p| json!({
                        "id": p.id, "display": p.display, "upstreams": p.upstreams,
                        "policies": p.policies.iter().map(|pp| json!({ "id": pp.id, "display": pp.display, "recommended": pp.recommended })).collect::<Vec<_>>(),
                    })).collect();
                    json!({ "contents": [{ "uri": uri, "mimeType": "application/json", "text": serde_json::to_string_pretty(&v).unwrap_or_default() }] })
                }
                "usk://audit/recent" => {
                    let v = s.vault.lock().await;
                    let events: Vec<Value> = v
                        .audit_events(1, None, 5000)
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|e| e.body["caller"].as_str() == Some(caller))
                        .rev()
                        .take(50)
                        .map(
                            |e| json!({ "seq": e.seq, "ts": e.ts, "kind": e.kind, "body": e.body }),
                        )
                        .collect();
                    json!({ "contents": [{ "uri": uri, "mimeType": "application/json", "text": serde_json::to_string_pretty(&events).unwrap_or_default() }] })
                }
                _ => return Some(rpc_error(id, -32602, format!("unknown resource {uri:?}"))),
            }
        }
        "prompts/list" => json!({ "prompts": [
            { "name": "setup-project", "description": "Replace real keys in this project's .env with Unseenkey handles", "arguments": [] }
        ] }),
        "prompts/get" => match params["name"].as_str() {
            Some("setup-project") => {
                json!({ "messages": [{ "role": "user", "content": { "type": "text", "text":
                "This project may contain real API keys in .env files. Do not print them. Ask the user to run `usk guard scan .env` and then `usk guard fix .env`, which moves the keys into the vault and rewrites the file with handles plus the provider's base-URL variable. Then confirm the application still starts." } }] })
            }
            _ => return Some(rpc_error(id, -32602, "unknown prompt")),
        },
        _ => return Some(rpc_error(id, -32601, format!("method not found: {method}"))),
    };
    Some(rpc_result(id, result))
}

/// Resolve the caller from `Authorization: Bearer usk_m_…` (or the session
/// token, as caller `local`).
fn authenticate(s: &Arc<AppState>, headers: &HeaderMap) -> Option<String> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)?;
    let now = unseenkey_core::time::Clock::now_unix_ms(&unseenkey_core::time::SystemClock);
    if let Some(name) = s.callers.verify(token, now) {
        return Some(format!("mcp:{name}"));
    }
    if crate::token::verify(&s.token_hash, token) {
        return Some(crate::proxy::LOCAL_CALLER.to_string());
    }
    None
}

/// `POST /mcp`
pub async fn mcp_http(State(s): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(caller) = authenticate(&s, &headers) else {
        return ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid MCP client token; run `usk mcp install <client>`",
        )
        .into_response();
    };
    s.touch().await;
    let dir = headers
        .get(PROJECT_DIR_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(decode_dir);
    let dir = dir.as_deref();
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::OK,
                [("content-type", "application/json")],
                rpc_error(Value::Null, -32700, format!("parse error: {e}")).to_string(),
            )
                .into_response()
        }
    };
    let out = match parsed {
        Value::Array(batch) => {
            let mut results = Vec::new();
            for m in &batch {
                if let Some(r) = handle_message(&s, &caller, dir, m).await {
                    results.push(r);
                }
            }
            if results.is_empty() {
                None
            } else {
                Some(Value::Array(results))
            }
        }
        m => handle_message(&s, &caller, dir, &m).await,
    };
    match out {
        Some(v) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            v.to_string(),
        )
            .into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// `GET /mcp`: no server-initiated stream yet.
pub async fn mcp_get() -> Response {
    StatusCode::METHOD_NOT_ALLOWED.into_response()
}
