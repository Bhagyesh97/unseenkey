//! `/v1/projects`: folders, the secrets they use, and a daily limit.

use crate::api::{resolve_secret, ApiError};
use crate::state::{AppState, DaemonVault, Event};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use std::sync::Arc;
use unseenkey_core::audit::kinds;
use unseenkey_core::ids::Id;
use unseenkey_core::projects::{name_from_dir, ProjectRecord};
use unseenkey_core::vault::ProjectChanges;

type ApiResult<T> = Result<Json<T>, ApiError>;

/// A secret as a project lists it.
#[derive(Serialize)]
pub struct ProjectSecret {
    /// Secret id (hex).
    pub id: String,
    /// Name.
    pub name: String,
    /// Provider id.
    pub provider: Option<String>,
}

/// What a project looks like to owners.
#[derive(Serialize)]
pub struct ProjectView {
    /// Project id (hex).
    pub id: String,
    /// Name.
    pub name: String,
    /// Code folders.
    pub paths: Vec<String>,
    /// Secrets it uses.
    pub secrets: Vec<ProjectSecret>,
    /// Requests per rolling day across its handles; `null` = no limit.
    pub cap_per_day: Option<u64>,
    /// Requests through its handles in the last 24 hours.
    pub requests_today: u64,
    /// Active handles made for it.
    pub handles: usize,
    /// Unix ms of the newest request through one of its handles.
    pub last_used_at: Option<i64>,
    /// Free text.
    pub notes: Option<String>,
    /// Unix ms.
    pub created_at: i64,
    /// Unix ms.
    pub updated_at: i64,
}

fn now_ms() -> i64 {
    unseenkey_core::time::Clock::now_unix_ms(&unseenkey_core::time::SystemClock)
}

/// Ids of the handles made for a project.
pub fn project_handle_ids(v: &DaemonVault, project: &Id) -> Vec<Id> {
    v.handles()
        .map(|hs| {
            hs.into_iter()
                .filter(|h| h.project.as_ref() == Some(project))
                .map(|h| h.handle_id)
                .collect()
        })
        .unwrap_or_default()
}

/// Everything but the usage count, read under the vault lock. The vault is
/// not `Sync`, so no future may hold a reference to it: callers fill in
/// `requests_today` with [`AppState::day_count`] on the returned ids.
fn view_now(v: &DaemonVault, p: &ProjectRecord) -> (ProjectView, Vec<Id>) {
    let now = now_ms();
    let mine: Vec<_> = v
        .handles()
        .map(|hs| {
            hs.into_iter()
                .filter(|h| h.project.as_ref() == Some(&p.project_id))
                .cloned()
                .collect()
        })
        .unwrap_or_else(|_| Vec::new());
    let ids: Vec<Id> = mine.iter().map(|h| h.handle_id).collect();
    let pv = ProjectView {
        id: p.project_id.to_hex(),
        name: p.name.clone(),
        paths: p.paths.clone(),
        secrets: p
            .secrets
            .iter()
            .filter_map(|sid| v.get(sid).ok())
            .map(|m| ProjectSecret {
                id: m.secret_id.to_hex(),
                name: m.name.clone(),
                provider: m.provider.clone(),
            })
            .collect(),
        cap_per_day: p.cap_per_day,
        requests_today: 0,
        handles: mine.iter().filter(|h| h.is_active(now)).count(),
        last_used_at: mine.iter().filter_map(|h| h.last_used_at).max(),
        notes: p.notes.clone(),
        created_at: p.created_at,
        updated_at: p.updated_at,
    };
    (pv, ids)
}

async fn finish(s: &AppState, parts: Vec<(ProjectView, Vec<Id>)>) -> Vec<ProjectView> {
    let mut out = Vec::with_capacity(parts.len());
    for (mut pv, ids) in parts {
        pv.requests_today = s.day_count(&ids).await;
        out.push(pv);
    }
    out
}

async fn one(s: &AppState, part: (ProjectView, Vec<Id>)) -> ProjectView {
    finish(s, vec![part]).await.pop().expect("one view")
}

/// A project by id (hex) or name.
pub fn resolve_project(v: &DaemonVault, r: &str) -> Result<Id, ApiError> {
    if let Some(id) = Id::from_hex(r) {
        if v.project(&id).is_ok() {
            return Ok(id);
        }
    }
    Ok(v.project_by_name(r)?.project_id)
}

/// `GET /v1/projects` query.
#[derive(Deserialize)]
pub struct ListQuery {
    /// Only the project whose folder contains this directory.
    pub dir: Option<String>,
}

/// `GET /v1/projects[?dir=…]`
pub async fn list(
    State(s): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Vec<ProjectView>> {
    let parts = {
        let v = s.vault.lock().await;
        let picked: Vec<ProjectRecord> = match &q.dir {
            Some(d) => v.project_for_dir(d)?.into_iter().cloned().collect(),
            None => v.projects()?.into_iter().cloned().collect(),
        };
        picked.iter().map(|p| view_now(&v, p)).collect::<Vec<_>>()
    };
    Ok(Json(finish(&s, parts).await))
}

/// `GET /v1/projects/{ref}`
pub async fn get(State(s): State<Arc<AppState>>, Path(r): Path<String>) -> ApiResult<ProjectView> {
    let part = {
        let v = s.vault.lock().await;
        let id = resolve_project(&v, &r)?;
        let p = v.project(&id)?.clone();
        view_now(&v, &p)
    };
    Ok(Json(one(&s, part).await))
}

/// `POST /v1/projects` body.
#[derive(Deserialize)]
pub struct CreateProject {
    /// Name; defaults to the first folder's name.
    pub name: Option<String>,
    /// Code folders.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Secrets (names or ids) to add.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Daily request limit.
    pub cap_per_day: Option<u64>,
    /// Free text.
    pub notes: Option<String>,
}

/// `POST /v1/projects`
pub async fn create(
    State(s): State<Arc<AppState>>,
    Json(req): Json<CreateProject>,
) -> Result<(StatusCode, Json<ProjectView>), ApiError> {
    let mut v = s.vault.lock().await;
    let name = match req.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => n.to_string(),
        None => {
            let Some(first) = req.paths.first() else {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid",
                    "give the project a name or a folder",
                ));
            };
            // Folder-derived names never collide: "shop", "shop 2", …
            let base = name_from_dir(first);
            let mut n = base.clone();
            let mut i = 1;
            while v.project_by_name(&n).is_ok() {
                i += 1;
                n = format!("{base} {i}");
            }
            n
        }
    };
    let secret_ids = req
        .secrets
        .iter()
        .map(|r| resolve_secret(&v, r))
        .collect::<Result<Vec<_>, _>>()?;
    let mut p = v.create_project(&name, &req.paths)?;
    for sid in &secret_ids {
        p = v.attach_secret(&p.project_id, sid)?;
    }
    if req.cap_per_day.is_some() || req.notes.is_some() {
        p = v.update_project(
            &p.project_id,
            ProjectChanges {
                cap_per_day: req.cap_per_day.map(Some),
                notes: req.notes.clone(),
                ..Default::default()
            },
        )?;
    }
    let _ = v.audit(
        kinds::PROJECT_CREATED,
        json!({ "id": p.project_id.to_hex(), "name": p.name, "paths": p.paths, "secrets": p.secrets.len() }),
    );
    s.emit(Event::ProjectChanged {
        id: p.project_id.to_hex(),
        change: "created",
    });
    let part = view_now(&v, &p);
    drop(v);
    Ok((StatusCode::CREATED, Json(one(&s, part).await)))
}

fn some_or_null<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<u64>>, D::Error> {
    Ok(Some(Option::<u64>::deserialize(d)?))
}

/// `PATCH /v1/projects/{ref}` body. Absent fields stay; `cap_per_day: null`
/// removes the limit.
#[derive(Deserialize)]
pub struct PatchProject {
    /// New name.
    pub name: Option<String>,
    /// Replace the folders.
    pub paths: Option<Vec<String>>,
    /// Set or (with `null`) remove the daily limit.
    #[serde(default, deserialize_with = "some_or_null")]
    pub cap_per_day: Option<Option<u64>>,
    /// Replace the notes.
    pub notes: Option<String>,
}

/// `PATCH /v1/projects/{ref}`
pub async fn patch(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
    Json(req): Json<PatchProject>,
) -> ApiResult<ProjectView> {
    let mut v = s.vault.lock().await;
    let id = resolve_project(&v, &r)?;
    let p = v.update_project(
        &id,
        ProjectChanges {
            name: req.name,
            paths: req.paths,
            cap_per_day: req.cap_per_day,
            notes: req.notes,
        },
    )?;
    let _ = v.audit(
        kinds::PROJECT_CHANGED,
        json!({ "id": id.to_hex(), "name": p.name, "paths": p.paths, "cap_per_day": p.cap_per_day }),
    );
    s.emit(Event::ProjectChanged {
        id: id.to_hex(),
        change: "updated",
    });
    let part = view_now(&v, &p);
    drop(v);
    Ok(Json(one(&s, part).await))
}

/// `DELETE /v1/projects/{ref}`: the secrets and handles stay.
pub async fn delete(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
) -> ApiResult<serde_json::Value> {
    let mut v = s.vault.lock().await;
    let id = resolve_project(&v, &r)?;
    let name = v.project(&id)?.name.clone();
    v.delete_project(&id)?;
    let _ = v.audit(
        kinds::PROJECT_DELETED,
        json!({ "id": id.to_hex(), "name": name }),
    );
    s.emit(Event::ProjectChanged {
        id: id.to_hex(),
        change: "deleted",
    });
    Ok(Json(json!({ "ok": true })))
}

/// `POST /v1/projects/{ref}/secrets` body.
#[derive(Deserialize)]
pub struct AttachSecret {
    /// Secret name or id.
    pub secret: String,
}

/// `POST /v1/projects/{ref}/secrets`
pub async fn attach(
    State(s): State<Arc<AppState>>,
    Path(r): Path<String>,
    Json(req): Json<AttachSecret>,
) -> ApiResult<ProjectView> {
    let mut v = s.vault.lock().await;
    let id = resolve_project(&v, &r)?;
    let sid = resolve_secret(&v, &req.secret)?;
    let had = v.project(&id)?.has_secret(&sid);
    let p = v.attach_secret(&id, &sid)?;
    if !had {
        let _ = v.audit(
            kinds::PROJECT_CHANGED,
            json!({ "id": id.to_hex(), "name": p.name, "added": sid.to_hex() }),
        );
        s.emit(Event::ProjectChanged {
            id: id.to_hex(),
            change: "updated",
        });
    }
    let part = view_now(&v, &p);
    drop(v);
    Ok(Json(one(&s, part).await))
}

/// `DELETE /v1/projects/{ref}/secrets/{secret}`
pub async fn detach(
    State(s): State<Arc<AppState>>,
    Path((r, secret)): Path<(String, String)>,
) -> ApiResult<ProjectView> {
    let mut v = s.vault.lock().await;
    let id = resolve_project(&v, &r)?;
    let sid = resolve_secret(&v, &secret)?;
    let had = v.project(&id)?.has_secret(&sid);
    let p = v.detach_secret(&id, &sid)?;
    if had {
        let _ = v.audit(
            kinds::PROJECT_CHANGED,
            json!({ "id": id.to_hex(), "name": p.name, "removed": sid.to_hex() }),
        );
        s.emit(Event::ProjectChanged {
            id: id.to_hex(),
            change: "updated",
        });
    }
    let part = view_now(&v, &p);
    drop(v);
    Ok(Json(one(&s, part).await))
}
