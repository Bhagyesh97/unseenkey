//! Vault operations for projects.

use super::{records, Vault, VaultError};
use crate::ids::Id;
use crate::projects::{normalize_dir, ProjectRecord};
use crate::storage::{RecordKind, Storage, StoredRecord};
use crate::time::Clock;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// What [`Vault::update_project`] changes; `None` leaves a field alone.
#[derive(Debug, Clone, Default)]
pub struct ProjectChanges {
    /// New name.
    pub name: Option<String>,
    /// Replace the folders.
    pub paths: Option<Vec<String>>,
    /// Set (`Some(Some(n))`) or clear (`Some(None)`) the daily limit.
    pub cap_per_day: Option<Option<u64>>,
    /// Replace the notes (empty clears).
    pub notes: Option<String>,
}

fn clean_paths(paths: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in paths {
        let n = normalize_dir(p);
        if !n.is_empty() && !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

impl<S: Storage, C: Clock> Vault<S, C> {
    pub(super) fn build_project_index(
        &self,
        vk: &crate::crypto::SecretBytes,
    ) -> Result<BTreeMap<Id, ProjectRecord>, VaultError> {
        let mut by_id = BTreeMap::new();
        for rec in self.storage.list_latest(Some(RecordKind::Project), false)? {
            let p: ProjectRecord = records::decrypt_json(vk, &self.header.vault_id, &rec)
                .map_err(|_| VaultError::Corrupt(rec.record_id))?;
            by_id.insert(p.project_id, p);
        }
        Ok(by_id)
    }

    fn write_project(&mut self, mut p: ProjectRecord) -> Result<ProjectRecord, VaultError> {
        let vk = self.vk()?.clone();
        let version = self
            .storage
            .latest_record(&p.project_id)?
            .map(|r| r.version + 1)
            .unwrap_or(1);
        let now = self.clock.now_unix_ms();
        p.updated_at = now;
        let rec = records::encrypt_json(
            &vk,
            &self.header.vault_id,
            p.project_id,
            RecordKind::Project,
            version,
            &p,
            now,
        )?;
        self.storage.insert_record(&rec)?;
        self.projects.insert(p.project_id, p.clone());
        Ok(p)
    }

    fn check_project_name(&self, name: &str, except: Option<&Id>) -> Result<String, VaultError> {
        let name = name.trim();
        if name.is_empty() || name.len() > 128 {
            return Err(VaultError::InvalidName);
        }
        if self
            .projects
            .values()
            .any(|p| Some(&p.project_id) != except && p.name.eq_ignore_ascii_case(name))
        {
            return Err(VaultError::ProjectExists(name.to_string()));
        }
        Ok(name.to_string())
    }

    /// Every project, by name.
    pub fn projects(&self) -> Result<Vec<&ProjectRecord>, VaultError> {
        self.vk()?;
        let mut v: Vec<&ProjectRecord> = self.projects.values().collect();
        v.sort_by_key(|p| p.name.to_lowercase());
        Ok(v)
    }

    /// One project by id.
    pub fn project(&self, id: &Id) -> Result<&ProjectRecord, VaultError> {
        self.vk()?;
        self.projects.get(id).ok_or(VaultError::ProjectNotFound)
    }

    /// One project by name (case-insensitive).
    pub fn project_by_name(&self, name: &str) -> Result<&ProjectRecord, VaultError> {
        self.vk()?;
        let name = name.trim();
        self.projects
            .values()
            .find(|p| p.name.eq_ignore_ascii_case(name))
            .ok_or(VaultError::ProjectNotFound)
    }

    /// The project whose folder most closely contains `dir`, if any.
    pub fn project_for_dir(&self, dir: &str) -> Result<Option<&ProjectRecord>, VaultError> {
        self.vk()?;
        let dir = normalize_dir(dir);
        Ok(self
            .projects
            .values()
            .filter_map(|p| p.match_len(&dir).map(|n| (n, p)))
            .max_by_key(|(n, _)| *n)
            .map(|(_, p)| p))
    }

    /// Projects that use a secret.
    pub fn projects_of_secret(&self, secret_id: &Id) -> Result<Vec<&ProjectRecord>, VaultError> {
        Ok(self
            .projects()?
            .into_iter()
            .filter(|p| p.has_secret(secret_id))
            .collect())
    }

    /// Create a project.
    pub fn create_project(
        &mut self,
        name: &str,
        paths: &[String],
    ) -> Result<ProjectRecord, VaultError> {
        self.vk()?;
        let name = self.check_project_name(name, None)?;
        let now = self.clock.now_unix_ms();
        self.write_project(ProjectRecord {
            project_id: Id::new_v7(now),
            name,
            paths: clean_paths(paths),
            secrets: Vec::new(),
            cap_per_day: None,
            notes: None,
            created_at: now,
            updated_at: now,
        })
    }

    /// Change a project's name, folders, limit or notes.
    pub fn update_project(
        &mut self,
        id: &Id,
        changes: ProjectChanges,
    ) -> Result<ProjectRecord, VaultError> {
        let mut p = self.project(id)?.clone();
        if let Some(name) = &changes.name {
            p.name = self.check_project_name(name, Some(id))?;
        }
        if let Some(paths) = &changes.paths {
            p.paths = clean_paths(paths);
        }
        if let Some(cap) = changes.cap_per_day {
            if cap == Some(0) {
                return Err(VaultError::InvalidPolicy(
                    "a daily limit must be at least 1".into(),
                ));
            }
            p.cap_per_day = cap;
        }
        if let Some(notes) = changes.notes {
            let n = notes.trim();
            p.notes = (!n.is_empty()).then(|| n.to_string());
        }
        self.write_project(p)
    }

    /// Add a secret to a project. Adding one it already has is a no-op.
    pub fn attach_secret(
        &mut self,
        project: &Id,
        secret: &Id,
    ) -> Result<ProjectRecord, VaultError> {
        let mut p = self.project(project)?.clone();
        if !self.index.contains_key(secret) {
            return Err(VaultError::NotFound);
        }
        if p.has_secret(secret) {
            return Ok(p);
        }
        p.secrets.push(*secret);
        self.write_project(p)
    }

    /// Take a secret out of a project. The secret itself stays in the vault,
    /// and handles already made for the project keep working.
    pub fn detach_secret(
        &mut self,
        project: &Id,
        secret: &Id,
    ) -> Result<ProjectRecord, VaultError> {
        let mut p = self.project(project)?.clone();
        let before = p.secrets.len();
        p.secrets.retain(|s| s != secret);
        if p.secrets.len() == before {
            return Ok(p);
        }
        self.write_project(p)
    }

    /// Delete a project. Its secrets and handles stay; the handles simply no
    /// longer count toward any project's limit.
    pub fn delete_project(&mut self, id: &Id) -> Result<(), VaultError> {
        self.project(id)?;
        let version = self
            .storage
            .latest_record(id)?
            .map(|r| r.version + 1)
            .unwrap_or(1);
        self.storage.insert_record(&StoredRecord {
            record_id: *id,
            kind: RecordKind::Project,
            version,
            nonce: [0; 24],
            ciphertext: Vec::new(),
            updated_at: self.clock.now_unix_ms(),
            deleted: true,
        })?;
        self.projects.remove(id);
        Ok(())
    }

    /// Drop a deleted secret from every project that used it.
    pub(super) fn forget_secret_in_projects(&mut self, secret: &Id) -> Result<(), VaultError> {
        let users: Vec<Id> = self
            .projects
            .values()
            .filter(|p| p.has_secret(secret))
            .map(|p| p.project_id)
            .collect();
        for id in users {
            self.detach_secret(&id, secret)?;
        }
        Ok(())
    }
}
