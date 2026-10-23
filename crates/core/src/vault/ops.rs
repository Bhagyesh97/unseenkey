//! Vault operations for handles and the audit log.

use super::{records, Vault, VaultError};
use crate::audit::{self, AuditEvent, AuditHead, AuditRow, VerifyReport};
use crate::broker::effective_hosts;
use crate::crypto::aead;
use crate::crypto::hash::Digest;
use crate::crypto::{kdf, SecretBytes};
use crate::handles::{self, Anomaly, AnomalyResponse, HandleRecord, HandleStatus};
use crate::ids::Id;
use crate::policy::Policy;
use crate::storage::{RecordKind, Storage};
use crate::time::Clock;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Persist handle counters after this many unrecorded uses.
pub const COUNTER_FLUSH_EVERY: u64 = 100;

/// How long a throttle set by an incident lasts.
pub const THROTTLE_MS: i64 = 60 * 60 * 1000;

/// Incident settings chosen when a handle is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleOptions {
    /// A tripwire rather than a working handle.
    pub canary: bool,
    /// What unusual activity does to it.
    pub on_anomaly: AnomalyResponse,
}

impl Default for HandleOptions {
    /// A working handle that gets throttled when it misbehaves.
    fn default() -> Self {
        Self {
            canary: false,
            on_anomaly: AnomalyResponse::Throttle,
        }
    }
}

impl HandleOptions {
    /// A canary: locks the vault when tripped unless told otherwise.
    pub fn canary() -> Self {
        Self {
            canary: true,
            on_anomaly: AnomalyResponse::Lock,
        }
    }
}

/// Handles by id, and handle hash → id.
type HandleIndex = (BTreeMap<Id, HandleRecord>, BTreeMap<Digest, Id>);

impl<S: Storage, C: Clock> Vault<S, C> {
    pub(super) fn build_handle_index(&self, vk: &SecretBytes) -> Result<HandleIndex, VaultError> {
        let mut by_id = BTreeMap::new();
        let mut by_hash = BTreeMap::new();
        for rec in self.storage.list_latest(Some(RecordKind::Handle), false)? {
            let h: HandleRecord = records::decrypt_json(vk, &self.header.vault_id, &rec)
                .map_err(|_| VaultError::Corrupt(rec.record_id))?;
            if let Some(hash) = h.hash_bytes() {
                by_hash.insert(hash, h.handle_id);
            }
            by_id.insert(h.handle_id, h);
        }
        Ok((by_id, by_hash))
    }

    /// Persist a handle record. Every write carries the current `use_count`,
    /// so it also notes how far into the audit log that count is good for.
    fn write_handle(&mut self, vk: &SecretBytes, mut h: HandleRecord) -> Result<(), VaultError> {
        let version = self
            .storage
            .latest_record(&h.handle_id)?
            .map(|r| r.version + 1)
            .unwrap_or(1);
        h.counted_seq = self.storage.audit_last()?.map(|r| r.seq).unwrap_or(0);
        self.handle_counters_flushed
            .insert(h.handle_id, h.use_count);
        let now = self.clock.now_unix_ms();
        let rec = records::encrypt_json(
            vk,
            &self.header.vault_id,
            h.handle_id,
            RecordKind::Handle,
            version,
            &h,
            now,
        )?;
        self.storage.insert_record(&rec)?;
        if let Some(hash) = h.hash_bytes() {
            self.handle_hashes.insert(hash, h.handle_id);
        }
        self.handles.insert(h.handle_id, h);
        Ok(())
    }

    /// Create a handle for a secret. Returns the record and the handle string,
    /// which is shown once and never stored. The policy may narrow the secret's
    /// upstreams but not widen them.
    pub fn create_handle(
        &mut self,
        secret_id: &Id,
        label: &str,
        policy: Policy,
        expires_at: Option<i64>,
    ) -> Result<(HandleRecord, String), VaultError> {
        self.create_handle_formatted(secret_id, label, policy, expires_at, None)
    }

    /// [`Vault::create_handle`] with the handle string in a camouflage format
    /// (D-26) instead of the canonical `usk_h_…` one.
    pub fn create_handle_formatted(
        &mut self,
        secret_id: &Id,
        label: &str,
        policy: Policy,
        expires_at: Option<i64>,
        format: Option<&handles::Format>,
    ) -> Result<(HandleRecord, String), VaultError> {
        self.create_handle_with(
            secret_id,
            label,
            policy,
            expires_at,
            format,
            HandleOptions::default(),
        )
    }

    /// [`Vault::create_handle_formatted`] plus the incident settings: whether
    /// the handle is a canary and what unusual activity does to it.
    pub fn create_handle_with(
        &mut self,
        secret_id: &Id,
        label: &str,
        policy: Policy,
        expires_at: Option<i64>,
        format: Option<&handles::Format>,
        opts: HandleOptions,
    ) -> Result<(HandleRecord, String), VaultError> {
        let vk = self.vk()?.clone();
        let meta = self.index.get(secret_id).ok_or(VaultError::NotFound)?;
        policy
            .validate()
            .map_err(|e| VaultError::InvalidPolicy(e.to_string()))?;
        if !policy.upstreams.is_empty()
            && effective_hosts(&meta.upstreams, &policy.upstreams).is_empty()
        {
            return Err(VaultError::PolicyWidensHosts);
        }
        let label = label.trim();
        if label.is_empty() || label.len() > 128 {
            return Err(VaultError::InvalidName);
        }
        if self
            .handles
            .values()
            .any(|h| h.label == label && h.revoked_at.is_none())
        {
            return Err(VaultError::LabelExists(label.to_string()));
        }
        let plain = match format {
            Some(f) => f.generate(),
            None => handles::generate(),
        };
        let now = self.clock.now_unix_ms();
        let record = HandleRecord {
            handle_id: Id::new_v7(now),
            handle_hash: hex::encode(handles::hash_of(&plain)),
            secret_id: *secret_id,
            label: label.to_string(),
            policy,
            created_at: now,
            expires_at,
            revoked_at: None,
            use_count: 0,
            last_used_at: None,
            counted_seq: 0,
            remembered: Vec::new(),
            canary: opts.canary,
            on_anomaly: opts.on_anomaly,
            status: HandleStatus::Normal,
            last_anomaly: None,
        };
        self.write_handle(&vk, record.clone())?;
        Ok((record, plain))
    }

    /// Record an incident on a handle and the standing it leaves the handle
    /// in. `Alert` and `Lock` responses change nothing on the handle itself
    /// (locking is the daemon's job); the others set the status.
    pub fn set_handle_incident(&mut self, id: &Id, anomaly: Anomaly) -> Result<(), VaultError> {
        let vk = self.vk()?.clone();
        let mut h = self
            .handles
            .get(id)
            .ok_or(VaultError::HandleNotFound)?
            .clone();
        h.status = match anomaly.response {
            AnomalyResponse::Alert | AnomalyResponse::Lock => h.status,
            AnomalyResponse::Throttle => HandleStatus::Throttled {
                until: anomaly.at + THROTTLE_MS,
            },
            AnomalyResponse::Approve => HandleStatus::ApprovalRequired,
            AnomalyResponse::Pause => HandleStatus::Paused,
        };
        h.last_anomaly = Some(anomaly);
        self.write_handle(&vk, h)
    }

    /// Put a handle back to normal after an incident. Returns whether anything
    /// changed. Requires an unlocked vault.
    pub fn resume_handle(&mut self, id: &Id) -> Result<bool, VaultError> {
        let vk = self.vk()?.clone();
        let mut h = self
            .handles
            .get(id)
            .ok_or(VaultError::HandleNotFound)?
            .clone();
        if h.status == HandleStatus::Normal && h.last_anomaly.is_none() {
            return Ok(false);
        }
        h.status = HandleStatus::Normal;
        h.last_anomaly = None;
        self.write_handle(&vk, h)?;
        Ok(true)
    }

    /// Change what unusual activity does to a handle.
    pub fn set_handle_response(
        &mut self,
        id: &Id,
        on_anomaly: AnomalyResponse,
    ) -> Result<(), VaultError> {
        let vk = self.vk()?.clone();
        let mut h = self
            .handles
            .get(id)
            .ok_or(VaultError::HandleNotFound)?
            .clone();
        if h.on_anomaly == on_anomaly {
            return Ok(());
        }
        h.on_anomaly = on_anomaly;
        self.write_handle(&vk, h)
    }

    /// All handles, active and revoked, newest first.
    pub fn handles(&self) -> Result<Vec<&HandleRecord>, VaultError> {
        self.vk()?;
        let mut v: Vec<&HandleRecord> = self.handles.values().collect();
        v.sort_by_key(|h| core::cmp::Reverse(h.created_at));
        Ok(v)
    }

    /// A handle by id.
    pub fn handle(&self, id: &Id) -> Result<&HandleRecord, VaultError> {
        self.vk()?;
        self.handles.get(id).ok_or(VaultError::HandleNotFound)
    }

    /// A handle by label (active ones first).
    pub fn handle_by_label(&self, label: &str) -> Result<&HandleRecord, VaultError> {
        self.vk()?;
        self.handles
            .values()
            .filter(|h| h.label == label)
            .max_by_key(|h| (h.revoked_at.is_none(), h.created_at))
            .ok_or(VaultError::HandleNotFound)
    }

    /// Resolve a presented handle string. Returns `None` for unknown handles;
    /// the caller decides how to respond (identically for unknown and revoked).
    pub fn handle_by_string(&self, presented: &str) -> Result<Option<&HandleRecord>, VaultError> {
        self.vk()?;
        if !crate::presets::is_handle(presented) {
            return Ok(None);
        }
        let hash = handles::hash_of(presented);
        Ok(self
            .handle_hashes
            .get(&hash)
            .and_then(|id| self.handles.get(id)))
    }

    /// Revoke a handle. Effective immediately for in-memory lookups.
    pub fn revoke_handle(&mut self, id: &Id) -> Result<(), VaultError> {
        let vk = self.vk()?.clone();
        let mut h = self
            .handles
            .get(id)
            .ok_or(VaultError::HandleNotFound)?
            .clone();
        if h.revoked_at.is_none() {
            h.revoked_at = Some(self.clock.now_unix_ms());
            self.write_handle(&vk, h)?;
        }
        Ok(())
    }

    /// Revoke every active handle of `secret_id`; returns the ids revoked.
    /// [`Vault::delete`] calls this so no handle outlives its secret.
    pub(crate) fn revoke_handles_of(&mut self, secret_id: &Id) -> Result<Vec<Id>, VaultError> {
        let vk = self.vk()?.clone();
        let now = self.clock.now_unix_ms();
        let stale: Vec<HandleRecord> = self
            .handles
            .values()
            .filter(|h| h.secret_id == *secret_id && h.revoked_at.is_none())
            .cloned()
            .collect();
        let mut ids = Vec::with_capacity(stale.len());
        for mut h in stale {
            h.revoked_at = Some(now);
            ids.push(h.handle_id);
            self.write_handle(&vk, h)?;
        }
        Ok(ids)
    }

    /// Replace a handle's policy.
    pub fn set_handle_policy(&mut self, id: &Id, policy: Policy) -> Result<(), VaultError> {
        let vk = self.vk()?.clone();
        let mut h = self
            .handles
            .get(id)
            .ok_or(VaultError::HandleNotFound)?
            .clone();
        policy
            .validate()
            .map_err(|e| VaultError::InvalidPolicy(e.to_string()))?;
        let meta = self.index.get(&h.secret_id).ok_or(VaultError::NotFound)?;
        if !policy.upstreams.is_empty()
            && effective_hosts(&meta.upstreams, &policy.upstreams).is_empty()
        {
            return Err(VaultError::PolicyWidensHosts);
        }
        h.policy = policy;
        // Standing approvals were given against the old rules.
        h.remembered.clear();
        self.write_handle(&vk, h)
    }

    /// Remember that the owner approved `rule` for this handle with "always".
    /// A no-op when already remembered. Requires an unlocked vault.
    pub fn remember_rule(&mut self, id: &Id, rule: &str) -> Result<(), VaultError> {
        let vk = self.vk()?.clone();
        let rule = rule.trim();
        if rule.is_empty() || rule.len() > 200 {
            return Err(VaultError::InvalidPolicy("invalid rule".into()));
        }
        let mut h = self
            .handles
            .get(id)
            .ok_or(VaultError::HandleNotFound)?
            .clone();
        if h.remembered.iter().any(|r| r == rule) {
            return Ok(());
        }
        h.remembered.push(rule.to_string());
        self.write_handle(&vk, h)
    }

    /// Forget remembered approvals: one rule, or all of them when `rule` is
    /// `None`. Returns how many were removed. Requires an unlocked vault.
    pub fn forget_rules(&mut self, id: &Id, rule: Option<&str>) -> Result<usize, VaultError> {
        let vk = self.vk()?.clone();
        let mut h = self
            .handles
            .get(id)
            .ok_or(VaultError::HandleNotFound)?
            .clone();
        let before = h.remembered.len();
        match rule {
            Some(r) => {
                let r = r.trim();
                h.remembered.retain(|x| x != r);
            }
            None => h.remembered.clear(),
        }
        let removed = before - h.remembered.len();
        if removed > 0 {
            self.write_handle(&vk, h)?;
        }
        Ok(removed)
    }

    /// Record a use in memory; persisted every [`COUNTER_FLUSH_EVERY`] uses and
    /// on lock. Uses that never get persisted (a crash) are recovered from the
    /// audit log by [`Vault::reconcile_handle_counters`] on the next unlock.
    pub fn touch_handle(&mut self, id: &Id, now: i64) -> Result<(), VaultError> {
        let vk = self.vk()?.clone();
        let h = self.handles.get_mut(id).ok_or(VaultError::HandleNotFound)?;
        h.use_count += 1;
        h.last_used_at = Some(now);
        let dirty = h.use_count - self.handle_counters_flushed.get(id).copied().unwrap_or(0);
        if dirty >= COUNTER_FLUSH_EVERY {
            let snapshot = h.clone();
            self.write_handle(&vk, snapshot)?;
        }
        Ok(())
    }

    /// Persist every handle whose counters changed since the last flush.
    pub fn flush_handle_counters(&mut self) -> Result<(), VaultError> {
        let Some(vk) = self.vk.clone() else {
            return Ok(());
        };
        let dirty: Vec<HandleRecord> = self
            .handles
            .values()
            .filter(|h| {
                h.use_count
                    != self
                        .handle_counters_flushed
                        .get(&h.handle_id)
                        .copied()
                        .unwrap_or(0)
            })
            .cloned()
            .collect();
        for h in dirty {
            self.write_handle(&vk, h)?;
        }
        Ok(())
    }

    /// Add to each handle's `use_count` the `use` events the log holds past
    /// the point its record was last written. Called on unlock, so a daemon
    /// that died before flushing (up to [`COUNTER_FLUSH_EVERY`] − 1 uses per
    /// handle) does not hand those uses back to a capped handle. The counts
    /// become dirty in memory and are persisted by the next flush.
    ///
    /// A request's `use` event is written after its `touch_handle`, so a
    /// record flushed while requests were in flight can count those once in
    /// the record and once here: an over-count of at most the concurrency at
    /// that moment, on the safe side of a cap.
    pub(super) fn reconcile_handle_counters(&mut self) -> Result<(), VaultError> {
        // A record written before `counted_seq` existed reads as 0 while
        // already holding every flushed use; adding the log on top would
        // double it. Pin such records to the log's end instead: the next
        // write persists the position, and at most the unflushed uses of the
        // last session before the upgrade are forgone, as they were before.
        let last_seq = self.storage.audit_last()?.map(|r| r.seq).unwrap_or(0);
        for h in self.handles.values_mut() {
            if h.counted_seq == 0 && h.use_count > 0 {
                h.counted_seq = last_seq;
            }
        }
        let Some(start) = self.handles.values().map(|h| h.counted_seq).min() else {
            return Ok(());
        };
        let by_hex: BTreeMap<String, Id> = self
            .handles
            .values()
            .map(|h| (h.handle_id.to_hex(), h.handle_id))
            .collect();
        let mut cursor = start + 1;
        loop {
            let batch = self.audit_events(cursor, Some(audit::kinds::USE), 1024)?;
            let Some(last) = batch.last() else {
                break;
            };
            cursor = last.seq + 1;
            for ev in &batch {
                let Some(id) = ev
                    .body
                    .get("handle")
                    .and_then(|v| v.as_str())
                    .and_then(|s| by_hex.get(s))
                else {
                    continue;
                };
                if let Some(h) = self.handles.get_mut(id) {
                    if ev.seq > h.counted_seq {
                        h.use_count += 1;
                        h.last_used_at = Some(h.last_used_at.map_or(ev.ts, |t| t.max(ev.ts)));
                    }
                }
            }
        }
        Ok(())
    }

    /// `(handle id, timestamp)` of every `use` event at or after `since_ts`,
    /// oldest first, for rebuilding sliding-window counters after a restart.
    /// Finds the starting row by binary search on the cleartext timestamps,
    /// so only the events in the window are decrypted. Requires an unlocked
    /// vault.
    pub fn recent_uses(&self, since_ts: i64) -> Result<Vec<(Id, i64)>, VaultError> {
        self.vk()?;
        let Some(last) = self.storage.audit_last()? else {
            return Ok(Vec::new());
        };
        if last.ts < since_ts {
            return Ok(Vec::new());
        }
        let (mut lo, mut hi) = (1u64, last.seq);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.storage.audit_rows(mid, 1)?.first() {
                Some(r) if r.ts >= since_ts => hi = r.seq,
                Some(r) => lo = r.seq + 1,
                None => lo = mid + 1,
            }
        }
        let by_hex: BTreeMap<String, Id> = self
            .handles
            .values()
            .map(|h| (h.handle_id.to_hex(), h.handle_id))
            .collect();
        let mut out = Vec::new();
        let mut cursor = lo;
        loop {
            let batch = self.audit_events(cursor, Some(audit::kinds::USE), 1024)?;
            let Some(last) = batch.last() else {
                break;
            };
            cursor = last.seq + 1;
            for ev in &batch {
                if ev.ts < since_ts {
                    continue;
                }
                if let Some(id) = ev
                    .body
                    .get("handle")
                    .and_then(|v| v.as_str())
                    .and_then(|s| by_hex.get(s))
                {
                    out.push((*id, ev.ts));
                }
            }
        }
        Ok(out)
    }

    fn audit_dek(&self, vk: &SecretBytes) -> SecretBytes {
        kdf::subkey(vk, b"usk/audit-dek/v1")
    }

    /// Key for the audit log's keyed head. A separate subkey, so the head
    /// MAC and the body AEAD never share key material.
    fn audit_head_key(&self, vk: &SecretBytes) -> zeroize::Zeroizing<[u8; 32]> {
        let sub = kdf::subkey(vk, b"usk/audit-head/v1");
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        key.copy_from_slice(sub.expose());
        key
    }

    fn audit_aad(&self, seq: u64, kind: &str) -> Vec<u8> {
        let mut a = Vec::with_capacity(64);
        a.extend_from_slice(self.header.vault_id.as_bytes());
        a.extend_from_slice(&seq.to_be_bytes());
        a.extend_from_slice(kind.as_bytes());
        a
    }

    /// Append an audit event. Requires an unlocked vault. Returns its sequence number.
    pub fn audit(&mut self, kind: &str, body: serde_json::Value) -> Result<u64, VaultError> {
        let vk = self.vk()?.clone();
        let last = self.storage.audit_last()?;
        let (seq, prev_hash) = match &last {
            Some(r) => (r.seq + 1, r.this_hash),
            None => (1, audit::genesis(&self.header.vault_id)),
        };
        let ts = self.clock.now_unix_ms();
        let json = serde_json::to_vec(&body)
            .map_err(|_| VaultError::InvalidPolicy("audit body".into()))?;
        let sealed = aead::seal(
            &self.audit_dek(&vk),
            &self.audit_aad(seq, kind),
            &SecretBytes::new(json),
        )?;
        let this_hash =
            audit::chain_hash(&prev_hash, seq, ts, kind, &sealed.nonce, &sealed.ciphertext);
        let head = AuditHead {
            seq,
            hash: this_hash,
            mac: audit::head_mac(&self.audit_head_key(&vk), seq, &this_hash),
        };
        self.storage.append_audit(
            &AuditRow {
                seq,
                ts,
                kind: kind.to_string(),
                prev_hash,
                this_hash,
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
                signature: None,
            },
            &head,
        )?;
        Ok(seq)
    }

    /// Decrypt events with `seq >= since_seq`, optionally filtered by kind, up to `limit`.
    pub fn audit_events(
        &self,
        since_seq: u64,
        kind: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, VaultError> {
        let vk = self.vk()?;
        let dek = self.audit_dek(vk);
        let mut out = Vec::new();
        let mut cursor = since_seq.max(1);
        while out.len() < limit {
            let batch = self.storage.audit_rows(cursor, 256)?;
            if batch.is_empty() {
                break;
            }
            for row in &batch {
                cursor = row.seq + 1;
                if kind.is_some_and(|k| k != row.kind) {
                    continue;
                }
                let sealed = aead::Sealed {
                    nonce: row.nonce,
                    ciphertext: row.ciphertext.clone(),
                };
                let plain = aead::open(&dek, &self.audit_aad(row.seq, &row.kind), &sealed)
                    .map_err(|_| VaultError::Corrupt(self.header.vault_id))?;
                let body: serde_json::Value = serde_json::from_slice(plain.expose())
                    .map_err(|_| VaultError::Corrupt(self.header.vault_id))?;
                out.push(AuditEvent {
                    seq: row.seq,
                    ts: row.ts,
                    kind: row.kind.clone(),
                    body,
                });
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Walk the whole chain, and check the keyed head when the vault is
    /// unlocked. Works while locked too (the chain needs no key), but then the
    /// report says the head went [`audit::HeadStatus::Unchecked`] and a cut-short log
    /// would pass.
    pub fn audit_verify(&self) -> Result<VerifyReport, VaultError> {
        let mut rows = Vec::new();
        let mut cursor = 1;
        loop {
            let batch = self.storage.audit_rows(cursor, 1024)?;
            if batch.is_empty() {
                break;
            }
            cursor = batch.last().map(|r| r.seq + 1).unwrap_or(cursor);
            rows.extend(batch);
        }
        let mut report = audit::verify(&self.header.vault_id, &rows);
        if let Some(vk) = &self.vk {
            let head = self.storage.audit_head()?;
            report.head = audit::check_head(&self.audit_head_key(vk), head.as_ref(), rows.last());
        }
        Ok(report)
    }

    /// Number of audit rows.
    pub fn audit_count(&self) -> Result<u64, VaultError> {
        Ok(self.storage.audit_count()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_from_before_counted_seq_are_pinned_not_doubled() {
        use crate::crypto::kdf::Argon2Profile;
        use crate::storage::memory::MemoryStorage;
        use crate::time::FixedClock;
        let (mut v, _) = Vault::create(
            MemoryStorage::new(),
            FixedClock(1_000),
            &SecretBytes::from("records-pinned-not-doubled"),
            Argon2Profile::MINIMUM,
        )
        .unwrap();
        let sid = v
            .add(crate::vault::NewSecret {
                name: "s".into(),
                kind: crate::vault::SecretKind::ApiKey,
                value: SecretBytes::from("tok_abcdefghijklmnop"),
                fields: BTreeMap::new(),
                provider: None,
                upstreams: vec!["api.example.com".into()],
                tags: vec![],
                notes: None,
            })
            .unwrap();
        let (rec, _) = v
            .create_handle(&sid, "h", Policy::allow_all(), None)
            .unwrap();
        let hid = rec.handle_id;
        // Five uses, flushed the old way: a record whose use_count is right
        // but which carries no log position (counted_seq = 0), as 0.1.1 wrote.
        for _ in 0..5 {
            v.touch_handle(&hid, 2_000).unwrap();
            v.audit(
                audit::kinds::USE,
                serde_json::json!({ "handle": hid.to_hex() }),
            )
            .unwrap();
        }
        let vk = v.vk().unwrap().clone();
        let mut legacy = v.handles.get(&hid).unwrap().clone();
        legacy.counted_seq = 0;
        let version = v.storage.latest_record(&hid).unwrap().unwrap().version + 1;
        let rec = records::encrypt_json(
            &vk,
            &v.header.vault_id,
            hid,
            RecordKind::Handle,
            version,
            &legacy,
            3_000,
        )
        .unwrap();
        v.storage.insert_record(&rec).unwrap();
        v.handles.insert(hid, legacy);
        v.reconcile_handle_counters().unwrap();
        let h = v.handles.get(&hid).unwrap();
        assert_eq!(h.use_count, 5, "not doubled");
        assert!(h.counted_seq > 0, "pinned to the log's end");
    }
}
