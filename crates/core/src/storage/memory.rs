//! In-memory backend for tests and ephemeral vaults.

use super::{HeaderRow, RecordKind, Storage, StorageError, StoredRecord};
use crate::audit::{AuditHead, AuditRow};
use crate::ids::Id;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Volatile storage. Everything is lost on drop.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    header: Option<HeaderRow>,
    records: BTreeMap<Id, BTreeMap<u64, StoredRecord>>,
    audit: Vec<AuditRow>,
    head: Option<AuditHead>,
}

impl MemoryStorage {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for MemoryStorage {
    fn load_header(&self) -> Result<Option<HeaderRow>, StorageError> {
        Ok(self.header.clone())
    }

    fn save_header(&mut self, header: &HeaderRow) -> Result<(), StorageError> {
        self.header = Some(header.clone());
        Ok(())
    }

    fn insert_record(&mut self, record: &StoredRecord) -> Result<(), StorageError> {
        let versions = self.records.entry(record.record_id).or_default();
        if let Some((&latest, _)) = versions.iter().next_back() {
            if record.version <= latest {
                return Err(StorageError::Conflict {
                    record_id: record.record_id,
                    version: record.version,
                });
            }
        }
        versions.insert(record.version, record.clone());
        Ok(())
    }

    fn latest_record(&self, record_id: &Id) -> Result<Option<StoredRecord>, StorageError> {
        Ok(self
            .records
            .get(record_id)
            .and_then(|v| v.values().next_back().cloned()))
    }

    fn record_version(
        &self,
        record_id: &Id,
        version: u64,
    ) -> Result<Option<StoredRecord>, StorageError> {
        Ok(self
            .records
            .get(record_id)
            .and_then(|v| v.get(&version).cloned()))
    }

    fn list_latest(
        &self,
        kind: Option<RecordKind>,
        include_deleted: bool,
    ) -> Result<Vec<StoredRecord>, StorageError> {
        Ok(self
            .records
            .values()
            .filter_map(|v| v.values().next_back())
            .filter(|r| kind.is_none_or(|k| r.kind == k))
            .filter(|r| include_deleted || !r.deleted)
            .cloned()
            .collect())
    }

    fn prune_versions(&mut self, record_id: &Id, keep_from: u64) -> Result<(), StorageError> {
        if let Some(versions) = self.records.get_mut(record_id) {
            versions.retain(|v, _| *v >= keep_from);
        }
        Ok(())
    }

    fn purge_record(&mut self, record_id: &Id) -> Result<(), StorageError> {
        self.records.remove(record_id);
        Ok(())
    }

    fn append_audit(&mut self, row: &AuditRow, head: &AuditHead) -> Result<(), StorageError> {
        let expected = self.audit.last().map(|r| r.seq + 1).unwrap_or(1);
        if row.seq != expected {
            return Err(StorageError::AuditSequence {
                expected,
                got: row.seq,
            });
        }
        self.audit.push(row.clone());
        self.head = Some(head.clone());
        Ok(())
    }

    fn audit_head(&self) -> Result<Option<AuditHead>, StorageError> {
        Ok(self.head.clone())
    }

    fn audit_last(&self) -> Result<Option<AuditRow>, StorageError> {
        Ok(self.audit.last().cloned())
    }

    fn audit_rows(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditRow>, StorageError> {
        Ok(self
            .audit
            .iter()
            .filter(|r| r.seq >= from_seq)
            .take(limit)
            .cloned()
            .collect())
    }

    fn audit_count(&self) -> Result<u64, StorageError> {
        Ok(self.audit.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: Id, version: u64, deleted: bool) -> StoredRecord {
        StoredRecord {
            record_id: id,
            kind: RecordKind::Secret,
            version,
            nonce: [0; 24],
            ciphertext: alloc::vec![1, 2, 3],
            updated_at: 0,
            deleted,
        }
    }

    #[test]
    fn versions_must_increase() {
        let mut s = MemoryStorage::new();
        let id = Id::new_v7(1);
        s.insert_record(&rec(id, 1, false)).unwrap();
        s.insert_record(&rec(id, 2, false)).unwrap();
        assert!(matches!(
            s.insert_record(&rec(id, 2, false)),
            Err(StorageError::Conflict { .. })
        ));
        assert_eq!(s.latest_record(&id).unwrap().unwrap().version, 2);
        assert_eq!(s.record_version(&id, 1).unwrap().unwrap().version, 1);
    }

    #[test]
    fn pruning_and_purging_remove_old_versions() {
        let mut s = MemoryStorage::new();
        let id = Id::new_v7(1);
        for v in 1..=3 {
            s.insert_record(&rec(id, v, false)).unwrap();
        }
        s.prune_versions(&id, 3).unwrap();
        assert_eq!(s.record_version(&id, 1).unwrap(), None);
        assert_eq!(s.record_version(&id, 2).unwrap(), None);
        assert_eq!(s.latest_record(&id).unwrap().unwrap().version, 3);
        // A pruned record still refuses a version it has already seen.
        assert!(matches!(
            s.insert_record(&rec(id, 2, false)),
            Err(StorageError::Conflict { .. })
        ));
        s.purge_record(&id).unwrap();
        assert_eq!(s.latest_record(&id).unwrap(), None);
        assert!(s.prune_versions(&Id::new_v7(9), 1).is_ok());
    }

    #[test]
    fn list_filters_tombstones() {
        let mut s = MemoryStorage::new();
        let a = Id::new_v7(1);
        let b = Id::new_v7(2);
        s.insert_record(&rec(a, 1, false)).unwrap();
        s.insert_record(&rec(b, 1, false)).unwrap();
        s.insert_record(&rec(b, 2, true)).unwrap();
        assert_eq!(s.list_latest(None, false).unwrap().len(), 1);
        assert_eq!(s.list_latest(None, true).unwrap().len(), 2);
        assert_eq!(
            s.list_latest(Some(RecordKind::Policy), true).unwrap().len(),
            0
        );
    }

    #[test]
    fn audit_is_append_only_and_contiguous() {
        let mut s = MemoryStorage::new();
        let row = |seq: u64| AuditRow {
            seq,
            ts: 0,
            kind: "use".into(),
            prev_hash: [0; 32],
            this_hash: [1; 32],
            nonce: [0; 24],
            ciphertext: alloc::vec![],
            signature: None,
        };
        let head = |seq: u64| AuditHead {
            seq,
            hash: [1; 32],
            mac: [seq as u8; 32],
        };
        assert_eq!(s.audit_head().unwrap(), None);
        assert!(matches!(
            s.append_audit(&row(2), &head(2)),
            Err(StorageError::AuditSequence {
                expected: 1,
                got: 2
            })
        ));
        assert_eq!(
            s.audit_head().unwrap(),
            None,
            "a refused append leaves no head"
        );
        s.append_audit(&row(1), &head(1)).unwrap();
        s.append_audit(&row(2), &head(2)).unwrap();
        assert!(s.append_audit(&row(2), &head(2)).is_err());
        assert_eq!(s.audit_count().unwrap(), 2);
        assert_eq!(s.audit_last().unwrap().unwrap().seq, 2);
        assert_eq!(s.audit_head().unwrap(), Some(head(2)));
        assert_eq!(s.audit_rows(2, 10).unwrap().len(), 1);
        assert_eq!(s.audit_rows(1, 1).unwrap().len(), 1);
    }
}
