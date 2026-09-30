//! In-memory backend for tests and ephemeral vaults.

use super::{HeaderRow, RecordKind, Storage, StorageError, StoredRecord};
use crate::ids::Id;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Volatile storage. Everything is lost on drop.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    header: Option<HeaderRow>,
    records: BTreeMap<Id, BTreeMap<u64, StoredRecord>>,
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
}
