//! SQLite backend: one file, versioned records, `secure_delete` on.
//!
//! Schema (see `docs/08-data-model.md`):
//! - `header`: a single row with the wrapped vault key(s) and KDF parameters.
//! - `records`: `(record_id, version)` primary key; ciphertext only.
//! - `audit`: the hash-chained log; `audit_head`: one row naming its newest
//!   entry under a key derived from the vault key.

use super::{HeaderRow, KeyWrap, RecordKind, Storage, StorageError, StoredRecord};
use crate::audit::{AuditHead, AuditRow};
use crate::crypto::aead::Sealed;
use crate::crypto::kdf::Argon2Profile;
use crate::ids::Id;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA secure_delete = ON;
PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS header (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  vault_id       BLOB    NOT NULL,
  format_version INTEGER NOT NULL,
  argon2_m       INTEGER NOT NULL,
  argon2_t       INTEGER NOT NULL,
  argon2_p       INTEGER NOT NULL,
  salt_pw        BLOB    NOT NULL,
  vk_pw_nonce    BLOB    NOT NULL,
  vk_pw_ct       BLOB    NOT NULL,
  vk_rec_nonce   BLOB,
  vk_rec_ct      BLOB,
  created_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS key_wraps (
  wrap_id    BLOB    PRIMARY KEY,
  kind       TEXT    NOT NULL,
  label      TEXT    NOT NULL,
  salt       BLOB    NOT NULL,
  nonce      BLOB    NOT NULL,
  ct         BLOB    NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
  record_id  BLOB    NOT NULL,
  version    INTEGER NOT NULL,
  kind       TEXT    NOT NULL,
  nonce      BLOB    NOT NULL,
  ciphertext BLOB    NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (record_id, version)
);
CREATE INDEX IF NOT EXISTS records_kind ON records (kind);
CREATE TABLE IF NOT EXISTS audit (
  seq        INTEGER PRIMARY KEY,
  ts         INTEGER NOT NULL,
  kind       TEXT    NOT NULL,
  prev_hash  BLOB    NOT NULL,
  this_hash  BLOB    NOT NULL,
  nonce      BLOB    NOT NULL,
  ciphertext BLOB    NOT NULL,
  signature  BLOB
);
CREATE INDEX IF NOT EXISTS audit_kind ON audit (kind);
CREATE TABLE IF NOT EXISTS audit_head (
  id   INTEGER PRIMARY KEY CHECK (id = 1),
  seq  INTEGER NOT NULL,
  hash BLOB    NOT NULL,
  mac  BLOB    NOT NULL
);
";

/// A vault stored in a SQLite file.
pub struct SqliteStorage {
    conn: Connection,
}

impl core::fmt::Debug for SqliteStorage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SqliteStorage")
    }
}

fn backend(e: rusqlite::Error) -> StorageError {
    StorageError::Backend(e.to_string())
}

fn blob16(v: Vec<u8>, what: &str) -> Result<[u8; 16], StorageError> {
    v.try_into()
        .map_err(|_| StorageError::Corrupt(format!("{what}: expected 16 bytes")))
}

fn blob24(v: Vec<u8>, what: &str) -> Result<[u8; 24], StorageError> {
    v.try_into()
        .map_err(|_| StorageError::Corrupt(format!("{what}: expected 24 bytes")))
}

fn blob32(v: Vec<u8>, what: &str) -> Result<[u8; 32], StorageError> {
    v.try_into()
        .map_err(|_| StorageError::Corrupt(format!("{what}: expected 32 bytes")))
}

impl SqliteStorage {
    /// Open or create the vault file at `path`. Creates parent directories.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StorageError::Backend(e.to_string()))?;
        }
        let conn = Connection::open(path).map_err(backend)?;
        conn.execute_batch(SCHEMA).map_err(backend)?;
        restrict_permissions(path);
        Ok(Self { conn })
    }

    fn load_wraps(&self) -> Result<Vec<KeyWrap>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT wrap_id, kind, label, salt, nonce, ct, created_at
                 FROM key_wraps ORDER BY created_at, wrap_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Vec<u8>>(3)?,
                    r.get::<_, Vec<u8>>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })
            .map_err(backend)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, kind, label, salt, nonce, ct, created_at) = row.map_err(backend)?;
            out.push(KeyWrap {
                id: Id::from_bytes(blob16(id, "wrap_id")?),
                kind,
                label,
                salt: blob32(salt, "wrap salt")?,
                wrapped_vk: Sealed {
                    nonce: blob24(nonce, "wrap nonce")?,
                    ciphertext: ct,
                },
                created_at,
            });
        }
        Ok(out)
    }

    /// An in-memory SQLite database (for tests of the SQL layer itself).
    pub fn open_in_memory() -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory().map_err(backend)?;
        conn.execute_batch(SCHEMA).map_err(backend)?;
        Ok(Self { conn })
    }

    fn row_to_record(row: &rusqlite::Row<'_>) -> Result<StoredRecord, rusqlite::Error> {
        let id: Vec<u8> = row.get(0)?;
        let version: i64 = row.get(1)?;
        let kind: String = row.get(2)?;
        let nonce: Vec<u8> = row.get(3)?;
        let ciphertext: Vec<u8> = row.get(4)?;
        let updated_at: i64 = row.get(5)?;
        let deleted: i64 = row.get(6)?;
        let corrupt = |m: &str| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::other(m.to_string())),
            )
        };
        Ok(StoredRecord {
            record_id: Id::from_bytes(
                id.try_into()
                    .map_err(|_| corrupt("record_id must be 16 bytes"))?,
            ),
            kind: RecordKind::parse(&kind).ok_or_else(|| corrupt("unknown record kind"))?,
            version: version as u64,
            nonce: nonce
                .try_into()
                .map_err(|_| corrupt("nonce must be 24 bytes"))?,
            ciphertext,
            updated_at,
            deleted: deleted != 0,
        })
    }
}

/// Owner-only permissions on Unix. On Windows the file inherits the user
/// profile's ACL, which is owner-only for `%APPDATA%`; explicit ACLs are a
/// later hardening step.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

impl Storage for SqliteStorage {
    fn load_header(&self) -> Result<Option<HeaderRow>, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT vault_id, format_version, argon2_m, argon2_t, argon2_p, salt_pw,
                        vk_pw_nonce, vk_pw_ct, vk_rec_nonce, vk_rec_ct, created_at
                 FROM header WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                        r.get::<_, Vec<u8>>(7)?,
                        r.get::<_, Option<Vec<u8>>>(8)?,
                        r.get::<_, Option<Vec<u8>>>(9)?,
                        r.get::<_, i64>(10)?,
                    ))
                },
            )
            .optional()
            .map_err(backend)?;
        let Some((vid, fv, m, t, p, salt, pwn, pwc, recn, recc, created)) = row else {
            return Ok(None);
        };
        let wrapped_vk_rec = match (recn, recc) {
            (Some(n), Some(c)) => Some(Sealed {
                nonce: blob24(n, "vk_rec_nonce")?,
                ciphertext: c,
            }),
            (None, None) => None,
            _ => return Err(StorageError::Corrupt("half-present recovery wrap".into())),
        };
        let wraps = self.load_wraps()?;
        Ok(Some(HeaderRow {
            vault_id: Id::from_bytes(blob16(vid, "vault_id")?),
            format_version: fv as u32,
            argon2: Argon2Profile {
                m_cost_kib: m as u32,
                t_cost: t as u32,
                p_cost: p as u32,
            },
            salt_pw: blob16(salt, "salt_pw")?,
            wrapped_vk_pw: Sealed {
                nonce: blob24(pwn, "vk_pw_nonce")?,
                ciphertext: pwc,
            },
            wrapped_vk_rec,
            created_at: created,
            wraps,
        }))
    }

    fn save_header(&mut self, h: &HeaderRow) -> Result<(), StorageError> {
        let tx = self.conn.transaction().map_err(backend)?;
        tx.execute(
            "INSERT OR REPLACE INTO header
                 (id, vault_id, format_version, argon2_m, argon2_t, argon2_p, salt_pw,
                  vk_pw_nonce, vk_pw_ct, vk_rec_nonce, vk_rec_ct, created_at)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                h.vault_id.as_bytes().as_slice(),
                h.format_version as i64,
                h.argon2.m_cost_kib as i64,
                h.argon2.t_cost as i64,
                h.argon2.p_cost as i64,
                h.salt_pw.as_slice(),
                h.wrapped_vk_pw.nonce.as_slice(),
                h.wrapped_vk_pw.ciphertext.as_slice(),
                h.wrapped_vk_rec.as_ref().map(|s| s.nonce.to_vec()),
                h.wrapped_vk_rec.as_ref().map(|s| s.ciphertext.clone()),
                h.created_at,
            ],
        )
        .map_err(backend)?;
        tx.execute("DELETE FROM key_wraps", []).map_err(backend)?;
        for w in &h.wraps {
            tx.execute(
                "INSERT INTO key_wraps (wrap_id, kind, label, salt, nonce, ct, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    w.id.as_bytes().as_slice(),
                    w.kind,
                    w.label,
                    w.salt.as_slice(),
                    w.wrapped_vk.nonce.as_slice(),
                    w.wrapped_vk.ciphertext.as_slice(),
                    w.created_at,
                ],
            )
            .map_err(backend)?;
        }
        tx.commit().map_err(backend)?;
        Ok(())
    }

    fn insert_record(&mut self, r: &StoredRecord) -> Result<(), StorageError> {
        let tx = self.conn.transaction().map_err(backend)?;
        let latest: Option<i64> = tx
            .query_row(
                "SELECT MAX(version) FROM records WHERE record_id = ?1",
                params![r.record_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(backend)?;
        if let Some(latest) = latest {
            if r.version <= latest as u64 {
                return Err(StorageError::Conflict {
                    record_id: r.record_id,
                    version: r.version,
                });
            }
        }
        tx.execute(
            "INSERT INTO records (record_id, version, kind, nonce, ciphertext, updated_at, deleted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                r.record_id.as_bytes().as_slice(),
                r.version as i64,
                r.kind.as_str(),
                r.nonce.as_slice(),
                r.ciphertext.as_slice(),
                r.updated_at,
                r.deleted as i64,
            ],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    fn latest_record(&self, record_id: &Id) -> Result<Option<StoredRecord>, StorageError> {
        self.conn
            .query_row(
                "SELECT record_id, version, kind, nonce, ciphertext, updated_at, deleted
                 FROM records WHERE record_id = ?1 ORDER BY version DESC LIMIT 1",
                params![record_id.as_bytes().as_slice()],
                Self::row_to_record,
            )
            .optional()
            .map_err(backend)
    }

    fn record_version(
        &self,
        record_id: &Id,
        version: u64,
    ) -> Result<Option<StoredRecord>, StorageError> {
        self.conn
            .query_row(
                "SELECT record_id, version, kind, nonce, ciphertext, updated_at, deleted
                 FROM records WHERE record_id = ?1 AND version = ?2",
                params![record_id.as_bytes().as_slice(), version as i64],
                Self::row_to_record,
            )
            .optional()
            .map_err(backend)
    }

    fn list_latest(
        &self,
        kind: Option<RecordKind>,
        include_deleted: bool,
    ) -> Result<Vec<StoredRecord>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT r.record_id, r.version, r.kind, r.nonce, r.ciphertext, r.updated_at, r.deleted
                 FROM records r
                 JOIN (SELECT record_id, MAX(version) AS v FROM records GROUP BY record_id) m
                   ON r.record_id = m.record_id AND r.version = m.v
                 WHERE (?1 IS NULL OR r.kind = ?1) AND (?2 = 1 OR r.deleted = 0)
                 ORDER BY r.record_id",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(
                params![kind.map(|k| k.as_str()), include_deleted as i64],
                Self::row_to_record,
            )
            .map_err(backend)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(backend)
    }

    fn append_audit(&mut self, row: &AuditRow, head: &AuditHead) -> Result<(), StorageError> {
        let tx = self.conn.transaction().map_err(backend)?;
        let last: Option<i64> = tx
            .query_row("SELECT MAX(seq) FROM audit", [], |r| r.get(0))
            .map_err(backend)?;
        let expected = last.map(|l| l as u64 + 1).unwrap_or(1);
        if row.seq != expected {
            return Err(StorageError::AuditSequence {
                expected,
                got: row.seq,
            });
        }
        tx.execute(
            "INSERT INTO audit (seq, ts, kind, prev_hash, this_hash, nonce, ciphertext, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                row.seq as i64,
                row.ts,
                row.kind,
                row.prev_hash.as_slice(),
                row.this_hash.as_slice(),
                row.nonce.as_slice(),
                row.ciphertext.as_slice(),
                row.signature.as_deref(),
            ],
        )
        .map_err(backend)?;
        tx.execute(
            "INSERT OR REPLACE INTO audit_head (id, seq, hash, mac) VALUES (1, ?1, ?2, ?3)",
            params![head.seq as i64, head.hash.as_slice(), head.mac.as_slice()],
        )
        .map_err(backend)?;
        tx.commit().map_err(backend)
    }

    fn audit_head(&self) -> Result<Option<AuditHead>, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT seq, hash, mac FROM audit_head WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(backend)?;
        let Some((seq, hash, mac)) = row else {
            return Ok(None);
        };
        Ok(Some(AuditHead {
            seq: seq as u64,
            hash: blob32(hash, "audit_head.hash")?,
            mac: blob32(mac, "audit_head.mac")?,
        }))
    }

    fn audit_last(&self) -> Result<Option<AuditRow>, StorageError> {
        self.conn
            .query_row(
                "SELECT seq, ts, kind, prev_hash, this_hash, nonce, ciphertext, signature
                 FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                Self::row_to_audit,
            )
            .optional()
            .map_err(backend)
    }

    fn audit_rows(&self, from_seq: u64, limit: usize) -> Result<Vec<AuditRow>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT seq, ts, kind, prev_hash, this_hash, nonce, ciphertext, signature
                 FROM audit WHERE seq >= ?1 ORDER BY seq ASC LIMIT ?2",
            )
            .map_err(backend)?;
        let rows = stmt
            .query_map(params![from_seq as i64, limit as i64], Self::row_to_audit)
            .map_err(backend)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(backend)
    }

    fn audit_count(&self) -> Result<u64, StorageError> {
        self.conn
            .query_row("SELECT COUNT(*) FROM audit", [], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
            .map_err(backend)
    }
}

impl SqliteStorage {
    fn row_to_audit(row: &rusqlite::Row<'_>) -> Result<AuditRow, rusqlite::Error> {
        let corrupt = |m: &str| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                Box::new(std::io::Error::other(m.to_string())),
            )
        };
        let seq: i64 = row.get(0)?;
        let prev: Vec<u8> = row.get(3)?;
        let this: Vec<u8> = row.get(4)?;
        let nonce: Vec<u8> = row.get(5)?;
        Ok(AuditRow {
            seq: seq as u64,
            ts: row.get(1)?,
            kind: row.get(2)?,
            prev_hash: prev
                .try_into()
                .map_err(|_| corrupt("prev_hash must be 32 bytes"))?,
            this_hash: this
                .try_into()
                .map_err(|_| corrupt("this_hash must be 32 bytes"))?,
            nonce: nonce
                .try_into()
                .map_err(|_| corrupt("nonce must be 24 bytes"))?,
            ciphertext: row.get(6)?,
            signature: row.get(7)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: Id, version: u64, deleted: bool) -> StoredRecord {
        StoredRecord {
            record_id: id,
            kind: RecordKind::SecretMeta,
            version,
            nonce: [7; 24],
            ciphertext: vec![9, 9],
            updated_at: 42,
            deleted,
        }
    }

    #[test]
    fn header_round_trip() {
        let mut s = SqliteStorage::open_in_memory().unwrap();
        assert_eq!(s.load_header().unwrap(), None);
        let h = HeaderRow {
            vault_id: Id::new_v7(1),
            format_version: 1,
            argon2: Argon2Profile::LIGHT,
            salt_pw: [3; 16],
            wrapped_vk_pw: Sealed {
                nonce: [1; 24],
                ciphertext: vec![1, 2, 3],
            },
            wrapped_vk_rec: Some(Sealed {
                nonce: [2; 24],
                ciphertext: vec![4, 5],
            }),
            created_at: 99,
            wraps: vec![],
        };
        s.save_header(&h).unwrap();
        assert_eq!(s.load_header().unwrap(), Some(h.clone()));
        let h2 = HeaderRow {
            wrapped_vk_rec: None,
            wraps: vec![
                KeyWrap {
                    id: Id::new_v7(5),
                    kind: "hello".into(),
                    label: "laptop".into(),
                    salt: [9; 32],
                    wrapped_vk: Sealed {
                        nonce: [4; 24],
                        ciphertext: vec![6, 7, 8],
                    },
                    created_at: 5,
                },
                KeyWrap {
                    id: Id::new_v7(6),
                    kind: "touchid".into(),
                    label: "mac".into(),
                    salt: [8; 32],
                    wrapped_vk: Sealed {
                        nonce: [5; 24],
                        ciphertext: vec![9],
                    },
                    created_at: 6,
                },
            ],
            ..h
        };
        s.save_header(&h2).unwrap();
        assert_eq!(s.load_header().unwrap(), Some(h2.clone()));
        // Saving again replaces the set rather than appending.
        let h3 = HeaderRow {
            wraps: vec![h2.wraps[1].clone()],
            ..h2
        };
        s.save_header(&h3).unwrap();
        assert_eq!(s.load_header().unwrap(), Some(h3));
    }

    #[test]
    fn records_versioned_and_listed() {
        let mut s = SqliteStorage::open_in_memory().unwrap();
        let a = Id::new_v7(1);
        let b = Id::new_v7(2);
        s.insert_record(&rec(a, 1, false)).unwrap();
        s.insert_record(&rec(a, 2, false)).unwrap();
        s.insert_record(&rec(b, 1, false)).unwrap();
        s.insert_record(&rec(b, 2, true)).unwrap();
        assert!(matches!(
            s.insert_record(&rec(a, 2, false)),
            Err(StorageError::Conflict { .. })
        ));
        assert_eq!(s.latest_record(&a).unwrap().unwrap().version, 2);
        assert_eq!(s.record_version(&a, 1).unwrap().unwrap().version, 1);
        assert_eq!(s.record_version(&a, 3).unwrap(), None);
        assert_eq!(s.list_latest(None, false).unwrap().len(), 1);
        assert_eq!(s.list_latest(None, true).unwrap().len(), 2);
        assert_eq!(
            s.list_latest(Some(RecordKind::SecretMeta), true)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            s.list_latest(Some(RecordKind::Policy), true).unwrap().len(),
            0
        );
    }

    #[test]
    fn file_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        {
            let mut s = SqliteStorage::open(&path).unwrap();
            s.insert_record(&rec(Id::new_v7(1), 1, false)).unwrap();
        }
        let s = SqliteStorage::open(&path).unwrap();
        assert_eq!(s.list_latest(None, true).unwrap().len(), 1);
    }
}
