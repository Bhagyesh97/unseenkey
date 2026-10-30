//! M1.1 acceptance tests: round trip, no plaintext at rest, recovery, versions.

use std::collections::BTreeMap;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::memory::MemoryStorage;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::FixedClock;
use unseenkey_core::vault::{NewSecret, SecretKind, Vault, VaultError};

// Small Argon2 profile so the suite stays fast; still above the floor.
const FAST: Argon2Profile = Argon2Profile::MINIMUM;

fn new_secret(name: &str, value: &str) -> NewSecret {
    NewSecret {
        name: name.into(),
        kind: SecretKind::ApiKey,
        value: SecretBytes::from(value),
        fields: BTreeMap::new(),
        provider: Some("openai".into()),
        upstreams: vec!["api.openai.com".into()],
        tags: vec![],
        notes: None,
    }
}

#[test]
fn create_unlock_add_reveal_memory() {
    let pw = SecretBytes::from("correct horse battery staple");
    let (mut v, _kit) = Vault::create(MemoryStorage::new(), FixedClock(1_000), &pw, FAST).unwrap();
    let id = v.add(new_secret("openai", "sk-abc")).unwrap();
    assert_eq!(v.list().unwrap().len(), 1);
    assert_eq!(v.get_by_name("openai").unwrap().secret_id, id);
    assert_eq!(v.reveal(&id).unwrap().value, SecretBytes::from("sk-abc"));

    v.lock();
    assert!(matches!(v.list(), Err(VaultError::Locked)));
    assert!(matches!(
        v.unlock_with_password(&SecretBytes::from("wrong")),
        Err(VaultError::WrongCredential)
    ));
    v.unlock_with_password(&pw).unwrap();
    assert_eq!(v.reveal(&id).unwrap().value, SecretBytes::from("sk-abc"));
}

#[test]
fn round_trip_1000_secrets_through_sqlite_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let pw = SecretBytes::from("pw-1000");
    let mut ids = Vec::new();
    {
        let (mut v, _) = Vault::create(
            SqliteStorage::open(&path).unwrap(),
            FixedClock(1),
            &pw,
            FAST,
        )
        .unwrap();
        for i in 0..1000 {
            let id = v
                .add(new_secret(&format!("secret-{i}"), &format!("sk-value-{i}")))
                .unwrap();
            ids.push((i, id));
        }
        assert_eq!(v.len(), 1000);
    }
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(2)).unwrap();
    assert!(v.is_locked());
    v.unlock_with_password(&pw).unwrap();
    assert_eq!(v.len(), 1000);
    for (i, id) in &ids {
        assert_eq!(
            v.reveal(id).unwrap().value,
            SecretBytes::from(format!("sk-value-{i}").as_str())
        );
    }
    let names = v.list().unwrap();
    assert_eq!(names[0].name, "secret-0");
    assert_eq!(names[1].name, "secret-1");
}

#[test]
fn no_plaintext_at_rest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let pw = SecretBytes::from("the-password-itself");
    let values: Vec<String> = (0..200)
        .map(|i| format!("sk-live-PLAINTEXT-{i:04}-abcdefghijklmnop"))
        .collect();
    let names: Vec<String> = (0..200)
        .map(|i| format!("very-unique-name-{i:04}"))
        .collect();
    {
        let (mut v, kit) = Vault::create(
            SqliteStorage::open(&path).unwrap(),
            FixedClock(1),
            &pw,
            FAST,
        )
        .unwrap();
        for (n, val) in names.iter().zip(&values) {
            let mut s = new_secret(n, val);
            s.notes = Some(format!("note-for-{n}"));
            v.add(s).unwrap();
        }
        // Also make sure the recovery phrase is not written anywhere.
        let _ = kit.phrase();
        drop(v);
    }
    // Read every file SQLite may have produced (db, wal, shm).
    let mut bytes = Vec::new();
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let p = entry.unwrap().path();
        bytes.extend(std::fs::read(&p).unwrap());
    }
    assert!(bytes.len() > 10_000, "vault file unexpectedly small");
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    for val in &values {
        assert!(!contains(val.as_bytes()), "plaintext value found at rest");
        assert!(
            !contains(base64_simple(val.as_bytes()).as_bytes()),
            "base64 value found at rest"
        );
    }
    for n in &names {
        assert!(
            !contains(n.as_bytes()),
            "secret name found at rest (metadata must be encrypted)"
        );
        assert!(
            !contains(format!("note-for-{n}").as_bytes()),
            "note found at rest"
        );
    }
    assert!(!contains(b"the-password-itself"));
    assert!(!contains(b"PLAINTEXT"));
    assert!(!contains(b"api.openai.com"), "upstream host found at rest");
}

fn base64_simple(input: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[test]
fn recovery_phrase_unlocks_and_password_can_be_reset() {
    let pw = SecretBytes::from("forgotten");
    let (mut v, kit) = Vault::create(MemoryStorage::new(), FixedClock(1), &pw, FAST).unwrap();
    let id = v.add(new_secret("x", "sk-x")).unwrap();
    let phrase = kit.phrase().to_string();
    v.lock();

    assert!(matches!(
        v.unlock_with_recovery("abandon abandon abandon abandon"),
        Err(VaultError::Recovery)
    ));
    v.unlock_with_recovery(&phrase).unwrap();
    assert_eq!(v.reveal(&id).unwrap().value, SecretBytes::from("sk-x"));

    let new_pw = SecretBytes::from("new password");
    v.change_password(&new_pw, FAST).unwrap();
    v.lock();
    assert!(matches!(
        v.unlock_with_password(&pw),
        Err(VaultError::WrongCredential)
    ));
    v.unlock_with_password(&new_pw).unwrap();
    // Recovery still works after a password change.
    v.lock();
    v.unlock_with_recovery(&phrase).unwrap();
}

#[test]
fn versions_updates_and_deletes() {
    let pw = SecretBytes::from("pw");
    let (mut v, _) = Vault::create(MemoryStorage::new(), FixedClock(1), &pw, FAST).unwrap();
    let id = v.add(new_secret("a", "v1")).unwrap();
    assert_eq!(v.get(&id).unwrap().value_version, 1);
    let ver = v
        .update_value(&id, SecretBytes::from("v2"), BTreeMap::new())
        .unwrap();
    assert_eq!(ver, 2);
    assert_eq!(v.reveal(&id).unwrap().value, SecretBytes::from("v2"));

    v.update_meta(&id, |m| {
        m.name = "renamed".into();
        m.tags.push("prod".into());
    })
    .unwrap();
    assert_eq!(
        v.get_by_name("renamed").unwrap().tags,
        vec!["prod".to_string()]
    );
    assert!(matches!(v.get_by_name("a"), Err(VaultError::NotFound)));

    v.add(new_secret("b", "x")).unwrap();
    assert!(matches!(
        v.add(new_secret("b", "y")),
        Err(VaultError::NameExists(_))
    ));
    assert!(matches!(
        v.update_meta(&id, |m| m.name = "b".into()),
        Err(VaultError::NameExists(_))
    ));
    assert!(matches!(
        v.add(new_secret("  ", "y")),
        Err(VaultError::InvalidName)
    ));

    v.delete(&id).unwrap();
    assert!(matches!(v.get(&id), Err(VaultError::NotFound)));
    assert!(matches!(v.reveal(&id), Err(VaultError::NotFound)));
    assert_eq!(v.len(), 1);
    // Deleted secrets stay deleted across lock/unlock (tombstones honoured).
    v.lock();
    v.unlock_with_password(&pw).unwrap();
    assert_eq!(v.len(), 1);
    // The name is free again.
    v.add(new_secret("renamed", "again")).unwrap();
}

#[test]
fn multi_field_secrets() {
    let pw = SecretBytes::from("pw");
    let (mut v, _) = Vault::create(MemoryStorage::new(), FixedClock(1), &pw, FAST).unwrap();
    let mut fields = BTreeMap::new();
    fields.insert("secret_access_key".to_string(), SecretBytes::from("wJalr"));
    let id = v
        .add(NewSecret {
            name: "aws".into(),
            kind: SecretKind::AwsCredentials,
            value: SecretBytes::from("AKIAIOSFODNN7EXAMPLE"),
            fields,
            provider: Some("aws".into()),
            upstreams: vec!["*.amazonaws.com".into()],
            tags: vec![],
            notes: None,
        })
        .unwrap();
    let r = v.reveal(&id).unwrap();
    assert_eq!(r.fields["secret_access_key"], SecretBytes::from("wJalr"));
}

#[test]
fn guards() {
    let pw = SecretBytes::from("pw");
    assert!(matches!(
        Vault::create(
            MemoryStorage::new(),
            FixedClock(1),
            &pw,
            Argon2Profile {
                m_cost_kib: 8,
                t_cost: 1,
                p_cost: 1
            }
        ),
        Err(VaultError::WeakKdf)
    ));
    assert!(matches!(
        Vault::open(MemoryStorage::new(), FixedClock(1)),
        Err(VaultError::NoVault)
    ));
}

/// A second handle on the same file, to look at what is really stored.
fn raw(path: &std::path::Path) -> SqliteStorage {
    SqliteStorage::open(path).unwrap()
}

#[test]
fn replaced_and_deleted_values_leave_nothing_behind() {
    use unseenkey_core::storage::Storage;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let pw = SecretBytes::from("prune-test-password");
    let (mut v, _) = Vault::create(
        SqliteStorage::open(&path).unwrap(),
        FixedClock(1),
        &pw,
        FAST,
    )
    .unwrap();
    let id = v.add(new_secret("a", "first-value")).unwrap();
    v.update_value(&id, SecretBytes::from("second-value"), BTreeMap::new())
        .unwrap();
    v.update_value(&id, SecretBytes::from("third-value"), BTreeMap::new())
        .unwrap();
    assert_eq!(v.get(&id).unwrap().value_version, 3);
    // Only the current version of the value exists in the file.
    let s = raw(&path);
    assert!(s.record_version(&id, 1).unwrap().is_none());
    assert!(s.record_version(&id, 2).unwrap().is_none());
    assert_eq!(s.latest_record(&id).unwrap().unwrap().version, 3);
    drop(s);

    // A handle keeps only its newest record too, so removing that row cannot
    // revive an earlier policy or a pre-revocation state.
    let (h, _) = v
        .create_handle(
            &id,
            "dev",
            unseenkey_core::policy::Policy::allow_all(),
            None,
        )
        .unwrap();
    v.revoke_handle(&h.handle_id).unwrap();
    let s = raw(&path);
    assert_eq!(s.latest_record(&h.handle_id).unwrap().unwrap().version, 2);
    assert!(s.record_version(&h.handle_id, 1).unwrap().is_none());
    drop(s);

    // Deleting a secret erases every version of the value; a tombstone marks
    // the metadata and nothing older stays.
    v.delete(&id).unwrap();
    let s = raw(&path);
    assert!(s.latest_record(&id).unwrap().is_none(), "value rows remain");
    let meta_id = unseenkey_core::ids::Id::derived("usk/meta-record/v1", &id);
    let latest = s.latest_record(&meta_id).unwrap().unwrap();
    assert!(latest.deleted && latest.ciphertext.is_empty());
    assert_eq!(
        s.list_latest(None, true)
            .unwrap()
            .iter()
            .filter(|r| r.record_id == meta_id)
            .count(),
        1
    );
    for ver in 1..latest.version {
        assert!(s.record_version(&meta_id, ver).unwrap().is_none());
    }
}

#[test]
fn a_deleted_audit_head_is_tampering_not_an_old_log() {
    use unseenkey_core::audit::HeadStatus;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let pw = SecretBytes::from("head-test-password");
    {
        let (mut v, _) = Vault::create(
            SqliteStorage::open(&path).unwrap(),
            FixedClock(1),
            &pw,
            FAST,
        )
        .unwrap();
        v.audit("unlock", serde_json::json!({})).unwrap();
        v.audit("use", serde_json::json!({ "n": 1 })).unwrap();
        assert_eq!(v.audit_verify().unwrap().head, HeadStatus::Verified);
    }
    // What a file-level attacker does to make a cut-short log look fine.
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("DELETE FROM audit_head", [])
        .unwrap();
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(2)).unwrap();
    v.unlock_with_password(&pw).unwrap();
    assert_eq!(v.audit_head_problem(), Some(HeadStatus::Removed));
    let tampered = v.audit_events(1, Some("audit_tampered"), 10).unwrap();
    assert_eq!(tampered.len(), 1);
    assert_eq!(tampered[0].body["state"], "removed");
    // The first append after unlock wrote a fresh head; the record of the
    // removal is in the log for good.
    assert_eq!(v.audit_verify().unwrap().head, HeadStatus::Verified);
}

#[test]
fn a_log_that_never_had_a_head_is_still_tolerated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let pw = SecretBytes::from("legacy-head-password");
    {
        let (mut v, _) = Vault::create(
            SqliteStorage::open(&path).unwrap(),
            FixedClock(1),
            &pw,
            FAST,
        )
        .unwrap();
        v.audit("unlock", serde_json::json!({})).unwrap();
    }
    // A 0.1.0 vault: rows, no head, and no flag saying one was ever written.
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute("DELETE FROM audit_head", []).unwrap();
    c.execute("UPDATE header SET audit_head_required = 0", [])
        .unwrap();
    drop(c);
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(2)).unwrap();
    v.unlock_with_password(&pw).unwrap();
    assert_eq!(v.audit_head_problem(), None);
    assert!(v.audit_verify().unwrap().ok());
}

#[test]
fn the_owner_can_be_confirmed_without_relocking() {
    let pw = SecretBytes::from("confirm-me-please");
    let (mut v, _) = Vault::create(MemoryStorage::new(), FixedClock(1), &pw, FAST).unwrap();
    assert!(v.verify_password(&pw).is_ok());
    assert!(matches!(
        v.verify_password(&SecretBytes::from("not it")),
        Err(VaultError::WrongCredential)
    ));
    let kek = SecretBytes::random(32);
    let wrap = v.add_key_wrap("hello", "laptop", [1; 32], &kek).unwrap();
    assert!(v.verify_kek(&wrap, &kek).is_ok());
    assert!(matches!(
        v.verify_kek(&wrap, &SecretBytes::random(32)),
        Err(VaultError::WrongCredential)
    ));
    assert!(matches!(
        v.verify_kek(&unseenkey_core::ids::Id::new_v7(9), &kek),
        Err(VaultError::UnlockMethodNotFound)
    ));
    // Nothing to confirm against while locked: unlocking is the proof then.
    v.lock();
    assert!(matches!(v.verify_password(&pw), Err(VaultError::Locked)));
}
