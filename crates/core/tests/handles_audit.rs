//! Handles and the audit log through the vault, on SQLite.

use serde_json::json;
use std::collections::BTreeMap;
use unseenkey_core::audit::kinds;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::handles;
use unseenkey_core::policy::Policy;
use unseenkey_core::presets;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::FixedClock;
use unseenkey_core::vault::{NewSecret, SecretKind, Vault, VaultError};

const FAST: Argon2Profile = Argon2Profile::MINIMUM;
const PW: &str = "handles-audit-password";

fn stripe() -> NewSecret {
    NewSecret {
        name: "stripe-live".into(),
        kind: SecretKind::ApiKey,
        value: SecretBytes::from("sk_live_51Habcdefghijklmnop"),
        fields: BTreeMap::new(),
        provider: Some("stripe".into()),
        upstreams: vec!["api.stripe.com".into()],
        tags: vec![],
        notes: None,
    }
}

#[test]
fn handle_lifecycle_and_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let plain;
    let hid;
    {
        let (mut v, _) = Vault::create(
            SqliteStorage::open(&path).unwrap(),
            FixedClock(1_000),
            &SecretBytes::from(PW),
            FAST,
        )
        .unwrap();
        let sid = v.add(stripe()).unwrap();
        let policy = presets::policy_ref("stripe:payments").unwrap();
        let (rec, p) = v
            .create_handle(&sid, "cursor", policy, Some(5_000))
            .unwrap();
        assert!(handles::is_handle_shaped(&p));
        assert_eq!(rec.label, "cursor");
        assert_eq!(rec.secret_id, sid);
        assert!(rec.is_active(4_999));
        assert!(!rec.is_active(5_000));
        plain = p;
        hid = rec.handle_id;

        // Duplicate active label and widening policies are refused.
        assert!(matches!(
            v.create_handle(&sid, "cursor", Policy::allow_all(), None),
            Err(VaultError::LabelExists(_))
        ));
        let mut widening = Policy::allow_all();
        widening.upstreams = vec!["evil.example".into()];
        assert!(matches!(
            v.create_handle(&sid, "evil", widening, None),
            Err(VaultError::PolicyWidensHosts)
        ));
        // Narrowing to the same host is fine.
        let mut narrowing = Policy::allow_all();
        narrowing.upstreams = vec!["api.stripe.com".into()];
        v.create_handle(&sid, "narrow", narrowing, None).unwrap();

        // Lookup by string, by label; unknown strings resolve to None.
        assert_eq!(v.handle_by_string(&plain).unwrap().unwrap().handle_id, hid);
        assert!(v
            .handle_by_string("usk_h_00000000000000000000000000000000")
            .unwrap()
            .is_none());
        assert!(v.handle_by_string("garbage").unwrap().is_none());
        assert_eq!(v.handle_by_label("narrow").unwrap().label, "narrow");
        assert_eq!(v.handles().unwrap().len(), 2);

        // Use counters flush on lock.
        for _ in 0..7 {
            v.touch_handle(&hid, 2_000).unwrap();
        }
        assert_eq!(v.handle(&hid).unwrap().use_count, 7);
        v.lock();
    }
    // Reopen: the handle, its policy and counters survived; the string still resolves.
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(3_000)).unwrap();
    v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
    let h = v.handle_by_string(&plain).unwrap().unwrap();
    assert_eq!(h.use_count, 7);
    assert_eq!(h.last_used_at, Some(2_000));
    assert_eq!(h.policy.upstreams, vec!["api.stripe.com".to_string()]);
    assert!(h
        .policy
        .deny
        .iter()
        .any(|r| r.to_string() == "* /v1/refunds/**"));

    // Revoke: string no longer usable, label can be reused.
    v.revoke_handle(&hid).unwrap();
    assert!(v
        .handle_by_string(&plain)
        .unwrap()
        .unwrap()
        .revoked_at
        .is_some());
    let sid = v.get_by_name("stripe-live").unwrap().secret_id;
    v.create_handle(&sid, "cursor", Policy::allow_all(), None)
        .unwrap();
    assert_eq!(v.handles().unwrap().len(), 3);

    // Policy replacement is validated.
    let nid = v.handle_by_label("narrow").unwrap().handle_id;
    v.set_handle_policy(&nid, presets::policy_ref("stripe:read-only").unwrap())
        .unwrap();
    let mut bad = Policy::allow_all();
    bad.upstreams = vec!["evil.example".into()];
    assert!(matches!(
        v.set_handle_policy(&nid, bad),
        Err(VaultError::PolicyWidensHosts)
    ));

    // The vault file never contains the handle string.
    drop(v);
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(plain.len()).any(|w| w == plain.as_bytes()));
}

#[test]
fn audit_chain_survives_reopen_and_detects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    {
        let (mut v, _) = Vault::create(
            SqliteStorage::open(&path).unwrap(),
            FixedClock(1),
            &SecretBytes::from(PW),
            FAST,
        )
        .unwrap();
        assert_eq!(v.audit(kinds::UNLOCK, json!({})).unwrap(), 1);
        for i in 0..5 {
            v.audit(
                kinds::USE,
                json!({ "host": "api.stripe.com", "path": format!("/v1/x/{i}"), "status": 200 }),
            )
            .unwrap();
        }
        assert_eq!(
            v.audit(kinds::REVEAL, json!({ "secret": "stripe-live" }))
                .unwrap(),
            7
        );
        assert_eq!(v.audit_count().unwrap(), 7);
        let uses = v.audit_events(1, Some(kinds::USE), 100).unwrap();
        assert_eq!(uses.len(), 5);
        assert_eq!(uses[2].body["path"], "/v1/x/2");
        let page = v.audit_events(3, None, 2).unwrap();
        assert_eq!(page.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3, 4]);
        assert!(v.audit_verify().unwrap().ok());
    }
    // Verification works on a locked vault.
    let v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(2)).unwrap();
    assert!(v.is_locked());
    let report = v.audit_verify().unwrap();
    assert!(report.ok());
    assert_eq!(report.rows, 7);
    drop(v);

    // Tamper with row 4's kind directly in SQLite: the chain breaks at 4.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE audit SET kind = 'lock' WHERE seq = 4", [])
            .unwrap();
    }
    let v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(3)).unwrap();
    let report = v.audit_verify().unwrap();
    assert_eq!(report.first_broken, Some(4));
    drop(v);

    // Deleting a row breaks contiguity.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE audit SET kind = 'use' WHERE seq = 4", [])
            .unwrap();
        conn.execute("DELETE FROM audit WHERE seq = 2", []).unwrap();
    }
    let v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(4)).unwrap();
    let report = v.audit_verify().unwrap();
    assert!(!report.contiguous);
    assert_eq!(report.first_broken, Some(3));

    // Audit bodies are ciphertext at rest.
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(14).any(|w| w == b"api.stripe.com"));
}

#[test]
fn keyed_head_catches_truncation_and_tolerates_old_logs() {
    use unseenkey_core::audit::HeadStatus;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (mut v, _) = Vault::create(
        SqliteStorage::open(&path).unwrap(),
        FixedClock(1),
        &SecretBytes::from(PW),
        FAST,
    )
    .unwrap();
    for i in 0..7 {
        v.audit(kinds::USE, json!({ "i": i })).unwrap();
    }
    let report = v.audit_verify().unwrap();
    assert!(report.ok() && report.head_checked());
    assert_eq!(report.head, HeadStatus::Verified);
    drop(v);

    // Locked: the chain is checked, the head cannot be.
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(2)).unwrap();
    let report = v.audit_verify().unwrap();
    assert!(report.ok() && !report.head_checked());
    assert_eq!(report.head, HeadStatus::Unchecked);
    v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
    assert_eq!(v.audit_head_problem(), None);
    assert_eq!(v.audit_verify().unwrap().head, HeadStatus::Verified);

    // The log is cut short underneath an unlocked vault: the chain is still
    // perfectly consistent, the head is not.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit WHERE seq > 4", []).unwrap();
    }
    let report = v.audit_verify().unwrap();
    assert_eq!(report.first_broken, None);
    assert!(report.contiguous);
    assert_eq!(
        report.head,
        HeadStatus::Mismatch {
            head_seq: 7,
            last_seq: 4
        }
    );
    assert!(!report.ok());
    // The owner's next event replaces the head, so from here the log is
    // consistent again (and shorter). That is why unlock records the finding.
    v.audit(kinds::LOCK, json!({})).unwrap();
    assert_eq!(v.audit_verify().unwrap().head, HeadStatus::Verified);
    drop(v);

    // Cut while locked: unlock notices before its first append and writes an
    // `audit_tampered` event that survives the head being replaced.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit WHERE seq > 2", []).unwrap();
    }
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(3)).unwrap();
    v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
    assert_eq!(
        v.audit_head_problem(),
        Some(HeadStatus::Mismatch {
            head_seq: 5,
            last_seq: 2
        })
    );
    let events = v.audit_events(1, Some(kinds::AUDIT_TAMPERED), 10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].seq, 3);
    assert_eq!(events[0].body["state"], "mismatch");
    assert_eq!(events[0].body["head_seq"], 5);
    assert_eq!(events[0].body["last_seq"], 2);
    assert_eq!(v.audit_verify().unwrap().head, HeadStatus::Verified);
    drop(v);

    // A head rewritten without the key is forged.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE audit_head SET mac = zeroblob(32)", [])
            .unwrap();
    }
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(4)).unwrap();
    v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
    assert_eq!(v.audit_head_problem(), Some(HeadStatus::Forged));
    assert_eq!(
        v.audit_events(1, Some(kinds::AUDIT_TAMPERED), 10)
            .unwrap()
            .len(),
        2
    );
    drop(v);

    // A log from before keyed heads has none: reported, not failed, and the
    // next event gives it one.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit_head", []).unwrap();
    }
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(5)).unwrap();
    v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
    assert_eq!(v.audit_head_problem(), None);
    let report = v.audit_verify().unwrap();
    assert!(report.ok() && !report.head_checked());
    assert_eq!(report.head, HeadStatus::Missing);
    v.audit(kinds::LOCK, json!({})).unwrap();
    assert_eq!(v.audit_verify().unwrap().head, HeadStatus::Verified);
}

#[test]
fn use_counts_survive_a_crash_through_the_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let hid;
    let other = unseenkey_core::ids::Id::new_v7(99).to_hex();
    {
        let (mut v, _) = Vault::create(
            SqliteStorage::open(&path).unwrap(),
            FixedClock(1_000),
            &SecretBytes::from(PW),
            FAST,
        )
        .unwrap();
        let sid = v.add(stripe()).unwrap();
        let (rec, _) = v
            .create_handle(&sid, "cursor", Policy::allow_all(), None)
            .unwrap();
        hid = rec.handle_id;
        // Seven brokered requests, as the daemon records them: counter in
        // memory, `use` event in the log. Two events for some other handle
        // are noise that must not be counted.
        for i in 0..7 {
            v.touch_handle(&hid, 1_000 + i).unwrap();
            v.audit(
                kinds::USE,
                json!({ "handle": hid.to_hex(), "path": "/v1/x" }),
            )
            .unwrap();
            if i < 2 {
                v.audit(kinds::USE, json!({ "handle": other, "path": "/v1/y" }))
                    .unwrap();
            }
        }
        assert_eq!(v.handle(&hid).unwrap().use_count, 7);
        // The daemon dies here: no lock(), nothing flushed.
    }
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(5_000)).unwrap();
    v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
    let h = v.handle(&hid).unwrap();
    assert_eq!(h.use_count, 7, "uses come back from the log");
    assert_eq!(
        h.last_used_at,
        Some(1_000),
        "the events' timestamps, not the touches'"
    );

    // Two more, then a clean lock persists 9 with the log position; a later
    // unlock has nothing to add.
    for _ in 0..2 {
        v.touch_handle(&hid, 5_000).unwrap();
        v.audit(
            kinds::USE,
            json!({ "handle": hid.to_hex(), "path": "/v1/x" }),
        )
        .unwrap();
    }
    // Sliding-window input: everything, then only the second session.
    let all = v.recent_uses(0).unwrap();
    assert_eq!(all.len(), 9);
    assert!(all.iter().all(|(id, _)| *id == hid));
    assert_eq!(all.iter().filter(|(_, ts)| *ts == 5_000).count(), 2);
    let recent = v.recent_uses(2_000).unwrap();
    assert_eq!(recent, vec![(hid, 5_000), (hid, 5_000)]);
    assert!(v.recent_uses(6_000).unwrap().is_empty());
    v.lock();
    drop(v);

    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(9_000)).unwrap();
    v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
    assert_eq!(
        v.handle(&hid).unwrap().use_count,
        9,
        "no double counting after a flush"
    );
    // Revoking (any write) also pins the count to the log position.
    v.touch_handle(&hid, 9_000).unwrap();
    v.audit(kinds::USE, json!({ "handle": hid.to_hex() }))
        .unwrap();
    v.revoke_handle(&hid).unwrap();
    drop(v);
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(9_500)).unwrap();
    v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
    assert_eq!(v.handle(&hid).unwrap().use_count, 10);
}

#[test]
fn remembered_rules_persist_and_reset_on_policy_change() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let hid;
    {
        let (mut v, _) = Vault::create(
            SqliteStorage::open(&path).unwrap(),
            FixedClock(1_000),
            &SecretBytes::from(PW),
            FAST,
        )
        .unwrap();
        let sid = v.add(stripe()).unwrap();
        let (rec, _) = v
            .create_handle(
                &sid,
                "agent",
                presets::policy_ref("stripe:payments").unwrap(),
                None,
            )
            .unwrap();
        hid = rec.handle_id;
        assert!(rec.remembered.is_empty());
        v.remember_rule(&hid, "POST /v1/customers").unwrap();
        v.remember_rule(&hid, " POST /v1/customers ").unwrap(); // duplicate, trimmed
        v.remember_rule(&hid, "POST /v1/refunds").unwrap();
        assert_eq!(
            v.handle(&hid).unwrap().remembered,
            ["POST /v1/customers", "POST /v1/refunds"]
        );
        assert!(matches!(
            v.remember_rule(&hid, "   "),
            Err(VaultError::InvalidPolicy(_))
        ));
        assert!(matches!(
            v.remember_rule(&unseenkey_core::ids::Id::new_v7(9), "GET /x"),
            Err(VaultError::HandleNotFound)
        ));
    }
    // Survives reopening, like everything else in the record.
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(2_000)).unwrap();
    v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
    assert_eq!(v.handle(&hid).unwrap().remembered.len(), 2);
    // Forget one, then the rest.
    assert_eq!(v.forget_rules(&hid, Some("POST /v1/refunds")).unwrap(), 1);
    assert_eq!(v.forget_rules(&hid, Some("POST /v1/refunds")).unwrap(), 0);
    assert_eq!(v.handle(&hid).unwrap().remembered, ["POST /v1/customers"]);
    v.remember_rule(&hid, "DELETE /v1/customers/*").unwrap();
    assert_eq!(v.forget_rules(&hid, None).unwrap(), 2);
    assert!(v.handle(&hid).unwrap().remembered.is_empty());
    // A policy change wipes standing approvals.
    v.remember_rule(&hid, "POST /v1/customers").unwrap();
    v.set_handle_policy(&hid, presets::policy_ref("stripe:read-only").unwrap())
        .unwrap();
    assert!(v.handle(&hid).unwrap().remembered.is_empty());
    // Locked vault: refused.
    v.lock();
    assert!(matches!(
        v.remember_rule(&hid, "GET /v1/balance"),
        Err(VaultError::Locked)
    ));
}

#[test]
fn deleting_a_secret_revokes_its_handles() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (mut v, _) = Vault::create(
        SqliteStorage::open(&path).unwrap(),
        FixedClock(1_000),
        &SecretBytes::from(PW),
        FAST,
    )
    .unwrap();
    let sid = v.add(stripe()).unwrap();
    let (active, plain) = v
        .create_handle(
            &sid,
            "cursor",
            presets::policy_ref("stripe:payments").unwrap(),
            None,
        )
        .unwrap();
    let (already, _) = v
        .create_handle(&sid, "old", Policy::allow_all(), None)
        .unwrap();
    v.revoke_handle(&already.handle_id).unwrap();
    let mut other = stripe();
    other.name = "stripe-test".into();
    other.value = SecretBytes::from("sk_test_51Hzyxwvutsrqponmlk");
    let oid = v.add(other).unwrap();
    let (keep, _) = v
        .create_handle(&oid, "keep", Policy::allow_all(), None)
        .unwrap();

    // Only the deleted secret's active handles go, and the caller learns which.
    assert_eq!(v.delete(&sid).unwrap(), vec![active.handle_id]);
    assert!(matches!(v.get(&sid), Err(VaultError::NotFound)));
    let h = v.handle(&active.handle_id).unwrap();
    assert_eq!(h.revoked_at, Some(1_000));
    assert!(!h.is_active(1_001));
    assert_eq!(
        v.handle(&already.handle_id).unwrap().revoked_at,
        Some(1_000)
    );
    assert!(v.handle(&keep.handle_id).unwrap().is_active(1_001));
    // The string still resolves, so the audit log can name it, but it is dead.
    assert!(!v
        .handle_by_string(&plain)
        .unwrap()
        .unwrap()
        .is_active(1_001));
    assert!(matches!(v.delete(&sid), Err(VaultError::NotFound)));

    // Survives a reopen.
    v.lock();
    drop(v);
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(3_000)).unwrap();
    v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
    assert_eq!(v.handle(&active.handle_id).unwrap().revoked_at, Some(1_000));
    assert!(v.handle(&keep.handle_id).unwrap().is_active(3_001));
}
