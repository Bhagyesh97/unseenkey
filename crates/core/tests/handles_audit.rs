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
