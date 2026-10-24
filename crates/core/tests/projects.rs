//! Projects in the vault: folders, membership, persistence and cleanup.

use std::collections::BTreeMap;
use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::policy::Policy;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::FixedClock;
use unseenkey_core::vault::{
    HandleOptions, NewSecret, ProjectChanges, SecretKind, Vault, VaultError,
};

const PW: &str = "projects-password";

fn secret(name: &str, value: &str) -> NewSecret {
    NewSecret {
        name: name.into(),
        kind: SecretKind::ApiKey,
        value: SecretBytes::from(value),
        fields: BTreeMap::new(),
        provider: Some("stripe".into()),
        upstreams: vec!["api.stripe.com".into()],
        tags: vec![],
        notes: None,
    }
}

#[test]
fn projects_group_secrets_by_folder_and_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let (shop_id, a, b);
    {
        let (mut v, _) = Vault::create(
            SqliteStorage::open(&path).unwrap(),
            FixedClock(1_000),
            &SecretBytes::from(PW),
            Argon2Profile::MINIMUM,
        )
        .unwrap();
        a = v
            .add(secret("stripe-live", "sk_live_51Habcdefghijklmnop"))
            .unwrap();
        b = v
            .add(secret("stripe-test", "sk_test_51Hzyxwvutsrqponmlk"))
            .unwrap();

        let shop = v
            .create_project("Shop", &[r"C:\Work\Shop\".into(), r"c:\work\shop".into()])
            .unwrap();
        assert_eq!(
            shop.paths,
            vec!["c:/work/shop".to_string()],
            "normalised and deduplicated"
        );
        shop_id = shop.project_id;
        let api = v
            .create_project("Shop API", &["C:/Work/Shop/api".into()])
            .unwrap();
        assert!(matches!(
            v.create_project("shop", &[]),
            Err(VaultError::ProjectExists(_))
        ));
        assert!(matches!(
            v.create_project("  ", &[]),
            Err(VaultError::InvalidName)
        ));

        v.attach_secret(&shop_id, &a).unwrap();
        v.attach_secret(&shop_id, &a).unwrap();
        v.attach_secret(&shop_id, &b).unwrap();
        v.attach_secret(&api.project_id, &a).unwrap();
        assert_eq!(
            v.project(&shop_id).unwrap().secrets,
            vec![a, b],
            "no duplicates"
        );
        assert_eq!(
            v.projects_of_secret(&a).unwrap().len(),
            2,
            "one secret, two projects"
        );

        // The deepest folder wins; outside every folder there is no project.
        let at = |d: &str| v.project_for_dir(d).unwrap().map(|p| p.name.clone());
        assert_eq!(at(r"C:\Work\Shop\web").as_deref(), Some("Shop"));
        assert_eq!(at(r"C:\work\shop\API\src").as_deref(), Some("Shop API"));
        assert_eq!(at(r"C:\Work\Shopping"), None);

        let changed = v
            .update_project(
                &shop_id,
                ProjectChanges {
                    cap_per_day: Some(Some(500)),
                    notes: Some("the storefront".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(changed.cap_per_day, Some(500));
        assert!(matches!(
            v.update_project(
                &shop_id,
                ProjectChanges {
                    cap_per_day: Some(Some(0)),
                    ..Default::default()
                }
            ),
            Err(VaultError::InvalidPolicy(_))
        ));
        assert!(matches!(
            v.update_project(
                &api.project_id,
                ProjectChanges {
                    name: Some("SHOP".into()),
                    ..Default::default()
                }
            ),
            Err(VaultError::ProjectExists(_))
        ));
        v.lock();
        assert!(matches!(v.projects(), Err(VaultError::Locked)));
    }
    let mut v = Vault::open(SqliteStorage::open(&path).unwrap(), FixedClock(2_000)).unwrap();
    v.unlock_with_password(&SecretBytes::from(PW)).unwrap();
    let shop = v.project_by_name("SHOP").unwrap();
    assert_eq!(shop.secrets, vec![a, b]);
    assert_eq!(shop.cap_per_day, Some(500));
    assert_eq!(shop.notes.as_deref(), Some("the storefront"));

    // Detach keeps the secret; deleting a secret takes it out of every project.
    v.detach_secret(&shop_id, &b).unwrap();
    assert!(v.get(&b).is_ok());
    v.delete(&a).unwrap();
    assert!(v.projects_of_secret(&a).unwrap().is_empty());
    assert!(v.project(&shop_id).unwrap().secrets.is_empty());

    // The file holds no project name in the clear.
    drop(v);
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.windows(14).any(|w| w == b"the storefront"));
}

#[test]
fn a_projects_handles_must_use_its_secrets_and_outlive_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut v, _) = Vault::create(
        SqliteStorage::open(&dir.path().join("vault.db")).unwrap(),
        FixedClock(1_000),
        &SecretBytes::from(PW),
        Argon2Profile::MINIMUM,
    )
    .unwrap();
    let a = v
        .add(secret("stripe-live", "sk_live_51Habcdefghijklmnop"))
        .unwrap();
    let p = v.create_project("shop", &[]).unwrap();
    let opts = HandleOptions {
        project: Some(p.project_id),
        ..Default::default()
    };
    assert!(matches!(
        v.create_handle_with(&a, "x", Policy::allow_all(), None, None, opts),
        Err(VaultError::SecretNotInProject)
    ));
    v.attach_secret(&p.project_id, &a).unwrap();
    let (h, _) = v
        .create_handle_with(&a, "x", Policy::allow_all(), None, None, opts)
        .unwrap();
    assert_eq!(h.project, Some(p.project_id));

    v.delete_project(&p.project_id).unwrap();
    assert!(matches!(
        v.project(&p.project_id),
        Err(VaultError::ProjectNotFound)
    ));
    assert!(
        v.handle(&h.handle_id).unwrap().is_active(1_001),
        "handles stay"
    );
    assert!(v.get(&a).is_ok(), "secrets stay");
    // The name is free again.
    v.create_project("shop", &[]).unwrap();
}
