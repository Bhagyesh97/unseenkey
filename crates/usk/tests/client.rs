//! The CLI and the app find the daemon through `daemon.addr` and
//! `daemon.token`. Right after a spawn the address can answer before the new
//! token is on disk; a client must not go ahead with the old token.

use unseenkey_core::crypto::kdf::Argon2Profile;
use unseenkey_core::crypto::SecretBytes;
use unseenkey_core::storage::sqlite::SqliteStorage;
use unseenkey_core::time::SystemClock;
use unseenkey_core::vault::Vault;
use unseenkey_daemon::{serve, ServeOptions, VaultPaths};

#[tokio::test(flavor = "multi_thread")]
async fn a_live_daemon_with_a_stale_token_file_is_not_ready() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault.db");
    drop(
        Vault::create(
            SqliteStorage::open(&vault).unwrap(),
            SystemClock,
            &SecretBytes::from("client-test-password"),
            Argon2Profile::MINIMUM,
        )
        .unwrap(),
    );
    let r = serve(ServeOptions {
        vault_path: vault.clone(),
        listen: "127.0.0.1:0".into(),
        idle_lock_minutes: 0,
        write_runtime_files: true,
        upstream_overrides: vec![],
        mcp_allow_store: false,
        lock_on_sleep: false,
        lock_on_session_lock: false,
    })
    .await
    .unwrap();
    let paths = VaultPaths::from_vault_file(&vault);
    let check = paths.clone();
    let ok =
        tokio::task::spawn_blocking(move || usk::client::Client::try_connect(&check).is_some())
            .await
            .unwrap();
    assert!(ok, "the real token connects");

    // What a client sees between a new daemon's bind and its token write:
    // the address answers, the file still holds the previous daemon's token.
    std::fs::write(&paths.token, "usk_s_left-behind-by-the-previous-daemon").unwrap();
    let check = paths.clone();
    let ok =
        tokio::task::spawn_blocking(move || usk::client::Client::try_connect(&check).is_some())
            .await
            .unwrap();
    assert!(
        !ok,
        "a stale token must read as not ready, not as a connection"
    );

    std::fs::write(&paths.token, r.token()).unwrap();
    let ok =
        tokio::task::spawn_blocking(move || usk::client::Client::try_connect(&paths).is_some())
            .await
            .unwrap();
    assert!(ok, "once the token is current it connects again");
    r.shutdown().await;
}

/// `daemon.addr` is written by the daemon and only ever names loopback. A
/// tampered file naming another machine must not get the token, the password
/// and the values a command is about to send.
#[test]
fn a_daemon_address_off_this_machine_is_not_a_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::from_vault_file(&dir.path().join("vault.db"));
    std::fs::write(&paths.token, "usk_s_00000000000000000000000000000000").unwrap();
    for addr in [
        "203.0.113.7:80",
        "[2001:db8::1]:7391",
        "example.invalid:7391",
    ] {
        std::fs::write(&paths.addr, addr).unwrap();
        assert!(
            usk::client::Client::try_connect(&paths).is_none(),
            "{addr} must be refused without a single request"
        );
    }
}
