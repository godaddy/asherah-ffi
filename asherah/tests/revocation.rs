#![allow(clippy::unwrap_used, clippy::expect_used)]
use asherah as ael;
use std::sync::Arc;

#[test]
fn revoked_intermediate_key_triggers_rotation() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![8_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let mut cfg = ael::Config::new("svc", "prod");
    cfg.policy.revoke_check_interval_s = 1; // ensure cache re-evaluates
    cfg.policy.create_date_precision_s = 1;
    let factory = ael::api::new_session_factory(cfg, store.clone(), kms, crypto);
    let sess = factory.get_session("p1");
    // First encrypt to create IK
    let d1 = sess.encrypt(b"one").unwrap();
    let ik_id = d1
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .id
        .clone();
    let ik_created = d1
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;
    // Mark revoked in metastore
    store.mark_revoked(&ik_id, ik_created);
    // Wait past cache TTL so IK cache re-evaluates and does not serve revoked IK
    std::thread::sleep(std::time::Duration::from_millis(1100));
    // Next encrypt should load/create a non-revoked IK
    let d2 = sess.encrypt(b"two").unwrap();
    let ik2 = d2.key.unwrap().parent_key_meta.unwrap().created;
    assert!(ik2 >= ik_created);
    assert!(ik2 > ik_created, "expected new IK after revocation");
}

/// Encrypt data, revoke the IK in the metastore, verify old data can
/// still be decrypted. The key material is still present in the store;
/// revocation only prevents the key from being used for *new* encryptions.
#[test]
fn revoked_key_still_decrypts_old_data() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![9_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let mut cfg = ael::Config::new("svc-dec", "prod-dec");
    cfg.policy.revoke_check_interval_s = 1;
    cfg.policy.create_date_precision_s = 1;
    let factory = ael::api::new_session_factory(cfg, store.clone(), kms, crypto);
    let sess = factory.get_session("p-dec");

    // Encrypt
    let drr = sess.encrypt(b"old secret").unwrap();
    let ik_id = drr
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .id
        .clone();
    let ik_created = drr
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;

    // Revoke the IK
    store.mark_revoked(&ik_id, ik_created);
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // Decryption of old DRR should still work — the decrypt path loads
    // the key by its specific (id, created) rather than asking for "latest".
    let plaintext = sess.decrypt(drr).unwrap();
    assert_eq!(plaintext, b"old secret");
}

/// Encrypt, revoke IK, sleep, encrypt (new IK), revoke that too, sleep,
/// encrypt a third time. All three DRRs should decrypt correctly.
#[test]
fn multiple_revocations_cascade() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![10_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let mut cfg = ael::Config::new("svc-casc", "prod-casc");
    cfg.policy.revoke_check_interval_s = 1;
    cfg.policy.create_date_precision_s = 1;
    let factory = ael::api::new_session_factory(cfg, store.clone(), kms, crypto);
    let sess = factory.get_session("p-casc");

    // --- round 1 ---
    let drr1 = sess.encrypt(b"round-1").unwrap();
    let ik1_id = drr1
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .id
        .clone();
    let ik1_created = drr1
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;

    // Revoke first IK and wait for cache expiry
    store.mark_revoked(&ik1_id, ik1_created);
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // --- round 2 ---
    let drr2 = sess.encrypt(b"round-2").unwrap();
    let ik2_id = drr2
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .id
        .clone();
    let ik2_created = drr2
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;
    assert!(
        ik2_created > ik1_created,
        "second IK should be newer than revoked first IK"
    );

    // Revoke second IK and wait for cache expiry
    store.mark_revoked(&ik2_id, ik2_created);
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // --- round 3 ---
    let drr3 = sess.encrypt(b"round-3").unwrap();
    let ik3_created = drr3
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;
    assert!(
        ik3_created > ik2_created,
        "third IK should be newer than revoked second IK"
    );

    // All three DRRs should still decrypt successfully
    assert_eq!(sess.decrypt(drr1).unwrap(), b"round-1");
    assert_eq!(sess.decrypt(drr2).unwrap(), b"round-2");
    assert_eq!(sess.decrypt(drr3).unwrap(), b"round-3");
}

/// With session caching enabled, encrypt, revoke IK, sleep past
/// revoke_check_interval, encrypt again from the same cached session,
/// and verify that a new IK is used despite the cached session.
#[test]
fn revocation_with_session_caching() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![11_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let mut cfg = ael::Config::new("svc-sc", "prod-sc");
    cfg.policy.revoke_check_interval_s = 1;
    cfg.policy.create_date_precision_s = 1;
    cfg.policy.cache_sessions = true;
    cfg.policy.session_cache_max_size = 100;
    cfg.policy.session_cache_ttl_s = 300;
    let factory = ael::api::new_session_factory(cfg, store.clone(), kms, crypto);

    // Get a session (will be cached)
    let sess = factory.get_session("p-sc");
    let drr1 = sess.encrypt(b"cached-1").unwrap();
    let ik1_created = drr1
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;
    let ik1_id = drr1
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .id
        .clone();

    // Revoke
    store.mark_revoked(&ik1_id, ik1_created);
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // Get session again from the same factory (should be cached)
    let sess2 = factory.get_session("p-sc");
    let drr2 = sess2.encrypt(b"cached-2").unwrap();
    let ik2_created = drr2
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;
    assert!(
        ik2_created > ik1_created,
        "new IK should be created even with session caching"
    );

    // Both DRRs should still decrypt
    assert_eq!(sess2.decrypt(drr1).unwrap(), b"cached-1");
    assert_eq!(sess2.decrypt(drr2).unwrap(), b"cached-2");

    factory.close().unwrap();
}
