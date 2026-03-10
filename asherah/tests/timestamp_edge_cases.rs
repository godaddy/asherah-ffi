#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ael::types::EnvelopeKeyRecord;
use asherah as ael;

// ── InMemoryMetastore timestamp edge cases ──

#[test]
fn metastore_negative_created() {
    let store = ael::metastore::InMemoryMetastore::new();
    let ekr = EnvelopeKeyRecord {
        revoked: None,
        id: "neg-key".into(),
        created: -1,
        encrypted_key: vec![10, 20, 30],
        parent_key_meta: None,
    };
    let stored = ael::Metastore::store(&store, "neg-key", -1, &ekr).unwrap();
    assert!(stored);
    let loaded = ael::Metastore::load(&store, "neg-key", -1).unwrap();
    assert!(loaded.is_some());
    let loaded = loaded.unwrap();
    assert_eq!(loaded.created, -1);
    assert_eq!(loaded.encrypted_key, vec![10, 20, 30]);
}

#[test]
fn metastore_zero_created() {
    let store = ael::metastore::InMemoryMetastore::new();
    let ekr = EnvelopeKeyRecord {
        revoked: None,
        id: "zero-key".into(),
        created: 0,
        encrypted_key: vec![1, 2, 3],
        parent_key_meta: None,
    };
    let stored = ael::Metastore::store(&store, "zero-key", 0, &ekr).unwrap();
    assert!(stored);
    let loaded = ael::Metastore::load(&store, "zero-key", 0).unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().created, 0);
}

#[test]
fn metastore_max_i64_created() {
    let store = ael::metastore::InMemoryMetastore::new();
    let ekr = EnvelopeKeyRecord {
        revoked: None,
        id: "max-key".into(),
        created: i64::MAX,
        encrypted_key: vec![4, 5, 6],
        parent_key_meta: None,
    };
    let stored = ael::Metastore::store(&store, "max-key", i64::MAX, &ekr).unwrap();
    assert!(stored);
    let loaded = ael::Metastore::load(&store, "max-key", i64::MAX).unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().created, i64::MAX);
}

#[test]
fn metastore_min_i64_created() {
    let store = ael::metastore::InMemoryMetastore::new();
    let ekr = EnvelopeKeyRecord {
        revoked: None,
        id: "min-key".into(),
        created: i64::MIN,
        encrypted_key: vec![7, 8, 9],
        parent_key_meta: None,
    };
    let stored = ael::Metastore::store(&store, "min-key", i64::MIN, &ekr).unwrap();
    assert!(stored);
    let loaded = ael::Metastore::load(&store, "min-key", i64::MIN).unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().created, i64::MIN);
}

#[test]
fn metastore_load_latest_with_negative_and_positive() {
    let store = ael::metastore::InMemoryMetastore::new();
    let ekr_neg = EnvelopeKeyRecord {
        revoked: None,
        id: "dual-key".into(),
        created: -100,
        encrypted_key: vec![1],
        parent_key_meta: None,
    };
    let ekr_pos = EnvelopeKeyRecord {
        revoked: None,
        id: "dual-key".into(),
        created: 100,
        encrypted_key: vec![2],
        parent_key_meta: None,
    };
    ael::Metastore::store(&store, "dual-key", -100, &ekr_neg).unwrap();
    ael::Metastore::store(&store, "dual-key", 100, &ekr_pos).unwrap();

    let latest = ael::Metastore::load_latest(&store, "dual-key").unwrap();
    assert!(latest.is_some());
    let latest = latest.unwrap();
    assert_eq!(latest.created, 100);
    assert_eq!(latest.encrypted_key, vec![2]);
}

// ── Policy edge cases with session encrypt/decrypt ──

fn make_factory_with_policy(
    expire_s: i64,
    precision_s: i64,
) -> ael::SessionFactory<
    ael::aead::AES256GCM,
    ael::kms::StaticKMS<ael::aead::AES256GCM>,
    ael::metastore::InMemoryMetastore,
> {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![3_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let mut cfg = ael::Config::new("ts-svc", "ts-prod");
    cfg.policy.expire_key_after_s = expire_s;
    cfg.policy.create_date_precision_s = precision_s;
    ael::api::new_session_factory(cfg, store, kms, crypto)
}

#[test]
fn policy_zero_expire_still_works() {
    // expire_key_after_s=0 means key is immediately expired, but
    // the encrypt path creates a new key each time so it still works.
    let factory = make_factory_with_policy(0, 60);
    let s = factory.get_session("p-zero-expire");
    let drr = s.encrypt(b"zero-expire").unwrap();
    let pt = s.decrypt(drr).unwrap();
    assert_eq!(pt, b"zero-expire");
}

#[test]
fn policy_negative_expire() {
    // expire_key_after_s=-1: keys are always expired (now - created >= -1 is always true for positive created),
    // so the encrypt path will create a new key every time; decrypt still works.
    let factory = make_factory_with_policy(-1, 60);
    let s = factory.get_session("p-neg-expire");
    let drr = s.encrypt(b"neg-expire").unwrap();
    let pt = s.decrypt(drr).unwrap();
    assert_eq!(pt, b"neg-expire");
}

#[test]
fn encrypt_decrypt_with_zero_precision() {
    // create_date_precision_s=0: the new_key_timestamp() returns now_s() directly
    let factory = make_factory_with_policy(86400, 0);
    let s = factory.get_session("p-zero-prec");
    let drr = s.encrypt(b"zero-precision").unwrap();
    let pt = s.decrypt(drr).unwrap();
    assert_eq!(pt, b"zero-precision");
}
