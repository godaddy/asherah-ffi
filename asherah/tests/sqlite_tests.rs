#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for SqliteMetastore: contract tests, full-stack encrypt/decrypt, SQLite-specific.

use asherah::metastore_sqlite::SqliteMetastore;
use asherah::traits::Metastore;
use asherah::types::{EnvelopeKeyRecord, KeyMeta};
use std::sync::Arc;

fn make_ekr(created: i64) -> EnvelopeKeyRecord {
    EnvelopeKeyRecord {
        id: String::new(),
        created,
        encrypted_key: vec![1, 2, 3],
        revoked: None,
        parent_key_meta: Some(KeyMeta {
            id: "parent".into(),
            created: 0,
        }),
    }
}

// ──────────────────────────── Contract Tests ────────────────────────────

#[test]
fn store_first_insert_returns_true() {
    let ms = SqliteMetastore::open(":memory:").unwrap();
    let ekr = make_ekr(100);
    assert!(ms.store("sk1", 100, &ekr).unwrap());
}

#[test]
fn store_duplicate_returns_false() {
    let ms = SqliteMetastore::open(":memory:").unwrap();
    let ekr = make_ekr(100);
    assert!(ms.store("sk1", 100, &ekr).unwrap());
    assert!(!ms.store("sk1", 100, &ekr).unwrap());
}

#[test]
fn load_exact_match() {
    let ms = SqliteMetastore::open(":memory:").unwrap();
    let ekr = make_ekr(100);
    ms.store("sk1", 100, &ekr).unwrap();
    let loaded = ms.load("sk1", 100).unwrap().unwrap();
    assert_eq!(loaded.created, 100);
    assert_eq!(loaded.encrypted_key, vec![1, 2, 3]);
}

#[test]
fn load_nonexistent_returns_none() {
    let ms = SqliteMetastore::open(":memory:").unwrap();
    assert!(ms.load("nonexistent", 999).unwrap().is_none());
}

#[test]
fn load_latest_returns_highest_created() {
    let ms = SqliteMetastore::open(":memory:").unwrap();
    ms.store("sk1", 100, &make_ekr(100)).unwrap();
    ms.store("sk1", 300, &make_ekr(300)).unwrap();
    ms.store("sk1", 200, &make_ekr(200)).unwrap();
    let latest = ms.load_latest("sk1").unwrap().unwrap();
    assert_eq!(latest.created, 300);
}

#[test]
fn load_latest_single_entry() {
    let ms = SqliteMetastore::open(":memory:").unwrap();
    ms.store("sk1", 42, &make_ekr(42)).unwrap();
    let latest = ms.load_latest("sk1").unwrap().unwrap();
    assert_eq!(latest.created, 42);
}

#[test]
fn load_latest_nonexistent_returns_none() {
    let ms = SqliteMetastore::open(":memory:").unwrap();
    assert!(ms.load_latest("nonexistent").unwrap().is_none());
}

#[test]
fn region_suffix_returns_none() {
    let ms = SqliteMetastore::open(":memory:").unwrap();
    assert!(ms.region_suffix().is_none());
}

#[test]
fn store_multiple_ids() {
    let ms = SqliteMetastore::open(":memory:").unwrap();
    ms.store("id_a", 100, &make_ekr(100)).unwrap();
    ms.store("id_b", 200, &make_ekr(200)).unwrap();
    ms.store("id_c", 300, &make_ekr(300)).unwrap();

    assert!(ms.load("id_a", 100).unwrap().is_some());
    assert!(ms.load("id_b", 200).unwrap().is_some());
    assert!(ms.load("id_c", 300).unwrap().is_some());

    // Cross-check: wrong id returns none
    assert!(ms.load("id_a", 200).unwrap().is_none());
    assert!(ms.load("id_b", 100).unwrap().is_none());
}

// ──────────────────────────── Full-Stack Tests ────────────────────────────

fn make_factory() -> asherah::session::PublicFactory<
    asherah::aead::AES256GCM,
    asherah::kms::StaticKMS<asherah::aead::AES256GCM>,
    SqliteMetastore,
> {
    let store = Arc::new(SqliteMetastore::open(":memory:").unwrap());
    let crypto = Arc::new(asherah::aead::AES256GCM::new());
    let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![1_u8; 32]).unwrap());
    let cfg = asherah::Config::new("svc", "prod");
    asherah::api::new_session_factory(cfg, store, kms, crypto)
}

#[test]
fn sqlite_full_stack_roundtrip() {
    let factory = make_factory();
    let session = factory.get_session("partition-1");

    let drr = session.encrypt(b"hello sqlite").unwrap();
    let out = session.decrypt(drr).unwrap();
    assert_eq!(out, b"hello sqlite");
}

#[test]
fn sqlite_cross_partition_isolation() {
    let factory = make_factory();
    let s1 = factory.get_session("partition-a");
    let s2 = factory.get_session("partition-b");

    let drr = s1.encrypt(b"secret-a").unwrap();

    // partition-b should not be able to decrypt partition-a's data
    let result = s2.decrypt(drr);
    assert!(result.is_err());
}

#[test]
fn sqlite_key_rotation() {
    use asherah::policy::PolicyOption;

    let store = Arc::new(SqliteMetastore::open(":memory:").unwrap());
    let crypto = Arc::new(asherah::aead::AES256GCM::new());
    let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![1_u8; 32]).unwrap());
    let cfg = asherah::Config::new("svc", "prod").with_policy_options(&[
        PolicyOption::ExpireAfterSecs(1),
        PolicyOption::NoCache,
        PolicyOption::CreateDatePrecisionSecs(1),
    ]);
    let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);

    let session = factory.get_session("rot-part");
    let drr1 = session.encrypt(b"before rotation").unwrap();
    let ik_created_1 = drr1
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;

    // Sleep long enough for the key to expire
    std::thread::sleep(std::time::Duration::from_secs(2));

    let session2 = factory.get_session("rot-part");
    let drr2 = session2.encrypt(b"after rotation").unwrap();
    let ik_created_2 = drr2
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;

    // After expiry, a new IK should have been created with a different timestamp
    assert_ne!(ik_created_1, ik_created_2);

    // Both should still decrypt correctly
    let session3 = factory.get_session("rot-part");
    let out1 = session3.decrypt(drr1).unwrap();
    assert_eq!(out1, b"before rotation");

    let session4 = factory.get_session("rot-part");
    let out2 = session4.decrypt(drr2).unwrap();
    assert_eq!(out2, b"after rotation");
}

// ──────────────────────────── SQLite-Specific Tests ────────────────────────────

#[test]
fn sqlite_concurrent_access() {
    let factory = Arc::new(make_factory());
    let mut handles = vec![];

    for i in 0..8 {
        let factory = factory.clone();
        handles.push(std::thread::spawn(move || {
            let partition = format!("thread-{i}");
            let session = factory.get_session(&partition);
            let plaintext = format!("data from thread {i}");
            let drr = session.encrypt(plaintext.as_bytes()).unwrap();
            let out = session.decrypt(drr).unwrap();
            assert_eq!(out, plaintext.as_bytes());
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn sqlite_file_based() {
    let dir = std::env::temp_dir();
    let db_path = dir.join(format!("asherah_test_{}.db", std::process::id()));
    let db_path_str = db_path.to_str().unwrap();

    let store = Arc::new(SqliteMetastore::open(db_path_str).unwrap());
    let crypto = Arc::new(asherah::aead::AES256GCM::new());
    let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![1_u8; 32]).unwrap());
    let cfg = asherah::Config::new("svc", "prod");
    let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);

    let session = factory.get_session("file-partition");
    let drr = session.encrypt(b"file-based test").unwrap();
    let out = session.decrypt(drr).unwrap();
    assert_eq!(out, b"file-based test");

    // Verify the file was actually created
    assert!(db_path.exists());

    // Clean up
    drop(std::fs::remove_file(&db_path));
}
