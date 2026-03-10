#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for InMemoryMetastore: store, load, load_latest, mark_revoked.

use asherah::metastore::InMemoryMetastore;
use asherah::traits::Metastore;
use asherah::types::{EnvelopeKeyRecord, KeyMeta};

fn make_ekr(id: &str, created: i64) -> EnvelopeKeyRecord {
    EnvelopeKeyRecord {
        id: id.into(),
        created,
        encrypted_key: vec![1, 2, 3],
        revoked: None,
        parent_key_meta: Some(KeyMeta {
            id: format!("parent_{id}"),
            created: created - 10,
        }),
    }
}

// ──────────────────────────── Store and Load ────────────────────────────

#[test]
fn store_and_load_by_id_and_created() {
    let ms = InMemoryMetastore::new();
    let ekr = make_ekr("sk1", 100);
    assert!(ms.store("sk1", 100, &ekr).unwrap());
    let loaded = ms.load("sk1", 100).unwrap().unwrap();
    assert_eq!(loaded.created, 100);
    assert_eq!(loaded.encrypted_key, vec![1, 2, 3]);
}

#[test]
fn load_nonexistent_returns_none() {
    let ms = InMemoryMetastore::new();
    assert!(ms.load("nonexistent", 999).unwrap().is_none());
}

#[test]
fn store_duplicate_returns_false() {
    let ms = InMemoryMetastore::new();
    let ekr = make_ekr("sk1", 100);
    assert!(ms.store("sk1", 100, &ekr).unwrap());
    // Second store with same (id, created) returns false
    assert!(!ms.store("sk1", 100, &ekr).unwrap());
}

#[test]
fn store_same_id_different_created() {
    let ms = InMemoryMetastore::new();
    let ekr1 = make_ekr("sk1", 100);
    let ekr2 = make_ekr("sk1", 200);
    assert!(ms.store("sk1", 100, &ekr1).unwrap());
    assert!(ms.store("sk1", 200, &ekr2).unwrap());
    assert_eq!(ms.load("sk1", 100).unwrap().unwrap().created, 100);
    assert_eq!(ms.load("sk1", 200).unwrap().unwrap().created, 200);
}

// ──────────────────────────── Load Latest ────────────────────────────

#[test]
fn load_latest_returns_highest_created() {
    let ms = InMemoryMetastore::new();
    ms.store("sk1", 100, &make_ekr("sk1", 100)).unwrap();
    ms.store("sk1", 300, &make_ekr("sk1", 300)).unwrap();
    ms.store("sk1", 200, &make_ekr("sk1", 200)).unwrap();
    let latest = ms.load_latest("sk1").unwrap().unwrap();
    assert_eq!(latest.created, 300);
}

#[test]
fn load_latest_nonexistent_returns_none() {
    let ms = InMemoryMetastore::new();
    assert!(ms.load_latest("nonexistent").unwrap().is_none());
}

#[test]
fn load_latest_single_entry() {
    let ms = InMemoryMetastore::new();
    ms.store("sk1", 42, &make_ekr("sk1", 42)).unwrap();
    let latest = ms.load_latest("sk1").unwrap().unwrap();
    assert_eq!(latest.created, 42);
}

// ──────────────────────────── Mark Revoked ────────────────────────────

#[test]
fn mark_revoked_sets_flag() {
    let ms = InMemoryMetastore::new();
    let ekr = make_ekr("sk1", 100);
    ms.store("sk1", 100, &ekr).unwrap();
    assert!(ms.load("sk1", 100).unwrap().unwrap().revoked.is_none());

    ms.mark_revoked("sk1", 100);
    let loaded = ms.load("sk1", 100).unwrap().unwrap();
    assert_eq!(loaded.revoked, Some(true));
}

#[test]
fn mark_revoked_nonexistent_is_noop() {
    let ms = InMemoryMetastore::new();
    // Should not panic
    ms.mark_revoked("nonexistent", 999);
}

#[test]
fn mark_revoked_wrong_created_is_noop() {
    let ms = InMemoryMetastore::new();
    ms.store("sk1", 100, &make_ekr("sk1", 100)).unwrap();
    ms.mark_revoked("sk1", 200); // wrong created
    assert!(ms.load("sk1", 100).unwrap().unwrap().revoked.is_none());
}

// ──────────────────────────── Region Suffix ────────────────────────────

#[test]
fn region_suffix_is_none() {
    let ms = InMemoryMetastore::new();
    assert!(ms.region_suffix().is_none());
}

// ──────────────────────────── Default trait ────────────────────────────

#[test]
fn default_metastore() {
    let ms = InMemoryMetastore::default();
    assert!(ms.load_latest("anything").unwrap().is_none());
}

// ──────────────────────────── Concurrent access ────────────────────────────

#[test]
fn concurrent_store_and_load() {
    use std::sync::Arc;
    use std::thread;

    let ms = Arc::new(InMemoryMetastore::new());
    let mut handles = vec![];

    for i in 0..10 {
        let ms = ms.clone();
        handles.push(thread::spawn(move || {
            let id = format!("key_{i}");
            let ekr = make_ekr(&id, i as i64);
            ms.store(&id, i as i64, &ekr).unwrap();
            let loaded = ms.load(&id, i as i64).unwrap().unwrap();
            assert_eq!(loaded.created, i as i64);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
