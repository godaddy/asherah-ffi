#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for InMemoryStore: Loader, Storer, LoaderCtx, StorerCtx.

use asherah::store::InMemoryStore;
use asherah::traits::{Loader, LoaderCtx, Storer, StorerCtx};
use asherah::types::{DataRowRecord, EnvelopeKeyRecord, KeyMeta};

fn make_drr(data: &[u8], created: i64) -> DataRowRecord {
    DataRowRecord {
        key: Some(EnvelopeKeyRecord {
            id: String::new(),
            created,
            encrypted_key: vec![0xAA],
            revoked: None,
            parent_key_meta: Some(KeyMeta {
                id: "ik".into(),
                created: 0,
            }),
        }),
        data: data.to_vec(),
    }
}

// ──────────────────────────── Basic store and load ────────────────────────────

#[test]
fn store_and_load_roundtrip() {
    let store = InMemoryStore::new();
    let drr = make_drr(b"hello", 100);
    let key = store.store(&drr).unwrap();
    let loaded = store.load(&key).unwrap().unwrap();
    assert_eq!(loaded.data, b"hello");
}

#[test]
fn load_nonexistent_key_returns_none() {
    let store = InMemoryStore::new();
    let key = serde_json::json!({"Created": 999, "Len": 42});
    assert!(store.load(&key).unwrap().is_none());
}

#[test]
fn store_multiple_items() {
    let store = InMemoryStore::new();
    let drr1 = make_drr(b"first", 1);
    let drr2 = make_drr(b"second", 2);
    let key1 = store.store(&drr1).unwrap();
    let key2 = store.store(&drr2).unwrap();
    assert_ne!(key1, key2, "different DRRs should produce different keys");
    assert_eq!(store.load(&key1).unwrap().unwrap().data, b"first");
    assert_eq!(store.load(&key2).unwrap().unwrap().data, b"second");
}

#[test]
fn store_overwrites_same_key() {
    let store = InMemoryStore::new();
    // Two DRRs with same created and same data length produce same key
    let drr1 = make_drr(b"aaaa", 100);
    let drr2 = make_drr(b"bbbb", 100);
    let key1 = store.store(&drr1).unwrap();
    let key2 = store.store(&drr2).unwrap();
    assert_eq!(key1, key2, "same created + same len = same key");
    // Latest stored wins
    let loaded = store.load(&key1).unwrap().unwrap();
    assert_eq!(loaded.data, b"bbbb");
}

// ──────────────────────────── Default trait ────────────────────────────

#[test]
fn default_store() {
    let store = InMemoryStore::default();
    assert!(store.load(&serde_json::json!({})).unwrap().is_none());
}

// ──────────────────────────── Ctx variants ────────────────────────────

#[test]
fn store_ctx_and_load_ctx_roundtrip() {
    let store = InMemoryStore::new();
    let drr = make_drr(b"ctx data", 200);
    let key = store.store_ctx(&(), &drr).unwrap();
    let loaded = store.load_ctx(&(), &key).unwrap().unwrap();
    assert_eq!(loaded.data, b"ctx data");
}

// ──────────────────────────── Key structure ────────────────────────────

#[test]
fn store_key_contains_created_and_len() {
    let store = InMemoryStore::new();
    let drr = make_drr(b"test", 42);
    let key = store.store(&drr).unwrap();
    assert_eq!(key["Created"], 42);
    assert_eq!(key["Len"], 4);
}

// ──────────────────────────── Empty data ────────────────────────────

#[test]
fn store_empty_data() {
    let store = InMemoryStore::new();
    let drr = make_drr(b"", 1);
    let key = store.store(&drr).unwrap();
    let loaded = store.load(&key).unwrap().unwrap();
    assert!(loaded.data.is_empty());
}

// ──────────────────────────── No key in DRR ────────────────────────────

#[test]
fn store_drr_without_key() {
    let store = InMemoryStore::new();
    let drr = DataRowRecord {
        key: None,
        data: vec![1, 2, 3],
    };
    let key = store.store(&drr).unwrap();
    assert_eq!(key["Created"], serde_json::Value::Null);
    assert_eq!(key["Len"], 3);
}
