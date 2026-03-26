//! Tests that verify the async Metastore trait methods work correctly.
//! Confirms default delegation (sync → async) and that InMemoryMetastore
//! async methods produce identical results to sync methods.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use asherah::metastore::InMemoryMetastore;
use asherah::traits::Metastore;
use asherah::types::{EnvelopeKeyRecord, KeyMeta};

fn make_ekr(id: &str, created: i64) -> EnvelopeKeyRecord {
    EnvelopeKeyRecord {
        id: id.to_string(),
        created,
        encrypted_key: vec![1, 2, 3, 4],
        revoked: None,
        parent_key_meta: Some(KeyMeta {
            id: "parent".to_string(),
            created: 100,
        }),
    }
}

#[tokio::test]
async fn async_store_and_load() {
    let ms = InMemoryMetastore::new();
    let ekr = make_ekr("key-1", 1000);

    // Store via async
    let stored = ms.store_async("key-1", 1000, &ekr).await.unwrap();
    assert!(stored);

    // Load via async
    let loaded = ms.load_async("key-1", 1000).await.unwrap();
    assert!(loaded.is_some());
    let loaded = loaded.unwrap();
    assert_eq!(loaded.id, "key-1");
    assert_eq!(loaded.created, 1000);
    assert_eq!(loaded.encrypted_key, vec![1, 2, 3, 4]);
}

#[tokio::test]
async fn async_store_and_load_latest() {
    let ms = InMemoryMetastore::new();

    let ekr1 = make_ekr("key-2", 1000);
    let ekr2 = make_ekr("key-2", 2000);

    ms.store_async("key-2", 1000, &ekr1).await.unwrap();
    ms.store_async("key-2", 2000, &ekr2).await.unwrap();

    let latest = ms.load_latest_async("key-2").await.unwrap();
    assert!(latest.is_some());
    assert_eq!(latest.unwrap().created, 2000);
}

#[tokio::test]
async fn async_load_nonexistent_returns_none() {
    let ms = InMemoryMetastore::new();

    let loaded = ms.load_async("nonexistent", 999).await.unwrap();
    assert!(loaded.is_none());

    let latest = ms.load_latest_async("nonexistent").await.unwrap();
    assert!(latest.is_none());
}

#[tokio::test]
async fn async_duplicate_store_returns_false() {
    let ms = InMemoryMetastore::new();
    let ekr = make_ekr("dup", 500);

    let first = ms.store_async("dup", 500, &ekr).await.unwrap();
    assert!(first);

    let second = ms.store_async("dup", 500, &ekr).await.unwrap();
    assert!(!second);
}

#[tokio::test]
async fn sync_and_async_interop() {
    let ms = InMemoryMetastore::new();
    let ekr = make_ekr("interop", 777);

    // Store via sync
    let stored = ms.store("interop", 777, &ekr).unwrap();
    assert!(stored);

    // Load via async
    let loaded = ms.load_async("interop", 777).await.unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().created, 777);

    // Store another via async
    let ekr2 = make_ekr("interop", 888);
    ms.store_async("interop", 888, &ekr2).await.unwrap();

    // Load latest via sync
    let latest = ms.load_latest("interop").unwrap();
    assert!(latest.is_some());
    assert_eq!(latest.unwrap().created, 888);
}

#[tokio::test]
async fn async_through_dyn_trait_object() {
    let ms: Arc<dyn Metastore> = Arc::new(InMemoryMetastore::new());
    let ekr = make_ekr("dyn-test", 333);

    let stored = ms.store_async("dyn-test", 333, &ekr).await.unwrap();
    assert!(stored);

    let loaded = ms.load_async("dyn-test", 333).await.unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().created, 333);

    let latest = ms.load_latest_async("dyn-test").await.unwrap();
    assert!(latest.is_some());
}
