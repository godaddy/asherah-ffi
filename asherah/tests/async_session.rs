//! Tests for the async encrypt/decrypt paths on PublicSession.
//! These mirror the sync session_roundtrip and concurrency tests but use
//! encrypt_async/decrypt_async to exercise the async metastore/KMS trait methods.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use asherah as ael;

fn make_factory() -> ael::SessionFactory<
    ael::aead::AES256GCM,
    ael::kms::StaticKMS<ael::aead::AES256GCM>,
    ael::metastore::InMemoryMetastore,
> {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let metastore = Arc::new(ael::metastore::InMemoryMetastore::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![1_u8; 32]).unwrap());
    let cfg = ael::Config::new("svc", "prod");
    ael::api::new_session_factory(cfg, metastore, kms, crypto)
}

#[tokio::test]
async fn async_encrypt_decrypt_roundtrip() {
    let factory = make_factory();
    let session = factory.get_session("partition-async");

    let drr = session.encrypt_async(b"hello async").await.unwrap();
    let out = session.decrypt_async(drr).await.unwrap();
    assert_eq!(out, b"hello async");
}

#[tokio::test]
async fn async_encrypt_sync_decrypt_interop() {
    let factory = make_factory();
    let session = factory.get_session("partition-interop");

    // Encrypt via async, decrypt via sync
    let drr = session.encrypt_async(b"async-to-sync").await.unwrap();
    let out = session.decrypt(drr).unwrap();
    assert_eq!(out, b"async-to-sync");
}

#[tokio::test]
async fn sync_encrypt_async_decrypt_interop() {
    let factory = make_factory();
    let session = factory.get_session("partition-interop2");

    // Encrypt via sync, decrypt via async
    let drr = session.encrypt(b"sync-to-async").unwrap();
    let out = session.decrypt_async(drr).await.unwrap();
    assert_eq!(out, b"sync-to-async");
}

#[tokio::test]
async fn async_multiple_partitions() {
    let factory = make_factory();

    let s1 = factory.get_session("p1");
    let s2 = factory.get_session("p2");

    let drr1 = s1.encrypt_async(b"data-p1").await.unwrap();
    let drr2 = s2.encrypt_async(b"data-p2").await.unwrap();

    let out1 = s1.decrypt_async(drr1).await.unwrap();
    let out2 = s2.decrypt_async(drr2).await.unwrap();

    assert_eq!(out1, b"data-p1");
    assert_eq!(out2, b"data-p2");
}

#[tokio::test]
async fn async_concurrent_encrypt_decrypt() {
    let factory = make_factory();
    let session = Arc::new(factory.get_session("p-async-concurrent"));

    let mut handles = vec![];
    for i in 0..16 {
        let s = session.clone();
        handles.push(tokio::spawn(async move {
            let msg = format!("async-hello-{i}");
            let drr = s.encrypt_async(msg.as_bytes()).await.unwrap();
            let out = s.decrypt_async(drr).await.unwrap();
            assert_eq!(out, msg.as_bytes());
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn async_cache_hit_path() {
    let factory = make_factory();
    let session = factory.get_session("p-cache");

    // First call: cache miss, loads from metastore
    let drr1 = session.encrypt_async(b"first").await.unwrap();
    // Second call: cache hit, no metastore call
    let drr2 = session.encrypt_async(b"second").await.unwrap();

    let out1 = session.decrypt_async(drr1).await.unwrap();
    let out2 = session.decrypt_async(drr2).await.unwrap();

    assert_eq!(out1, b"first");
    assert_eq!(out2, b"second");
}

#[tokio::test]
async fn async_empty_partition_rejected() {
    let factory = make_factory();
    let session = factory.get_session("");

    let result = session.encrypt_async(b"data").await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("partition id cannot be empty"),
        "expected partition validation error"
    );
}

#[tokio::test]
async fn async_large_payload() {
    let factory = make_factory();
    let session = factory.get_session("p-large");

    let data = vec![0xAB_u8; 1_000_000]; // 1MB
    let drr = session.encrypt_async(&data).await.unwrap();
    let out = session.decrypt_async(drr).await.unwrap();
    assert_eq!(out, data);
}
