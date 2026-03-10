#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for RegionSuffixMetastore wrapper.

use std::sync::Arc;

use asherah::metastore::InMemoryMetastore;
use asherah::metastore_region::RegionSuffixMetastore;
use asherah::traits::Metastore;
use asherah::types::{EnvelopeKeyRecord, KeyMeta};

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

#[test]
fn region_suffix_returned() {
    let inner = Arc::new(InMemoryMetastore::new());
    let rsm = RegionSuffixMetastore::new(inner, "us-east-1");
    assert_eq!(rsm.region_suffix().unwrap(), "us-east-1");
}

#[test]
fn delegates_store_and_load() {
    let inner = Arc::new(InMemoryMetastore::new());
    let rsm = RegionSuffixMetastore::new(inner.clone(), "eu-west-1");

    let ekr = make_ekr(100);
    assert!(rsm.store("sk1", 100, &ekr).unwrap());
    let loaded = rsm.load("sk1", 100).unwrap().unwrap();
    assert_eq!(loaded.created, 100);

    // Also visible via inner store
    assert!(inner.load("sk1", 100).unwrap().is_some());
}

#[test]
fn delegates_load_latest() {
    let inner = Arc::new(InMemoryMetastore::new());
    let rsm = RegionSuffixMetastore::new(inner, "ap-south-1");

    rsm.store("sk1", 100, &make_ekr(100)).unwrap();
    rsm.store("sk1", 200, &make_ekr(200)).unwrap();
    let latest = rsm.load_latest("sk1").unwrap().unwrap();
    assert_eq!(latest.created, 200);
}

#[test]
fn region_suffix_used_in_factory() {
    let crypto = Arc::new(asherah::aead::AES256GCM::new());
    let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![1_u8; 32]).unwrap());
    let inner = Arc::new(InMemoryMetastore::new());
    let store = Arc::new(RegionSuffixMetastore::new(inner, "us-west-2"));

    let cfg = asherah::Config::new("svc", "prod");
    let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
    let session = factory.get_session("p1");
    let drr = session.encrypt(b"region test").unwrap();

    // IK ID should include region suffix from metastore
    let ik_id = drr
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .id
        .clone();
    assert!(
        ik_id.contains("us-west-2"),
        "IK ID should have suffix: {ik_id}"
    );

    let pt = session.decrypt(drr).unwrap();
    assert_eq!(pt, b"region test");
}
