#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::sync::Arc;

use asherah as ael;

#[test]
fn json_shapes_match() {
    let ekr = ael::EnvelopeKeyRecord {
        revoked: Some(false),
        id: "ik-1".into(),
        created: 123,
        encrypted_key: vec![1, 2, 3],
        parent_key_meta: Some(ael::KeyMeta {
            id: "sk-1".into(),
            created: 10,
        }),
    };
    let s = serde_json::to_string(&ekr).unwrap();
    // Expect Go-compatible JSON field names
    assert!(s.contains("\"Created\":"));
    assert!(s.contains("\"Key\":"));
    assert!(s.contains("\"ParentKeyMeta\":"));
}

#[test]
fn session_roundtrip_inmemory() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![7_u8; 32]).unwrap());
    let metastore = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("svc", "prod");
    let f = ael::api::new_session_factory(cfg, metastore, kms, crypto);
    let s = f.get_session("p1");
    let drr = s.encrypt(b"hello").unwrap();
    let pt = s.decrypt(drr).unwrap();
    assert_eq!(pt, b"hello");
}

#[test]
fn store_load_with_context_variants() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![7_u8; 32]).unwrap());
    let metastore = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("svc", "prod");
    let f = ael::api::new_session_factory(cfg, metastore, kms, crypto);
    let s = f.get_session("pctx");
    let store = ael::store::InMemoryStore::new();
    let key = s.store_ctx(&(), b"payload-ctx", &store).unwrap();
    let out = s.load_ctx(&(), &key, &store).unwrap();
    assert_eq!(out, b"payload-ctx");
}

#[test]
fn region_suffix_prefers_metastore_over_config() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![0_u8; 32]).unwrap());
    let base = Arc::new(ael::metastore::InMemoryMetastore::new());
    // Decorate with region suffix
    let meta = Arc::new(ael::metastore_region::RegionSuffixMetastore::new(
        base.clone(),
        "-from-store",
    ));
    let cfg = ael::Config::new("svc", "prod").with_region_suffix("-from-config");
    let f = ael::api::new_session_factory(cfg, meta, kms, crypto);
    let s = f.get_session("partition");
    // Encrypt and inspect parent key meta in DRK
    let drr = s.encrypt(b"data").unwrap();
    let key = drr.key.unwrap();
    let parent = key.parent_key_meta.unwrap();
    // Expect intermediate key's id includes suffix from metastore decorator
    assert!(parent.id.ends_with("-from-store"));
}
