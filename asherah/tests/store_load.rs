#![allow(clippy::unwrap_used, clippy::expect_used)]
use asherah as ael;
use std::sync::Arc;

#[test]
fn test_store_load_with_inmemory_store() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let metastore = Arc::new(ael::metastore::InMemoryMetastore::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![3_u8; 32]));
    let cfg = ael::Config::new("svc", "prod");
    let factory = ael::api::new_session_factory(cfg, metastore, kms, crypto);
    let session = factory.get_session("p");
    let store = ael::store::InMemoryStore::new();
    let key = session.store(b"payload-1", &store).unwrap();
    let out = session.load(&key, &store).unwrap();
    assert_eq!(out, b"payload-1");
}
