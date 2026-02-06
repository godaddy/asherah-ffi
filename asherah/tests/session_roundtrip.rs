#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::sync::Arc;

use asherah as ael;

#[test]
fn session_encrypt_decrypt_roundtrip() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let metastore = Arc::new(ael::metastore::InMemoryMetastore::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![1_u8; 32]).unwrap());
    let cfg = ael::Config::new("svc", "prod");
    let factory = ael::api::new_session_factory(cfg, metastore, kms, crypto);
    let session = factory.get_session("partition-x");

    let drr = session.encrypt(b"hello").unwrap();
    let out = session.decrypt(drr).unwrap();
    assert_eq!(out, b"hello");
}
