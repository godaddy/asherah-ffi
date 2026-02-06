#![allow(clippy::unwrap_used, clippy::expect_used)]
use asherah as ael;
use std::sync::Arc;

#[test]
fn test_metastore_region_suffix_overrides_config() {
    let inner = Arc::new(ael::metastore::InMemoryMetastore::new());
    let ms = Arc::new(ael::metastore_region::RegionSuffixMetastore::new(
        inner,
        "us-east-1",
    ));
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![7_u8; 32]).unwrap());
    let cfg = ael::Config::new("svc", "prod").with_region_suffix("eu-west-1");
    let factory = ael::api::new_session_factory(cfg, ms, kms, crypto);
    let session = factory.get_session("partition");
    // encrypt to ensure partition naming works; no panic
    let drr = session.encrypt(b"X").unwrap();
    assert!(drr.key.is_some());
}
