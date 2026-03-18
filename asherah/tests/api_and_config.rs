#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use asherah::aead::AES256GCM;
use asherah::api::{new_session_factory, new_session_factory_with_options, FactoryOption};
use asherah::kms::StaticKMS;
use asherah::metastore::InMemoryMetastore;
use asherah::policy::{CryptoPolicy, PolicyOption};
use asherah::Config;

fn make_components() -> (
    Config,
    Arc<InMemoryMetastore>,
    Arc<StaticKMS<AES256GCM>>,
    Arc<AES256GCM>,
) {
    let crypto = Arc::new(AES256GCM::new());
    let kms = Arc::new(StaticKMS::new(crypto.clone(), vec![42_u8; 32]).unwrap());
    let metastore = Arc::new(InMemoryMetastore::new());
    let cfg = Config::new("test-service", "test-product");
    (cfg, metastore, kms, crypto)
}

// ---------- API tests ----------

#[test]
fn test_new_session_factory_roundtrip() {
    let (cfg, metastore, kms, crypto) = make_components();
    let factory = new_session_factory(cfg, metastore, kms, crypto);
    let session = factory.get_session("partition-1");
    let plaintext = b"the quick brown fox";
    let drr = session.encrypt(plaintext).unwrap();
    let decrypted = session.decrypt(drr).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_new_session_factory_with_options_metrics_true() {
    let (cfg, metastore, kms, crypto) = make_components();
    let factory = new_session_factory_with_options(
        cfg,
        metastore,
        kms,
        crypto,
        &[FactoryOption::Metrics(true)],
    );
    let session = factory.get_session("p-metrics-true");
    let drr = session.encrypt(b"metrics-on").unwrap();
    let pt = session.decrypt(drr).unwrap();
    assert_eq!(pt, b"metrics-on");
}

#[test]
fn test_new_session_factory_with_options_metrics_false() {
    let (cfg, metastore, kms, crypto) = make_components();
    let factory = new_session_factory_with_options(
        cfg,
        metastore,
        kms,
        crypto,
        &[FactoryOption::Metrics(false)],
    );
    let session = factory.get_session("p-metrics-false");
    let drr = session.encrypt(b"metrics-off").unwrap();
    let pt = session.decrypt(drr).unwrap();
    assert_eq!(pt, b"metrics-off");
}

#[test]
fn test_new_session_factory_with_options_secret_factory() {
    let (cfg, metastore, kms, crypto) = make_components();
    let factory = new_session_factory_with_options(
        cfg,
        metastore,
        kms,
        crypto,
        &[FactoryOption::SecretFactory],
    );
    let session = factory.get_session("p-secret-factory");
    let drr = session.encrypt(b"secret-factory-noop").unwrap();
    let pt = session.decrypt(drr).unwrap();
    assert_eq!(pt, b"secret-factory-noop");
}

#[test]
fn test_new_session_factory_with_options_empty_opts() {
    let (cfg, metastore, kms, crypto) = make_components();
    let factory = new_session_factory_with_options(cfg, metastore, kms, crypto, &[]);
    let session = factory.get_session("p-empty-opts");
    let drr = session.encrypt(b"empty-opts").unwrap();
    let pt = session.decrypt(drr).unwrap();
    assert_eq!(pt, b"empty-opts");
}

#[test]
fn test_factory_close() {
    let (cfg, metastore, kms, crypto) = make_components();
    let factory = new_session_factory(cfg, metastore, kms, crypto);
    // Get a session and use it before close
    let session = factory.get_session("p-close");
    let drr = session.encrypt(b"before-close").unwrap();
    let pt = session.decrypt(drr).unwrap();
    assert_eq!(pt, b"before-close");
    // Close should succeed without error
    factory.close().unwrap();
}

// ---------- Config tests ----------

#[test]
fn test_config_new_sets_fields() {
    let cfg = Config::new("my-service", "my-product");
    assert_eq!(cfg.service, "my-service");
    assert_eq!(cfg.product, "my-product");
    assert!(cfg.region_suffix.is_none());
    // Default policy should be applied
    assert_eq!(cfg.policy.create_date_precision_s, 60);
}

#[test]
fn test_config_with_region_suffix() {
    let cfg = Config::new("svc", "prod").with_region_suffix("-us-west-2");
    assert_eq!(cfg.region_suffix, Some("-us-west-2".to_string()));
    assert_eq!(cfg.service, "svc");
    assert_eq!(cfg.product, "prod");
}

#[test]
fn test_config_with_policy() {
    let policy = CryptoPolicy {
        expire_key_after_s: 3600,
        cache_system_keys: false,
        ..CryptoPolicy::default()
    };
    let cfg = Config::new("svc", "prod").with_policy(policy);
    assert_eq!(cfg.policy.expire_key_after_s, 3600);
    assert!(!cfg.policy.cache_system_keys);
}

#[test]
fn test_config_builder_chain() {
    let custom_policy = CryptoPolicy {
        expire_key_after_s: 7200,
        ..CryptoPolicy::default()
    };
    let cfg = Config::new("chain-svc", "chain-prod")
        .with_region_suffix("-eu-west-1")
        .with_policy(custom_policy);
    assert_eq!(cfg.service, "chain-svc");
    assert_eq!(cfg.product, "chain-prod");
    assert_eq!(cfg.region_suffix, Some("-eu-west-1".to_string()));
    assert_eq!(cfg.policy.expire_key_after_s, 7200);
}

#[test]
fn test_config_with_policy_options() {
    let cfg = Config::new("svc", "prod").with_policy_options(&[
        PolicyOption::ExpireAfterSecs(1800),
        PolicyOption::NoCache,
        PolicyOption::SessionCache(false),
        PolicyOption::SessionCacheMaxSize(500),
    ]);
    assert_eq!(cfg.policy.expire_key_after_s, 1800);
    // NoCache disables SK/IK caching (programmatic API honors it for tests)
    assert!(!cfg.policy.cache_system_keys);
    assert!(!cfg.policy.cache_intermediate_keys);
    assert!(!cfg.policy.cache_sessions);
    assert_eq!(cfg.policy.session_cache_max_size, 500);
}

// ---------- Encryption trait tests ----------

#[test]
fn test_encryption_trait_roundtrip() {
    use asherah::Encryption;

    let (cfg, metastore, kms, crypto) = make_components();
    let factory = new_session_factory(cfg, metastore, kms, crypto);
    let session = factory.get_session("p-trait");

    let plaintext = b"trait-encrypt-test";
    let drr = Encryption::encrypt(&session, plaintext).unwrap();
    let decrypted = Encryption::decrypt(&session, drr).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encryption_ctx_trait_roundtrip() {
    use asherah::EncryptionCtx;

    let (cfg, metastore, kms, crypto) = make_components();
    let factory = new_session_factory(cfg, metastore, kms, crypto);
    let session = factory.get_session("p-ctx-trait");

    let plaintext = b"ctx-encrypt-test";
    let ctx = ();
    let drr = EncryptionCtx::encrypt_ctx(&session, &ctx, plaintext).unwrap();
    let decrypted = EncryptionCtx::decrypt_ctx(&session, &ctx, drr).unwrap();
    assert_eq!(decrypted, plaintext);
}
