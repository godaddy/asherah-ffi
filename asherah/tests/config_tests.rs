#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for Config, PublicFactory, session caching, region suffix, and metrics toggling.

use std::sync::Arc;

use asherah as ael;
fn make_factory() -> ael::SessionFactory<
    ael::aead::AES256GCM,
    ael::kms::StaticKMS<ael::aead::AES256GCM>,
    ael::metastore::InMemoryMetastore,
> {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![1_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    ael::api::new_session_factory(ael::Config::new("svc", "prod"), store, kms, crypto)
}

// ──────────────────────────── Config builders ────────────────────────────

#[test]
fn config_new() {
    let cfg = ael::Config::new("my-service", "my-product");
    assert_eq!(cfg.service, "my-service");
    assert_eq!(cfg.product, "my-product");
    assert!(cfg.region_suffix.is_none());
}

#[test]
fn config_with_region_suffix() {
    let cfg = ael::Config::new("svc", "prod").with_region_suffix("us-east-1");
    assert_eq!(cfg.region_suffix.unwrap(), "us-east-1");
}

#[test]
fn config_with_policy() {
    let policy = ael::CryptoPolicy::default();
    let cfg = ael::Config::new("svc", "prod").with_policy(policy.clone());
    assert_eq!(cfg.policy.expire_key_after_s, policy.expire_key_after_s);
}

#[test]
fn config_with_policy_options() {
    let cfg = ael::Config::new("svc", "prod").with_policy_options(&[
        ael::policy::PolicyOption::ExpireAfterSecs(1000),
        ael::policy::PolicyOption::NoCache,
    ]);
    assert_eq!(cfg.policy.expire_key_after_s, 1000);
    assert!(!cfg.policy.cache_system_keys);
}

// ──────────────────────────── PublicFactory ────────────────────────────

#[test]
fn factory_get_session_returns_valid_session() {
    let factory = make_factory();
    let session = factory.get_session("user-1");
    let drr = session.encrypt(b"test").unwrap();
    let pt = session.decrypt(drr).unwrap();
    assert_eq!(pt, b"test");
}

#[test]
fn factory_with_metrics_disabled() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![2_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = ael::api::new_session_factory_with_options(
        ael::Config::new("svc", "prod"),
        store,
        kms,
        crypto,
        &[ael::FactoryOption::Metrics(false)],
    );
    let session = factory.get_session("p1");
    let drr = session.encrypt(b"data").unwrap();
    let pt = session.decrypt(drr).unwrap();
    assert_eq!(pt, b"data");
}

#[test]
fn factory_with_secret_factory_option() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![3_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    // SecretFactory is a no-op, just verifying it doesn't panic
    let factory = ael::api::new_session_factory_with_options(
        ael::Config::new("svc", "prod"),
        store,
        kms,
        crypto,
        &[ael::FactoryOption::SecretFactory],
    );
    let session = factory.get_session("p1");
    let drr = session.encrypt(b"ok").unwrap();
    assert_eq!(session.decrypt(drr).unwrap(), b"ok");
}

// ──────────────────────────── Session caching ────────────────────────────

#[test]
fn session_cache_enabled() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![4_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("svc", "prod").with_policy_options(&[
        ael::policy::PolicyOption::SessionCache(true),
        ael::policy::PolicyOption::SessionCacheMaxSize(10),
        ael::policy::PolicyOption::SessionCacheDurationSecs(3600),
    ]);
    let factory = ael::api::new_session_factory(cfg, store, kms, crypto);

    let s1 = factory.get_session("user-1");
    let drr = s1.encrypt(b"cached session").unwrap();
    // Get same session again from cache
    let s2 = factory.get_session("user-1");
    let pt = s2.decrypt(drr).unwrap();
    assert_eq!(pt, b"cached session");
}

#[test]
fn session_cache_with_ttl_zero() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![5_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("svc", "prod").with_policy_options(&[
        ael::policy::PolicyOption::SessionCache(true),
        ael::policy::PolicyOption::SessionCacheDurationSecs(0),
    ]);
    let factory = ael::api::new_session_factory(cfg, store, kms, crypto);
    // Should still work even with TTL=0 (creates fresh session each time)
    let session = factory.get_session("user");
    let drr = session.encrypt(b"hello").unwrap();
    let pt = session.decrypt(drr).unwrap();
    assert_eq!(pt, b"hello");
}

// ──────────────────────────── Region suffix ────────────────────────────

#[test]
fn factory_with_region_suffix() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![6_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("svc", "prod").with_region_suffix("us-west-2");
    let factory = ael::api::new_session_factory(cfg, store, kms, crypto);

    let session = factory.get_session("p1");
    let drr = session.encrypt(b"region data").unwrap();
    // IK ID should include region suffix
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
        "IK ID should contain region suffix: {ik_id}"
    );
    let pt = session.decrypt(drr).unwrap();
    assert_eq!(pt, b"region data");
}

// ──────────────────────────── Shared IK cache ────────────────────────────

#[test]
fn factory_with_shared_intermediate_key_cache() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![7_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("svc", "prod")
        .with_policy_options(&[ael::policy::PolicyOption::SharedIntermediateKeyCache(true)]);
    let factory = ael::api::new_session_factory(cfg, store, kms, crypto);

    let s1 = factory.get_session("p1");
    let s2 = factory.get_session("p2");
    let drr1 = s1.encrypt(b"data1").unwrap();
    let drr2 = s2.encrypt(b"data2").unwrap();
    assert_eq!(s1.decrypt(drr1).unwrap(), b"data1");
    assert_eq!(s2.decrypt(drr2).unwrap(), b"data2");
}

// ──────────────────────────── Ctx variants ────────────────────────────

#[test]
fn encrypt_ctx_decrypt_ctx() {
    let factory = make_factory();
    let session = factory.get_session("p1");
    let drr = session.encrypt_ctx(&(), b"ctx data").unwrap();
    let pt = session.decrypt_ctx(&(), drr).unwrap();
    assert_eq!(pt, b"ctx data");
}

#[test]
fn store_ctx_load_ctx() {
    let factory = make_factory();
    let session = factory.get_session("p1");
    let store = ael::store::InMemoryStore::new();
    let key = session.store_ctx(&(), b"ctx payload", &store).unwrap();
    let pt = session.load_ctx(&(), &key, &store).unwrap();
    assert_eq!(pt, b"ctx payload");
}

// ──────────────────────────── Encryption trait ────────────────────────────

#[test]
fn encryption_trait() {
    use ael::Encryption;
    let factory = make_factory();
    let session = factory.get_session("p1");
    let drr = Encryption::encrypt(&session, b"trait test").unwrap();
    let pt = Encryption::decrypt(&session, drr).unwrap();
    assert_eq!(pt, b"trait test");
    Encryption::close(&session).unwrap();
}

// ──────────────────────────── EncryptionCtx trait ────────────────────────────

#[test]
fn encryption_ctx_trait() {
    use ael::EncryptionCtx;
    let factory = make_factory();
    let session = factory.get_session("p1");
    let drr = EncryptionCtx::encrypt_ctx(&session, &(), b"ctx trait test").unwrap();
    let pt = EncryptionCtx::decrypt_ctx(&session, &(), drr).unwrap();
    assert_eq!(pt, b"ctx trait test");
}

// ──────────────────────────── Session close ────────────────────────────

#[test]
fn session_close() {
    let factory = make_factory();
    let session = factory.get_session("p1");
    session.close().unwrap();
}

// ──────────────────────────── Multiple cache eviction policies ────────────────────────────

#[test]
fn factory_lru_eviction_policy() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![8_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("svc", "prod").with_policy_options(&[
        ael::policy::PolicyOption::IntermediateKeyCacheEvictionPolicy("lru".into()),
        ael::policy::PolicyOption::SystemKeyCacheEvictionPolicy("lru".into()),
    ]);
    let factory = ael::api::new_session_factory(cfg, store, kms, crypto);
    let session = factory.get_session("p1");
    let drr = session.encrypt(b"lru test").unwrap();
    assert_eq!(session.decrypt(drr).unwrap(), b"lru test");
}

#[test]
fn factory_lfu_eviction_policy() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![9_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("svc", "prod").with_policy_options(&[
        ael::policy::PolicyOption::IntermediateKeyCacheEvictionPolicy("lfu".into()),
        ael::policy::PolicyOption::SystemKeyCacheEvictionPolicy("lfu".into()),
    ]);
    let factory = ael::api::new_session_factory(cfg, store, kms, crypto);
    let session = factory.get_session("p1");
    let drr = session.encrypt(b"lfu test").unwrap();
    assert_eq!(session.decrypt(drr).unwrap(), b"lfu test");
}

#[test]
fn factory_slru_eviction_policy() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![10_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("svc", "prod").with_policy_options(&[
        ael::policy::PolicyOption::IntermediateKeyCacheEvictionPolicy("slru".into()),
        ael::policy::PolicyOption::SystemKeyCacheEvictionPolicy("slru".into()),
    ]);
    let factory = ael::api::new_session_factory(cfg, store, kms, crypto);
    let session = factory.get_session("p1");
    let drr = session.encrypt(b"slru test").unwrap();
    assert_eq!(session.decrypt(drr).unwrap(), b"slru test");
}

#[test]
fn factory_tinylfu_eviction_policy() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![11_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("svc", "prod").with_policy_options(&[
        ael::policy::PolicyOption::IntermediateKeyCacheEvictionPolicy("tinylfu".into()),
        ael::policy::PolicyOption::SystemKeyCacheEvictionPolicy("tinylfu".into()),
    ]);
    let factory = ael::api::new_session_factory(cfg, store, kms, crypto);
    let session = factory.get_session("p1");
    let drr = session.encrypt(b"tinylfu test").unwrap();
    assert_eq!(session.decrypt(drr).unwrap(), b"tinylfu test");
}

// ──────────────────────────── Factory options edge cases ────────────────────────────

#[test]
fn factory_with_empty_options() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![12_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = ael::api::new_session_factory_with_options(
        ael::Config::new("svc", "prod"),
        store,
        kms,
        crypto,
        &[], // empty options
    );
    let session = factory.get_session("p1");
    let drr = session.encrypt(b"empty opts").unwrap();
    assert_eq!(session.decrypt(drr).unwrap(), b"empty opts");
}

#[test]
fn factory_with_duplicate_metrics_options() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![13_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    // Last Metrics option should win
    let factory = ael::api::new_session_factory_with_options(
        ael::Config::new("svc", "prod"),
        store,
        kms,
        crypto,
        &[
            ael::FactoryOption::Metrics(true),
            ael::FactoryOption::Metrics(false),
            ael::FactoryOption::Metrics(true),
        ],
    );
    let session = factory.get_session("p1");
    let drr = session.encrypt(b"dup opts").unwrap();
    assert_eq!(session.decrypt(drr).unwrap(), b"dup opts");
}

#[test]
fn factory_with_all_options() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![14_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = ael::api::new_session_factory_with_options(
        ael::Config::new("svc", "prod"),
        store,
        kms,
        crypto,
        &[
            ael::FactoryOption::Metrics(true),
            ael::FactoryOption::SecretFactory,
        ],
    );
    let session = factory.get_session("p1");
    let drr = session.encrypt(b"all opts").unwrap();
    assert_eq!(session.decrypt(drr).unwrap(), b"all opts");
}

// ──────────────────────────── Gap 13: Config builder chaining ────────────────────────────

#[test]
fn config_with_policy_chaining() {
    let policy1 = ael::CryptoPolicy::default();
    let policy2 = ael::policy::new_crypto_policy(&[ael::policy::PolicyOption::ExpireAfterSecs(42)]);
    let cfg = ael::Config::new("svc", "prod")
        .with_policy(policy1)
        .with_policy(policy2);
    assert_eq!(
        cfg.policy.expire_key_after_s, 42,
        "last with_policy should win"
    );
}

#[test]
fn config_with_region_suffix_empty_string() {
    let cfg = ael::Config::new("svc", "prod").with_region_suffix("");
    assert_eq!(cfg.region_suffix.as_deref(), Some(""));
}

#[test]
fn config_builder_full_chain() {
    let cfg = ael::Config::new("svc", "prod")
        .with_region_suffix("us-east-1")
        .with_policy_options(&[
            ael::policy::PolicyOption::ExpireAfterSecs(3600),
            ael::policy::PolicyOption::NoCache,
        ]);
    assert_eq!(cfg.region_suffix.as_deref(), Some("us-east-1"));
    assert_eq!(cfg.policy.expire_key_after_s, 3600);
    assert!(!cfg.policy.cache_system_keys);
}
