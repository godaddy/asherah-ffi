#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for CryptoPolicy default and new_crypto_policy with PolicyOptions.

use asherah::policy::{new_crypto_policy, CryptoPolicy, PolicyOption};

// ──────────────────────────── Default values ────────────────────────────

#[test]
fn default_policy_values() {
    let p = CryptoPolicy::default();
    assert_eq!(p.create_date_precision_s, 60);
    assert_eq!(p.expire_key_after_s, 60 * 60 * 24 * 90);
    assert!(p.cache_system_keys);
    assert!(p.cache_intermediate_keys);
    assert!(p.shared_intermediate_key_cache);
    assert_eq!(p.intermediate_key_cache_max_size, 1000);
    assert_eq!(p.intermediate_key_cache_eviction_policy, "simple");
    assert_eq!(p.system_key_cache_max_size, 1000);
    assert_eq!(p.system_key_cache_eviction_policy, "simple");
    assert!(!p.cache_sessions);
    assert_eq!(p.session_cache_max_size, 1000);
    assert_eq!(p.session_cache_ttl_s, 2 * 60 * 60);
    assert_eq!(p.session_cache_eviction_policy, "slru");
    assert_eq!(p.revoke_check_interval_s, 60 * 60);
}

// ──────────────────────────── Individual options ────────────────────────────

#[test]
fn option_expire_after_secs() {
    let p = new_crypto_policy(&[PolicyOption::ExpireAfterSecs(3600)]);
    assert_eq!(p.expire_key_after_s, 3600);
    // Others unchanged
    assert!(p.cache_system_keys);
}

#[test]
fn option_no_cache() {
    let p = new_crypto_policy(&[PolicyOption::NoCache]);
    assert!(!p.cache_system_keys);
    assert!(!p.cache_intermediate_keys);
}

#[test]
fn option_revoke_check_interval() {
    let p = new_crypto_policy(&[PolicyOption::RevokeCheckIntervalSecs(300)]);
    assert_eq!(p.revoke_check_interval_s, 300);
}

#[test]
fn option_shared_intermediate_key_cache() {
    let p = new_crypto_policy(&[PolicyOption::SharedIntermediateKeyCache(true)]);
    assert!(p.shared_intermediate_key_cache);
}

#[test]
fn option_intermediate_key_cache_max_size() {
    let p = new_crypto_policy(&[PolicyOption::IntermediateKeyCacheMaxSize(500)]);
    assert_eq!(p.intermediate_key_cache_max_size, 500);
}

#[test]
fn option_intermediate_key_cache_eviction_policy() {
    let p = new_crypto_policy(&[PolicyOption::IntermediateKeyCacheEvictionPolicy(
        "lru".into(),
    )]);
    assert_eq!(p.intermediate_key_cache_eviction_policy, "lru");
}

#[test]
fn option_system_key_cache_max_size() {
    let p = new_crypto_policy(&[PolicyOption::SystemKeyCacheMaxSize(50)]);
    assert_eq!(p.system_key_cache_max_size, 50);
}

#[test]
fn option_system_key_cache_eviction_policy() {
    let p = new_crypto_policy(&[PolicyOption::SystemKeyCacheEvictionPolicy("lfu".into())]);
    assert_eq!(p.system_key_cache_eviction_policy, "lfu");
}

#[test]
fn option_session_cache() {
    let p = new_crypto_policy(&[PolicyOption::SessionCache(true)]);
    assert!(p.cache_sessions);
}

#[test]
fn option_session_cache_max_size() {
    let p = new_crypto_policy(&[PolicyOption::SessionCacheMaxSize(42)]);
    assert_eq!(p.session_cache_max_size, 42);
}

#[test]
fn option_session_cache_duration() {
    let p = new_crypto_policy(&[PolicyOption::SessionCacheDurationSecs(120)]);
    assert_eq!(p.session_cache_ttl_s, 120);
}

#[test]
fn option_session_cache_eviction_policy() {
    let p = new_crypto_policy(&[PolicyOption::SessionCacheEvictionPolicy("lru".into())]);
    assert_eq!(p.session_cache_eviction_policy, "lru");
}

#[test]
fn option_create_date_precision() {
    let p = new_crypto_policy(&[PolicyOption::CreateDatePrecisionSecs(10)]);
    assert_eq!(p.create_date_precision_s, 10);
}

// ──────────────────────────── Multiple options ────────────────────────────

#[test]
fn multiple_options_applied_in_order() {
    let p = new_crypto_policy(&[
        PolicyOption::ExpireAfterSecs(1000),
        PolicyOption::NoCache,
        PolicyOption::SessionCache(true),
        PolicyOption::SessionCacheMaxSize(10),
    ]);
    assert_eq!(p.expire_key_after_s, 1000);
    assert!(!p.cache_system_keys);
    assert!(!p.cache_intermediate_keys);
    assert!(p.cache_sessions);
    assert_eq!(p.session_cache_max_size, 10);
}

#[test]
fn no_cache_then_re_enable_system_cache() {
    // NoCache disables both, but a subsequent option could re-enable neither
    // (there's no re-enable option; this just verifies order)
    let p = new_crypto_policy(&[PolicyOption::NoCache, PolicyOption::ExpireAfterSecs(500)]);
    assert!(!p.cache_system_keys);
    assert!(!p.cache_intermediate_keys);
    assert_eq!(p.expire_key_after_s, 500);
}

#[test]
fn empty_options() {
    let p = new_crypto_policy(&[]);
    let d = CryptoPolicy::default();
    assert_eq!(p.expire_key_after_s, d.expire_key_after_s);
    assert_eq!(p.cache_system_keys, d.cache_system_keys);
}

// ──────────────────────────── Edge values ────────────────────────────

#[test]
fn zero_expire_after() {
    let p = new_crypto_policy(&[PolicyOption::ExpireAfterSecs(0)]);
    assert_eq!(p.expire_key_after_s, 0);
}

#[test]
fn negative_expire_after() {
    let p = new_crypto_policy(&[PolicyOption::ExpireAfterSecs(-1)]);
    assert_eq!(p.expire_key_after_s, -1);
}

#[test]
fn zero_cache_size() {
    let p = new_crypto_policy(&[
        PolicyOption::IntermediateKeyCacheMaxSize(0),
        PolicyOption::SystemKeyCacheMaxSize(0),
        PolicyOption::SessionCacheMaxSize(0),
    ]);
    assert_eq!(p.intermediate_key_cache_max_size, 0);
    assert_eq!(p.system_key_cache_max_size, 0);
    assert_eq!(p.session_cache_max_size, 0);
}

#[test]
fn very_large_cache_size() {
    let p = new_crypto_policy(&[PolicyOption::IntermediateKeyCacheMaxSize(usize::MAX)]);
    assert_eq!(p.intermediate_key_cache_max_size, usize::MAX);
}

#[test]
fn negative_create_date_precision() {
    let p = new_crypto_policy(&[PolicyOption::CreateDatePrecisionSecs(-1)]);
    assert_eq!(p.create_date_precision_s, -1);
}

#[test]
fn zero_create_date_precision() {
    let p = new_crypto_policy(&[PolicyOption::CreateDatePrecisionSecs(0)]);
    assert_eq!(p.create_date_precision_s, 0);
}
