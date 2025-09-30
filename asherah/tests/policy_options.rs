#![allow(clippy::unwrap_used, clippy::expect_used)]
use asherah as ael;
#[test]
fn test_policy_options_builder() {
    use ael::policy::PolicyOption::*;
    let p = ael::policy::new_crypto_policy(&[
        ExpireAfterSecs(3600),
        CreateDatePrecisionSecs(60),
        SessionCache(true),
        SessionCacheMaxSize(123),
        SessionCacheDurationSecs(456),
        SharedIntermediateKeyCache(true),
    ]);
    assert_eq!(p.expire_key_after_s, 3600);
    assert_eq!(p.create_date_precision_s, 60);
    assert!(p.cache_sessions);
    assert_eq!(p.session_cache_max_size, 123);
    assert_eq!(p.session_cache_ttl_s, 456);
    assert!(p.shared_intermediate_key_cache);
}
