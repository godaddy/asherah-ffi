#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for `asherah::builders::config_from_env()` env-var parsing.

use std::sync::Mutex;

use asherah::builders::config_from_env;
use asherah::policy::CryptoPolicy;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// All env var names that `config_from_env` reads.
const CONFIG_ENV_VARS: &[&str] = &[
    "SERVICE_NAME",
    "PRODUCT_ID",
    "REGION_SUFFIX",
    "EXPIRE_AFTER_SECS",
    "CREATE_DATE_PRECISION_SECS",
    "REVOKE_CHECK_INTERVAL_SECS",
    "SESSION_CACHE",
    "SESSION_CACHE_MAX_SIZE",
    "SESSION_CACHE_DURATION_SECS",
    "CACHE_SYSTEM_KEYS",
    "CACHE_INTERMEDIATE_KEYS",
    "SHARED_INTERMEDIATE_KEY_CACHE",
];

/// Remove all config env vars to get a clean slate.
fn clear_config_env() {
    for k in CONFIG_ENV_VARS {
        std::env::remove_var(k);
    }
}

// ─────────────────────────── defaults ───────────────────────────

#[test]
fn defaults_when_no_env_vars_set() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    let cfg = config_from_env();
    let defaults = CryptoPolicy::default();

    assert_eq!(cfg.service, "service");
    assert_eq!(cfg.product, "product");
    assert_eq!(cfg.region_suffix, None);
    assert_eq!(cfg.policy.expire_key_after_s, defaults.expire_key_after_s);
    assert_eq!(
        cfg.policy.create_date_precision_s,
        defaults.create_date_precision_s
    );
    assert_eq!(
        cfg.policy.revoke_check_interval_s,
        defaults.revoke_check_interval_s
    );
    assert_eq!(cfg.policy.cache_sessions, defaults.cache_sessions);
    assert_eq!(
        cfg.policy.session_cache_max_size,
        defaults.session_cache_max_size
    );
    assert_eq!(cfg.policy.session_cache_ttl_s, defaults.session_cache_ttl_s);
    assert_eq!(cfg.policy.cache_system_keys, defaults.cache_system_keys);
    assert_eq!(
        cfg.policy.cache_intermediate_keys,
        defaults.cache_intermediate_keys
    );
    assert_eq!(
        cfg.policy.shared_intermediate_key_cache,
        defaults.shared_intermediate_key_cache
    );
}

// ─────────────────────── individual env vars ───────────────────────

#[test]
fn service_name_env() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    std::env::set_var("SERVICE_NAME", "my-svc");
    let cfg = config_from_env();
    assert_eq!(cfg.service, "my-svc");

    clear_config_env();
}

#[test]
fn product_id_env() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    std::env::set_var("PRODUCT_ID", "my-product");
    let cfg = config_from_env();
    assert_eq!(cfg.product, "my-product");

    clear_config_env();
}

#[test]
fn region_suffix_env() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    std::env::set_var("REGION_SUFFIX", "_us-west-2");
    let cfg = config_from_env();
    assert_eq!(cfg.region_suffix.as_deref(), Some("_us-west-2"));

    clear_config_env();
}

#[test]
fn expire_after_secs_env() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    std::env::set_var("EXPIRE_AFTER_SECS", "3600");
    let cfg = config_from_env();
    assert_eq!(cfg.policy.expire_key_after_s, 3600);

    clear_config_env();
}

#[test]
fn create_date_precision_secs_env() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    std::env::set_var("CREATE_DATE_PRECISION_SECS", "120");
    let cfg = config_from_env();
    assert_eq!(cfg.policy.create_date_precision_s, 120);

    clear_config_env();
}

#[test]
fn revoke_check_interval_secs_env() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    std::env::set_var("REVOKE_CHECK_INTERVAL_SECS", "1800");
    let cfg = config_from_env();
    assert_eq!(cfg.policy.revoke_check_interval_s, 1800);

    clear_config_env();
}

#[test]
fn session_cache_max_size_env() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    std::env::set_var("SESSION_CACHE_MAX_SIZE", "5000");
    let cfg = config_from_env();
    assert_eq!(cfg.policy.session_cache_max_size, 5000);

    clear_config_env();
}

#[test]
fn session_cache_duration_secs_env() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    std::env::set_var("SESSION_CACHE_DURATION_SECS", "7200");
    let cfg = config_from_env();
    assert_eq!(cfg.policy.session_cache_ttl_s, 7200);

    clear_config_env();
}

// ─────────────────────── bool parsing ───────────────────────

#[test]
fn session_cache_bool_true_variants() {
    let _lock = ENV_MUTEX.lock().unwrap();

    for val in &["1", "true", "yes", "on", "TRUE", "Yes", "ON"] {
        clear_config_env();
        std::env::set_var("SESSION_CACHE", val);
        let cfg = config_from_env();
        assert!(
            cfg.policy.cache_sessions,
            "SESSION_CACHE={val} should parse as true"
        );
    }

    clear_config_env();
}

#[test]
fn session_cache_bool_false_variants() {
    let _lock = ENV_MUTEX.lock().unwrap();

    // SESSION_CACHE=false is ignored — cache is always enabled
    for val in &["0", "false", "no", "off", "FALSE", "No", "OFF"] {
        clear_config_env();
        std::env::set_var("SESSION_CACHE", val);
        let cfg = config_from_env();
        assert!(
            cfg.policy.cache_sessions,
            "SESSION_CACHE={val} should be ignored — caches always enabled"
        );
    }

    clear_config_env();
}

#[test]
fn session_cache_bool_garbage_stays_default() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    let defaults = CryptoPolicy::default();
    std::env::set_var("SESSION_CACHE", "garbage");
    let cfg = config_from_env();
    assert_eq!(cfg.policy.cache_sessions, defaults.cache_sessions);

    clear_config_env();
}

#[test]
fn cache_system_keys_bool() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    // CACHE_SYSTEM_KEYS=false is ignored — cache is always enabled
    std::env::set_var("CACHE_SYSTEM_KEYS", "false");
    let cfg = config_from_env();
    assert!(cfg.policy.cache_system_keys);

    std::env::set_var("CACHE_SYSTEM_KEYS", "1");
    let cfg = config_from_env();
    assert!(cfg.policy.cache_system_keys);

    clear_config_env();
}

#[test]
fn cache_intermediate_keys_bool() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    // CACHE_INTERMEDIATE_KEYS=off is ignored — cache is always enabled
    std::env::set_var("CACHE_INTERMEDIATE_KEYS", "off");
    let cfg = config_from_env();
    assert!(cfg.policy.cache_intermediate_keys);

    std::env::set_var("CACHE_INTERMEDIATE_KEYS", "yes");
    let cfg = config_from_env();
    assert!(cfg.policy.cache_intermediate_keys);

    clear_config_env();
}

#[test]
fn shared_intermediate_key_cache_bool() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    // Default is false
    std::env::set_var("SHARED_INTERMEDIATE_KEY_CACHE", "true");
    let cfg = config_from_env();
    assert!(cfg.policy.shared_intermediate_key_cache);

    std::env::set_var("SHARED_INTERMEDIATE_KEY_CACHE", "0");
    let cfg = config_from_env();
    assert!(!cfg.policy.shared_intermediate_key_cache);

    clear_config_env();
}

// ─────────────────────── invalid numeric values ───────────────────────

#[test]
fn invalid_numeric_expire_after_stays_default() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    let defaults = CryptoPolicy::default();
    std::env::set_var("EXPIRE_AFTER_SECS", "not_a_number");
    let cfg = config_from_env();
    assert_eq!(cfg.policy.expire_key_after_s, defaults.expire_key_after_s);

    clear_config_env();
}

#[test]
fn invalid_numeric_create_date_precision_stays_default() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    let defaults = CryptoPolicy::default();
    std::env::set_var("CREATE_DATE_PRECISION_SECS", "abc");
    let cfg = config_from_env();
    assert_eq!(
        cfg.policy.create_date_precision_s,
        defaults.create_date_precision_s
    );

    clear_config_env();
}

#[test]
fn invalid_numeric_revoke_check_interval_stays_default() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    let defaults = CryptoPolicy::default();
    std::env::set_var("REVOKE_CHECK_INTERVAL_SECS", "12.5");
    let cfg = config_from_env();
    assert_eq!(
        cfg.policy.revoke_check_interval_s,
        defaults.revoke_check_interval_s
    );

    clear_config_env();
}

#[test]
fn invalid_numeric_session_cache_max_size_stays_default() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    let defaults = CryptoPolicy::default();
    std::env::set_var("SESSION_CACHE_MAX_SIZE", "-1");
    let cfg = config_from_env();
    assert_eq!(
        cfg.policy.session_cache_max_size,
        defaults.session_cache_max_size
    );

    clear_config_env();
}

#[test]
fn invalid_numeric_session_cache_duration_stays_default() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    let defaults = CryptoPolicy::default();
    std::env::set_var("SESSION_CACHE_DURATION_SECS", "");
    let cfg = config_from_env();
    assert_eq!(cfg.policy.session_cache_ttl_s, defaults.session_cache_ttl_s);

    clear_config_env();
}

// ─────────────────────── all env vars at once ───────────────────────

#[test]
fn all_env_vars_set_at_once() {
    let _lock = ENV_MUTEX.lock().unwrap();
    clear_config_env();

    std::env::set_var("SERVICE_NAME", "all-svc");
    std::env::set_var("PRODUCT_ID", "all-prod");
    std::env::set_var("REGION_SUFFIX", "_eu-west-1");
    std::env::set_var("EXPIRE_AFTER_SECS", "999");
    std::env::set_var("CREATE_DATE_PRECISION_SECS", "30");
    std::env::set_var("REVOKE_CHECK_INTERVAL_SECS", "600");
    std::env::set_var("SESSION_CACHE", "on");
    std::env::set_var("SESSION_CACHE_MAX_SIZE", "2000");
    std::env::set_var("SESSION_CACHE_DURATION_SECS", "300");
    std::env::set_var("CACHE_SYSTEM_KEYS", "no");
    std::env::set_var("CACHE_INTERMEDIATE_KEYS", "off");
    std::env::set_var("SHARED_INTERMEDIATE_KEY_CACHE", "yes");

    let cfg = config_from_env();

    assert_eq!(cfg.service, "all-svc");
    assert_eq!(cfg.product, "all-prod");
    assert_eq!(cfg.region_suffix.as_deref(), Some("_eu-west-1"));
    assert_eq!(cfg.policy.expire_key_after_s, 999);
    assert_eq!(cfg.policy.create_date_precision_s, 30);
    assert_eq!(cfg.policy.revoke_check_interval_s, 600);
    assert!(cfg.policy.cache_sessions);
    assert_eq!(cfg.policy.session_cache_max_size, 2000);
    assert_eq!(cfg.policy.session_cache_ttl_s, 300);
    // Caches are always enabled regardless of env var setting
    assert!(cfg.policy.cache_system_keys);
    assert!(cfg.policy.cache_intermediate_keys);
    assert!(cfg.policy.shared_intermediate_key_cache);

    clear_config_env();
}
