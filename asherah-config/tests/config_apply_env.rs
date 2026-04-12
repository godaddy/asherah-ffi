#![allow(clippy::unwrap_used, clippy::print_stdout)]
//! Tests for ConfigOptions::apply_env and related helpers.
//!
//! Since apply_env manipulates process-global environment variables,
//! tests run sequentially via harness=false to avoid races.

use asherah_config::ConfigOptions;
use std::collections::HashMap;

// ============================================================================
// Helpers
// ============================================================================

fn base_config() -> ConfigOptions {
    ConfigOptions {
        service_name: Some("test-svc".into()),
        product_id: Some("test-prod".into()),
        metastore: Some("memory".into()),
        kms: Some("static".into()),
        enable_session_caching: Some(false),
        ..Default::default()
    }
}

fn get_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

// ============================================================================
// Tests
// ============================================================================

fn test_from_json_valid() {
    let json = r#"{
        "ServiceName": "svc",
        "ProductID": "prod",
        "Metastore": "memory",
        "KMS": "static"
    }"#;
    let cfg = ConfigOptions::from_json(json).unwrap();
    assert_eq!(cfg.service_name.as_deref(), Some("svc"));
    assert_eq!(cfg.product_id.as_deref(), Some("prod"));
    assert_eq!(cfg.metastore.as_deref(), Some("memory"));
    assert_eq!(cfg.kms.as_deref(), Some("static"));
}

fn test_from_json_invalid() {
    let result = ConfigOptions::from_json("not json at all");
    assert!(result.is_err());
}

fn test_from_json_all_fields() {
    let json = r#"{
        "ServiceName": "svc",
        "ProductID": "prod",
        "ExpireAfter": 3600,
        "CheckInterval": 60,
        "Metastore": "memory",
        "ConnectionString": "postgres://localhost/db",
        "ReplicaReadConsistency": "eventual",
        "DynamoDBEndpoint": "http://localhost:8000",
        "DynamoDBRegion": "us-east-1",
        "DynamoDBTableName": "keys",
        "SessionCacheMaxSize": 100,
        "SessionCacheDuration": 300,
        "KMS": "aws",
        "PreferredRegion": "us-west-2",
        "EnableRegionSuffix": true,
        "EnableSessionCaching": true,
        "Verbose": true,
        "SQLMetastoreDBType": "postgres",
        "DisableZeroCopy": true,
        "NullDataCheck": true,
        "RegionMap": {"us-east-1": "arn:aws:kms:us-east-1:123:key/abc"}
    }"#;
    let cfg = ConfigOptions::from_json(json).unwrap();
    assert_eq!(cfg.expire_after, Some(3600));
    assert_eq!(cfg.check_interval, Some(60));
    assert_eq!(cfg.session_cache_max_size, Some(100));
    assert_eq!(cfg.session_cache_duration, Some(300));
    assert_eq!(cfg.preferred_region.as_deref(), Some("us-west-2"));
    assert_eq!(cfg.enable_region_suffix, Some(true));
    assert_eq!(cfg.verbose, Some(true));
    assert_eq!(cfg.disable_zero_copy, Some(true));
    assert_eq!(cfg.null_data_check, Some(true));
    assert!(cfg.region_map.is_some());
}

fn test_missing_service_name() {
    let cfg = ConfigOptions {
        service_name: None,
        product_id: Some("prod".into()),
        metastore: Some("memory".into()),
        ..Default::default()
    };
    let err = cfg.apply_env().unwrap_err();
    assert!(
        err.to_string().contains("ServiceName"),
        "expected ServiceName error, got: {err}"
    );
}

fn test_missing_product_id() {
    let cfg = ConfigOptions {
        service_name: Some("svc".into()),
        product_id: None,
        metastore: Some("memory".into()),
        ..Default::default()
    };
    let err = cfg.apply_env().unwrap_err();
    assert!(
        err.to_string().contains("ProductID"),
        "expected ProductID error, got: {err}"
    );
}

fn test_missing_metastore() {
    let cfg = ConfigOptions {
        service_name: Some("svc".into()),
        product_id: Some("prod".into()),
        metastore: None,
        ..Default::default()
    };
    let err = cfg.apply_env().unwrap_err();
    assert!(
        err.to_string().contains("Metastore"),
        "expected Metastore error, got: {err}"
    );
}

fn test_unsupported_metastore() {
    let cfg = ConfigOptions {
        service_name: Some("svc".into()),
        product_id: Some("prod".into()),
        metastore: Some("redis".into()),
        ..Default::default()
    };
    let err = cfg.apply_env().unwrap_err();
    assert!(
        err.to_string().contains("Unsupported"),
        "expected Unsupported error, got: {err}"
    );
}

fn test_memory_metastore_sets_env() {
    let cfg = base_config();
    let applied = cfg.apply_env().unwrap();
    assert!(!applied.verbose);
    assert!(!applied.enable_session_caching);

    assert_eq!(get_env("SERVICE_NAME").as_deref(), Some("test-svc"));
    assert_eq!(get_env("PRODUCT_ID").as_deref(), Some("test-prod"));
    assert_eq!(get_env("Metastore").as_deref(), Some("memory"));
    assert_eq!(get_env("KMS").as_deref(), Some("static"));
    // memory clears DB-specific vars
    assert!(get_env("SQLITE_PATH").is_none());
    assert!(get_env("POSTGRES_URL").is_none());
    assert!(get_env("MYSQL_URL").is_none());
    assert!(get_env("DDB_TABLE").is_none());
}

fn test_sqlite_metastore_with_connection_string() {
    let cfg = ConfigOptions {
        metastore: Some("sqlite".into()),
        connection_string: Some("/tmp/test.db".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert_eq!(get_env("Metastore").as_deref(), Some("sqlite"));
    assert_eq!(get_env("SQLITE_PATH").as_deref(), Some("/tmp/test.db"));
    assert!(get_env("POSTGRES_URL").is_none());
    assert!(get_env("MYSQL_URL").is_none());
}

fn test_sqlite_metastore_strips_prefix() {
    let cfg = ConfigOptions {
        metastore: Some("sqlite".into()),
        connection_string: Some("sqlite:///tmp/prefixed.db".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert_eq!(get_env("SQLITE_PATH").as_deref(), Some("/tmp/prefixed.db"));
}

fn test_sqlite_metastore_missing_connection_string() {
    let cfg = ConfigOptions {
        metastore: Some("sqlite".into()),
        connection_string: None,
        ..base_config()
    };
    let err = cfg.apply_env().unwrap_err();
    assert!(err.to_string().contains("ConnectionString"));
}

fn test_rdbms_postgres() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("postgres://user:pass@localhost/db".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert_eq!(
        get_env("POSTGRES_URL").as_deref(),
        Some("postgres://user:pass@localhost/db")
    );
    assert!(get_env("MYSQL_URL").is_none());
    assert!(get_env("SQLITE_PATH").is_none());
}

fn test_rdbms_mysql() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("mysql://user:pass@localhost/db".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert!(get_env("MYSQL_URL").is_some());
    assert!(get_env("POSTGRES_URL").is_none());
}

fn test_rdbms_missing_connection_string() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: None,
        ..base_config()
    };
    let err = cfg.apply_env().unwrap_err();
    assert!(err.to_string().contains("ConnectionString"));
}

fn test_dynamodb_metastore() {
    let cfg = ConfigOptions {
        metastore: Some("dynamodb".into()),
        dynamo_db_table_name: Some("my-table".into()),
        dynamo_db_region: Some("eu-west-1".into()),
        dynamo_db_endpoint: Some("http://localhost:8000".into()),
        enable_region_suffix: Some(true),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert_eq!(get_env("DDB_TABLE").as_deref(), Some("my-table"));
    assert_eq!(get_env("AWS_REGION").as_deref(), Some("eu-west-1"));
    assert_eq!(
        get_env("AWS_ENDPOINT_URL").as_deref(),
        Some("http://localhost:8000")
    );
    assert_eq!(get_env("DDB_REGION_SUFFIX").as_deref(), Some("1"));
    assert!(get_env("SQLITE_PATH").is_none());
    assert!(get_env("POSTGRES_URL").is_none());
    assert!(get_env("MYSQL_URL").is_none());
}

fn test_normalize_alias_test_debug_memory() {
    let cfg = ConfigOptions {
        metastore: Some("test-debug-memory".into()),
        kms: Some("test-debug-static".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert_eq!(get_env("Metastore").as_deref(), Some("memory"));
    assert_eq!(get_env("KMS").as_deref(), Some("static"));
}

fn test_normalize_alias_test_debug_sqlite() {
    let cfg = ConfigOptions {
        metastore: Some("test-debug-sqlite".into()),
        connection_string: Some("/tmp/debug.db".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert_eq!(get_env("Metastore").as_deref(), Some("sqlite"));
}

fn test_optional_int_fields_set() {
    let cfg = ConfigOptions {
        expire_after: Some(7200),
        check_interval: Some(120),
        session_cache_duration: Some(600),
        session_cache_max_size: Some(50),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert_eq!(get_env("EXPIRE_AFTER_SECS").as_deref(), Some("7200"));
    assert_eq!(
        get_env("REVOKE_CHECK_INTERVAL_SECS").as_deref(),
        Some("120")
    );
    assert_eq!(
        get_env("SESSION_CACHE_DURATION_SECS").as_deref(),
        Some("600")
    );
    assert_eq!(get_env("SESSION_CACHE_MAX_SIZE").as_deref(), Some("50"));
}

fn test_optional_int_fields_none_clears_env() {
    // Pre-set env vars to simulate a prior factory build
    std::env::set_var("EXPIRE_AFTER_SECS", "999");
    std::env::set_var("REVOKE_CHECK_INTERVAL_SECS", "888");

    let cfg = ConfigOptions {
        expire_after: None,
        check_interval: None,
        session_cache_duration: None,
        session_cache_max_size: None,
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();

    // None fields must clear stale env vars from prior builds
    assert_eq!(get_env("EXPIRE_AFTER_SECS"), None);
    assert_eq!(get_env("REVOKE_CHECK_INTERVAL_SECS"), None);
    assert_eq!(get_env("SESSION_CACHE_DURATION_SECS"), None);
    assert_eq!(get_env("SESSION_CACHE_MAX_SIZE"), None);
}

fn test_sequential_factory_builds_isolated() {
    // First build sets policy/KMS/pool fields
    let cfg_a = ConfigOptions {
        expire_after: Some(7200),
        check_interval: Some(120),
        preferred_region: Some("us-east-1".into()),
        pool_max_open: Some(50),
        pool_max_idle: Some(10),
        pool_max_lifetime: Some(3600),
        pool_max_idle_time: Some(600),
        ..base_config()
    };
    let _applied = cfg_a.apply_env().unwrap();
    assert_eq!(get_env("EXPIRE_AFTER_SECS").as_deref(), Some("7200"));
    assert_eq!(get_env("PREFERRED_REGION").as_deref(), Some("us-east-1"));
    assert_eq!(get_env("ASHERAH_POOL_MAX_OPEN").as_deref(), Some("50"));

    // Second build omits those fields — they must not carry over
    let cfg_b = ConfigOptions {
        expire_after: None,
        check_interval: None,
        preferred_region: None,
        pool_max_open: None,
        pool_max_idle: None,
        pool_max_lifetime: None,
        pool_max_idle_time: None,
        ..base_config()
    };
    let _applied = cfg_b.apply_env().unwrap();
    assert_eq!(get_env("EXPIRE_AFTER_SECS"), None);
    assert_eq!(get_env("REVOKE_CHECK_INTERVAL_SECS"), None);
    assert_eq!(get_env("PREFERRED_REGION"), None);
    assert_eq!(get_env("ASHERAH_POOL_MAX_OPEN"), None);
    assert_eq!(get_env("ASHERAH_POOL_MAX_IDLE"), None);
    assert_eq!(get_env("ASHERAH_POOL_MAX_LIFETIME"), None);
    assert_eq!(get_env("ASHERAH_POOL_MAX_IDLE_TIME"), None);
}

fn test_region_map_set() {
    let mut map = HashMap::new();
    map.insert(
        "us-east-1".to_string(),
        "arn:aws:kms:us-east-1:123:key/abc".to_string(),
    );
    let cfg = ConfigOptions {
        region_map: Some(map),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    let rm = get_env("REGION_MAP").unwrap();
    assert!(rm.contains("us-east-1"));
    assert!(rm.contains("arn:aws:kms"));
}

fn test_region_map_none() {
    let cfg = ConfigOptions {
        region_map: None,
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert!(get_env("REGION_MAP").is_none());
}

fn test_verbose_true() {
    let cfg = ConfigOptions {
        verbose: Some(true),
        ..base_config()
    };
    let applied = cfg.apply_env().unwrap();
    assert!(applied.verbose);
    assert_eq!(get_env("ASHERAH_VERBOSE").as_deref(), Some("1"));
}

fn test_verbose_false() {
    let cfg = ConfigOptions {
        verbose: Some(false),
        ..base_config()
    };
    let applied = cfg.apply_env().unwrap();
    assert!(!applied.verbose);
    assert!(get_env("ASHERAH_VERBOSE").is_none());
}

fn test_session_caching_default_true() {
    let cfg = ConfigOptions {
        enable_session_caching: None,
        ..base_config()
    };
    let applied = cfg.apply_env().unwrap();
    assert!(applied.enable_session_caching);
    assert_eq!(get_env("SESSION_CACHE").as_deref(), Some("1"));
}

fn test_preferred_region_set() {
    let cfg = ConfigOptions {
        preferred_region: Some("us-west-2".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert_eq!(get_env("PREFERRED_REGION").as_deref(), Some("us-west-2"));
}

fn test_replica_read_consistency_set() {
    let cfg = ConfigOptions {
        replica_read_consistency: Some("eventual".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert_eq!(
        get_env("REPLICA_READ_CONSISTENCY").as_deref(),
        Some("eventual")
    );
}

fn test_kms_defaults_to_static() {
    let cfg = ConfigOptions {
        kms: None,
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert_eq!(get_env("KMS").as_deref(), Some("static"));
}

fn test_rdbms_go_mysql_dsn_with_tls() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("root:pass@tcp(localhost:3306)/testdb?tls=skip-verify".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    // Should be classified as MySQL and converted to mysql:// URL
    assert_eq!(
        get_env("MYSQL_URL").as_deref(),
        Some("mysql://root:pass@localhost:3306/testdb")
    );
    // Go tls parameter should be preserved as MYSQL_TLS_MODE
    assert_eq!(get_env("MYSQL_TLS_MODE").as_deref(), Some("skip-verify"));
    assert!(get_env("POSTGRES_URL").is_none());
    assert!(get_env("SQLITE_PATH").is_none());
}

fn test_rdbms_go_mysql_dsn_tls_true() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("root:pass@tcp(localhost:3306)/testdb?tls=true".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert!(get_env("MYSQL_URL").is_some());
    assert_eq!(get_env("MYSQL_TLS_MODE").as_deref(), Some("true"));
}

fn test_rdbms_go_mysql_dsn_no_tls() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("root:pass@tcp(localhost:3306)/testdb".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert!(get_env("MYSQL_URL").is_some());
    // No tls parameter in DSN → no MYSQL_TLS_MODE
    assert!(get_env("MYSQL_TLS_MODE").is_none());
}

fn test_rdbms_standard_mysql_url_no_tls_mode() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("mysql://root:pass@localhost:3306/testdb".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert_eq!(
        get_env("MYSQL_URL").as_deref(),
        Some("mysql://root:pass@localhost:3306/testdb")
    );
    // Standard mysql:// URL without tls param → no MYSQL_TLS_MODE
    assert!(get_env("MYSQL_TLS_MODE").is_none());
}

fn test_rdbms_sql_metastore_db_type_mysql() {
    // Connection string without mysql:// prefix, but SQLMetastoreDBType = "mysql"
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("root:pass@localhost:3306/testdb".into()),
        sql_metastore_db_type: Some("mysql".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert!(
        get_env("MYSQL_URL").is_some(),
        "Should be classified as MySQL via db type hint"
    );
    assert!(get_env("POSTGRES_URL").is_none());
}

fn test_rdbms_sql_metastore_db_type_postgres() {
    // Connection string without postgres:// prefix, but SQLMetastoreDBType = "postgres"
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("host=localhost dbname=testdb user=root".into()),
        sql_metastore_db_type: Some("postgres".into()),
        ..base_config()
    };
    let _applied = cfg.apply_env().unwrap();
    assert!(
        get_env("POSTGRES_URL").is_some(),
        "Should be classified as Postgres via db type hint"
    );
    assert!(get_env("MYSQL_URL").is_none());
}

fn test_customer_config_mysql_url_with_db_type_hint() {
    // Exact JSON a customer would pass to SetupJson — standard mysql:// URL with SQLMetastoreDBType hint
    let json = r#"{"ServiceName":"service","ProductID":"product","KMS":"static","Metastore":"rdbms","ConnectionString":"mysql://root:pass@localhost:3306/testdb","SQLMetastoreDBType":"mysql","EnableSessionCaching":true,"Verbose":true}"#;
    let cfg = ConfigOptions::from_json(json).unwrap();

    assert_eq!(cfg.service_name.as_deref(), Some("service"));
    assert_eq!(cfg.product_id.as_deref(), Some("product"));
    assert_eq!(cfg.kms.as_deref(), Some("static"));
    assert_eq!(cfg.metastore.as_deref(), Some("rdbms"));
    assert_eq!(
        cfg.connection_string.as_deref(),
        Some("mysql://root:pass@localhost:3306/testdb")
    );
    assert_eq!(cfg.sql_metastore_db_type.as_deref(), Some("mysql"));
    assert_eq!(cfg.enable_session_caching, Some(true));
    assert_eq!(cfg.verbose, Some(true));

    let applied = cfg.apply_env().unwrap();
    assert!(applied.verbose);
    assert!(applied.enable_session_caching);

    assert_eq!(get_env("SERVICE_NAME").as_deref(), Some("service"));
    assert_eq!(get_env("PRODUCT_ID").as_deref(), Some("product"));
    assert_eq!(get_env("KMS").as_deref(), Some("static"));
    assert_eq!(
        get_env("MYSQL_URL").as_deref(),
        Some("mysql://root:pass@localhost:3306/testdb")
    );
    assert!(
        get_env("POSTGRES_URL").is_none(),
        "mysql:// URL should not set POSTGRES_URL"
    );
    assert!(get_env("MYSQL_TLS_MODE").is_none());
    assert_eq!(get_env("SESSION_CACHE").as_deref(), Some("1"));
    assert_eq!(get_env("ASHERAH_VERBOSE").as_deref(), Some("1"));
}

fn test_customer_config_go_mysql_dsn_with_tls() {
    // Exact JSON a customer would pass to SetupJson — Go MySQL DSN format with tls=skip-verify
    let json = r#"{"ServiceName":"service","ProductID":"product","KMS":"static","Metastore":"rdbms","ConnectionString":"root:pass@tcp(localhost:3306)/testdb?tls=skip-verify","EnableSessionCaching":true,"Verbose":false}"#;
    let cfg = ConfigOptions::from_json(json).unwrap();

    assert_eq!(cfg.service_name.as_deref(), Some("service"));
    assert_eq!(cfg.product_id.as_deref(), Some("product"));
    assert_eq!(cfg.kms.as_deref(), Some("static"));
    assert_eq!(cfg.metastore.as_deref(), Some("rdbms"));
    assert_eq!(
        cfg.connection_string.as_deref(),
        Some("root:pass@tcp(localhost:3306)/testdb?tls=skip-verify")
    );
    assert_eq!(cfg.sql_metastore_db_type, None);
    assert_eq!(cfg.enable_session_caching, Some(true));
    assert_eq!(cfg.verbose, Some(false));

    let applied = cfg.apply_env().unwrap();
    assert!(!applied.verbose);
    assert!(applied.enable_session_caching);

    assert_eq!(get_env("SERVICE_NAME").as_deref(), Some("service"));
    assert_eq!(get_env("PRODUCT_ID").as_deref(), Some("product"));
    assert_eq!(get_env("KMS").as_deref(), Some("static"));
    // Go DSN should be converted to mysql:// URL
    assert_eq!(
        get_env("MYSQL_URL").as_deref(),
        Some("mysql://root:pass@localhost:3306/testdb")
    );
    assert!(
        get_env("POSTGRES_URL").is_none(),
        "Go MySQL DSN should not set POSTGRES_URL"
    );
    // tls=skip-verify should be extracted as MYSQL_TLS_MODE
    assert_eq!(get_env("MYSQL_TLS_MODE").as_deref(), Some("skip-verify"));
    assert_eq!(get_env("SESSION_CACHE").as_deref(), Some("1"));
    assert!(get_env("ASHERAH_VERBOSE").is_none());
}

fn test_memory_metastore_clears_mysql_tls_mode() {
    // First set up MySQL with TLS
    let cfg1 = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("root:pass@tcp(localhost:3306)/testdb?tls=skip-verify".into()),
        ..base_config()
    };
    let _applied1 = cfg1.apply_env().unwrap();
    assert_eq!(get_env("MYSQL_TLS_MODE").as_deref(), Some("skip-verify"));

    // Switch to memory — MYSQL_TLS_MODE should be cleared
    let cfg2 = base_config();
    let _applied2 = cfg2.apply_env().unwrap();
    assert!(
        get_env("MYSQL_TLS_MODE").is_none(),
        "Memory metastore should clear MYSQL_TLS_MODE"
    );
}

// ============================================================================
// Main — runs all tests sequentially (harness=false)
// ============================================================================

fn run_test(name: &str, f: fn()) {
    print!("test {} ... ", name);
    f();
    println!("ok");
}

fn main() {
    run_test("test_from_json_valid", test_from_json_valid);
    run_test("test_from_json_invalid", test_from_json_invalid);
    run_test("test_from_json_all_fields", test_from_json_all_fields);
    run_test("test_missing_service_name", test_missing_service_name);
    run_test("test_missing_product_id", test_missing_product_id);
    run_test("test_missing_metastore", test_missing_metastore);
    run_test("test_unsupported_metastore", test_unsupported_metastore);
    run_test(
        "test_memory_metastore_sets_env",
        test_memory_metastore_sets_env,
    );
    run_test(
        "test_sqlite_metastore_with_connection_string",
        test_sqlite_metastore_with_connection_string,
    );
    run_test(
        "test_sqlite_metastore_strips_prefix",
        test_sqlite_metastore_strips_prefix,
    );
    run_test(
        "test_sqlite_metastore_missing_connection_string",
        test_sqlite_metastore_missing_connection_string,
    );
    run_test("test_rdbms_postgres", test_rdbms_postgres);
    run_test("test_rdbms_mysql", test_rdbms_mysql);
    run_test(
        "test_rdbms_missing_connection_string",
        test_rdbms_missing_connection_string,
    );
    run_test("test_dynamodb_metastore", test_dynamodb_metastore);
    run_test(
        "test_normalize_alias_test_debug_memory",
        test_normalize_alias_test_debug_memory,
    );
    run_test(
        "test_normalize_alias_test_debug_sqlite",
        test_normalize_alias_test_debug_sqlite,
    );
    run_test("test_optional_int_fields_set", test_optional_int_fields_set);
    run_test(
        "test_optional_int_fields_none_clears_env",
        test_optional_int_fields_none_clears_env,
    );
    run_test(
        "test_sequential_factory_builds_isolated",
        test_sequential_factory_builds_isolated,
    );
    run_test("test_region_map_set", test_region_map_set);
    run_test("test_region_map_none", test_region_map_none);
    run_test("test_verbose_true", test_verbose_true);
    run_test("test_verbose_false", test_verbose_false);
    run_test(
        "test_session_caching_default_true",
        test_session_caching_default_true,
    );
    run_test("test_preferred_region_set", test_preferred_region_set);
    run_test(
        "test_replica_read_consistency_set",
        test_replica_read_consistency_set,
    );
    run_test("test_kms_defaults_to_static", test_kms_defaults_to_static);
    run_test(
        "test_rdbms_go_mysql_dsn_with_tls",
        test_rdbms_go_mysql_dsn_with_tls,
    );
    run_test(
        "test_rdbms_go_mysql_dsn_tls_true",
        test_rdbms_go_mysql_dsn_tls_true,
    );
    run_test(
        "test_rdbms_go_mysql_dsn_no_tls",
        test_rdbms_go_mysql_dsn_no_tls,
    );
    run_test(
        "test_rdbms_standard_mysql_url_no_tls_mode",
        test_rdbms_standard_mysql_url_no_tls_mode,
    );
    run_test(
        "test_rdbms_sql_metastore_db_type_mysql",
        test_rdbms_sql_metastore_db_type_mysql,
    );
    run_test(
        "test_rdbms_sql_metastore_db_type_postgres",
        test_rdbms_sql_metastore_db_type_postgres,
    );
    run_test(
        "test_customer_config_mysql_url_with_db_type_hint",
        test_customer_config_mysql_url_with_db_type_hint,
    );
    run_test(
        "test_customer_config_go_mysql_dsn_with_tls",
        test_customer_config_go_mysql_dsn_with_tls,
    );
    run_test(
        "test_memory_metastore_clears_mysql_tls_mode",
        test_memory_metastore_clears_mysql_tls_mode,
    );

    println!("\ntest result: ok. 37 passed; 0 failed");
}
