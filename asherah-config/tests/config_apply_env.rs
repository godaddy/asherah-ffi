#![allow(clippy::unwrap_used, clippy::print_stdout, clippy::panic)]
//! Tests for ConfigOptions::resolve() — produces ResolvedConfig without env side effects.
//!
//! Since resolve() has no env var side effects, tests can run in parallel.

use asherah::builders::{KmsConfig, MetastoreConfig, ResolvedConfig};
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

fn resolve(cfg: &ConfigOptions) -> ResolvedConfig {
    cfg.resolve().unwrap().0
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
    assert!(cfg.resolve().is_err());
}

fn test_missing_product_id() {
    let cfg = ConfigOptions {
        service_name: Some("svc".into()),
        product_id: None,
        metastore: Some("memory".into()),
        ..Default::default()
    };
    assert!(cfg.resolve().is_err());
}

fn test_missing_metastore() {
    let cfg = ConfigOptions {
        service_name: Some("svc".into()),
        product_id: Some("prod".into()),
        metastore: None,
        ..Default::default()
    };
    assert!(cfg.resolve().is_err());
}

fn test_unsupported_metastore() {
    let cfg = ConfigOptions {
        service_name: Some("svc".into()),
        product_id: Some("prod".into()),
        metastore: Some("redis".into()),
        ..Default::default()
    };
    assert!(cfg.resolve().is_err());
}

fn test_resolve_basic() {
    let resolved = resolve(&base_config());
    assert_eq!(resolved.service_name, "test-svc");
    assert_eq!(resolved.product_id, "test-prod");
    assert!(matches!(resolved.metastore, MetastoreConfig::Memory));
    assert!(matches!(resolved.kms, KmsConfig::Static { .. }));
}

fn test_sqlite_metastore_with_connection_string() {
    let cfg = ConfigOptions {
        metastore: Some("sqlite".into()),
        connection_string: Some("/tmp/test.db".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Sqlite { path } => assert_eq!(path, "/tmp/test.db"),
        other => panic!("expected Sqlite, got {other:?}"),
    }
}

fn test_sqlite_metastore_strips_prefix() {
    let cfg = ConfigOptions {
        metastore: Some("sqlite".into()),
        connection_string: Some("sqlite:///tmp/prefixed.db".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Sqlite { path } => assert_eq!(path, "/tmp/prefixed.db"),
        other => panic!("expected Sqlite, got {other:?}"),
    }
}

fn test_sqlite_metastore_missing_connection_string() {
    let cfg = ConfigOptions {
        metastore: Some("sqlite".into()),
        connection_string: None,
        ..base_config()
    };
    assert!(cfg.resolve().is_err());
}

fn test_rdbms_postgres() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("postgres://user:pass@localhost/db".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Postgres { url, .. } => {
            assert_eq!(url, "postgres://user:pass@localhost/db")
        }
        other => panic!("expected Postgres, got {other:?}"),
    }
}

fn test_rdbms_mysql() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("mysql://user:pass@localhost/db".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Mysql { url, .. } => assert_eq!(url, "mysql://user:pass@localhost/db"),
        other => panic!("expected Mysql, got {other:?}"),
    }
}

fn test_rdbms_missing_connection_string() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: None,
        ..base_config()
    };
    assert!(cfg.resolve().is_err());
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
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::DynamoDb {
            table,
            region,
            endpoint,
            region_suffix,
        } => {
            assert_eq!(table, "my-table");
            assert_eq!(region.as_deref(), Some("eu-west-1"));
            assert_eq!(endpoint.as_deref(), Some("http://localhost:8000"));
            assert!(*region_suffix);
        }
        other => panic!("expected DynamoDb, got {other:?}"),
    }
}

fn test_normalize_alias_test_debug_memory() {
    let cfg = ConfigOptions {
        metastore: Some("test-debug-memory".into()),
        kms: Some("test-debug-static".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    assert!(matches!(resolved.metastore, MetastoreConfig::Memory));
    assert!(matches!(resolved.kms, KmsConfig::Static { .. }));
}

fn test_normalize_alias_test_debug_sqlite() {
    let cfg = ConfigOptions {
        metastore: Some("test-debug-sqlite".into()),
        connection_string: Some("/tmp/debug.db".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    assert!(matches!(resolved.metastore, MetastoreConfig::Sqlite { .. }));
}

fn test_optional_int_fields_set() {
    let cfg = ConfigOptions {
        expire_after: Some(7200),
        check_interval: Some(120),
        session_cache_duration: Some(600),
        session_cache_max_size: Some(50),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    assert_eq!(resolved.policy.expire_key_after_s, Some(7200));
    assert_eq!(resolved.policy.revoke_check_interval_s, Some(120));
    assert_eq!(resolved.policy.session_cache_ttl_s, Some(600));
    assert_eq!(resolved.policy.session_cache_max_size, Some(50));
}

fn test_optional_int_fields_none_produces_none() {
    let cfg = ConfigOptions {
        expire_after: None,
        check_interval: None,
        session_cache_duration: None,
        session_cache_max_size: None,
        ..base_config()
    };
    let resolved = resolve(&cfg);
    assert_eq!(resolved.policy.expire_key_after_s, None);
    assert_eq!(resolved.policy.revoke_check_interval_s, None);
    assert_eq!(resolved.policy.session_cache_ttl_s, None);
    assert_eq!(resolved.policy.session_cache_max_size, None);
}

fn test_sequential_resolves_are_isolated() {
    // First resolve with explicit policy fields
    let cfg_a = ConfigOptions {
        expire_after: Some(7200),
        check_interval: Some(120),
        preferred_region: Some("us-east-1".into()),
        pool_max_open: Some(50),
        ..base_config()
    };
    let resolved_a = resolve(&cfg_a);
    assert_eq!(resolved_a.policy.expire_key_after_s, Some(7200));

    // Second resolve with None fields — must not inherit from first
    let cfg_b = ConfigOptions {
        expire_after: None,
        check_interval: None,
        preferred_region: None,
        pool_max_open: None,
        ..base_config()
    };
    let resolved_b = resolve(&cfg_b);
    assert_eq!(resolved_b.policy.expire_key_after_s, None);
    assert_eq!(resolved_b.policy.revoke_check_interval_s, None);
}

fn test_region_map_set() {
    let mut map = HashMap::new();
    map.insert(
        "us-east-1".to_string(),
        "arn:aws:kms:us-east-1:123:key/abc".to_string(),
    );
    let cfg = ConfigOptions {
        kms: Some("aws".into()),
        region_map: Some(map.clone()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.kms {
        KmsConfig::Aws { region_map, .. } => {
            assert_eq!(region_map.as_ref().unwrap(), &map);
        }
        other => panic!("expected Aws, got {other:?}"),
    }
}

fn test_region_map_none() {
    let cfg = ConfigOptions {
        kms: Some("aws".into()),
        region_map: None,
        kms_key_id: Some("key-123".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.kms {
        KmsConfig::Aws {
            region_map, key_id, ..
        } => {
            assert!(region_map.is_none());
            assert_eq!(key_id.as_deref(), Some("key-123"));
        }
        other => panic!("expected Aws, got {other:?}"),
    }
}

fn test_verbose_true() {
    let cfg = ConfigOptions {
        verbose: Some(true),
        ..base_config()
    };
    let (_, applied) = cfg.resolve().unwrap();
    assert!(applied.verbose);
}

fn test_verbose_false() {
    let cfg = ConfigOptions {
        verbose: Some(false),
        ..base_config()
    };
    let (_, applied) = cfg.resolve().unwrap();
    assert!(!applied.verbose);
}

fn test_session_caching_default_true() {
    let cfg = ConfigOptions {
        enable_session_caching: None,
        ..base_config()
    };
    let (_, applied) = cfg.resolve().unwrap();
    assert!(applied.enable_session_caching);
}

fn test_preferred_region_set() {
    let cfg = ConfigOptions {
        kms: Some("aws".into()),
        preferred_region: Some("us-west-2".into()),
        kms_key_id: Some("key-123".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.kms {
        KmsConfig::Aws {
            preferred_region, ..
        } => {
            assert_eq!(preferred_region.as_deref(), Some("us-west-2"));
        }
        other => panic!("expected Aws, got {other:?}"),
    }
}

fn test_replica_read_consistency_set() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("postgres://user:pass@localhost/db".into()),
        replica_read_consistency: Some("eventual".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Postgres {
            replica_consistency,
            ..
        } => {
            assert_eq!(replica_consistency.as_deref(), Some("eventual"));
        }
        other => panic!("expected Postgres, got {other:?}"),
    }
}

fn test_kms_defaults_to_static() {
    let cfg = ConfigOptions {
        kms: None,
        ..base_config()
    };
    let resolved = resolve(&cfg);
    assert!(matches!(resolved.kms, KmsConfig::Static { .. }));
}

fn test_rdbms_go_mysql_dsn_with_tls() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("root:pass@tcp(localhost:3306)/testdb?tls=skip-verify".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Mysql { url, tls_mode, .. } => {
            assert!(url.starts_with("mysql://"));
            assert_eq!(tls_mode.as_deref(), Some("skip-verify"));
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

fn test_rdbms_go_mysql_dsn_tls_true() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("root:pass@tcp(localhost:3306)/testdb?tls=true".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Mysql { tls_mode, .. } => {
            assert_eq!(tls_mode.as_deref(), Some("true"));
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

fn test_rdbms_go_mysql_dsn_no_tls() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("root:pass@tcp(localhost:3306)/testdb".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Mysql { tls_mode, .. } => {
            assert!(tls_mode.is_none());
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

fn test_rdbms_standard_mysql_url_no_tls_mode() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("mysql://root:pass@localhost:3306/testdb".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Mysql { url, tls_mode, .. } => {
            assert_eq!(url, "mysql://root:pass@localhost:3306/testdb");
            assert!(tls_mode.is_none());
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

fn test_rdbms_sql_metastore_db_type_mysql() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("root:pass@localhost:3306/testdb".into()),
        sql_metastore_db_type: Some("mysql".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Mysql { url, .. } => {
            assert!(url.starts_with("mysql://"));
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

fn test_rdbms_sql_metastore_db_type_postgres() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("host=localhost dbname=testdb user=root".into()),
        sql_metastore_db_type: Some("postgres".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Postgres { url, .. } => {
            assert!(url.starts_with("postgres://"));
        }
        other => panic!("expected Postgres, got {other:?}"),
    }
}

fn test_pool_config_passed_through() {
    let cfg = ConfigOptions {
        metastore: Some("rdbms".into()),
        connection_string: Some("mysql://root:pass@localhost/db".into()),
        pool_max_open: Some(50),
        pool_max_idle: Some(10),
        pool_max_lifetime: Some(3600),
        pool_max_idle_time: Some(600),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.metastore {
        MetastoreConfig::Mysql { pool, .. } => {
            assert_eq!(pool.max_open, Some(50));
            assert_eq!(pool.max_idle, Some(10));
            assert_eq!(pool.max_lifetime_s, Some(3600));
            assert_eq!(pool.max_idle_time_s, Some(600));
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

fn test_static_master_key_hex() {
    let cfg = ConfigOptions {
        kms: Some("static".into()),
        static_master_key_hex: Some("aabbccdd".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);
    match &resolved.kms {
        KmsConfig::Static { key_hex } => assert_eq!(key_hex, "aabbccdd"),
        other => panic!("expected Static, got {other:?}"),
    }
}

fn test_no_env_side_effects() {
    // Set some env vars that apply_env used to write
    let sentinel = format!("sentinel-{}", std::process::id());
    std::env::set_var("SERVICE_NAME", &sentinel);

    let cfg = ConfigOptions {
        service_name: Some("different-svc".into()),
        ..base_config()
    };
    let resolved = resolve(&cfg);

    // resolve() must not have changed the env var
    assert_eq!(std::env::var("SERVICE_NAME").unwrap(), sentinel);
    // But the resolved config should have the new value
    assert_eq!(resolved.service_name, "different-svc");

    std::env::remove_var("SERVICE_NAME");
}

fn test_concurrent_resolves_are_safe() {
    // Defect #12: factory_from_config_async must be concurrency-safe.
    // With env transport eliminated, concurrent resolves must not interfere.
    let handles: Vec<_> = (0..10)
        .map(|i| {
            std::thread::spawn(move || {
                let cfg = ConfigOptions {
                    service_name: Some(format!("concurrent-svc-{i}")),
                    ..base_config()
                };
                let resolved = resolve(&cfg);
                assert_eq!(
                    resolved.service_name,
                    format!("concurrent-svc-{i}"),
                    "thread {i} got wrong service_name"
                );
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

// ============================================================================
// Test runner (harness=false)
// ============================================================================

fn main() {
    let mut pass = 0;
    let mut fail = 0;

    macro_rules! run_test {
        ($name:expr, $func:expr) => {
            print!("test {} ... ", $name);
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $func())) {
                Ok(()) => {
                    println!("ok");
                    pass += 1;
                }
                Err(e) => {
                    let msg = e
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| e.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".to_string());
                    println!("FAILED: {msg}");
                    fail += 1;
                }
            }
        };
    }

    run_test!("test_from_json_valid", test_from_json_valid);
    run_test!("test_from_json_invalid", test_from_json_invalid);
    run_test!("test_from_json_all_fields", test_from_json_all_fields);
    run_test!("test_missing_service_name", test_missing_service_name);
    run_test!("test_missing_product_id", test_missing_product_id);
    run_test!("test_missing_metastore", test_missing_metastore);
    run_test!("test_unsupported_metastore", test_unsupported_metastore);
    run_test!("test_resolve_basic", test_resolve_basic);
    run_test!(
        "test_sqlite_metastore_with_connection_string",
        test_sqlite_metastore_with_connection_string
    );
    run_test!(
        "test_sqlite_metastore_strips_prefix",
        test_sqlite_metastore_strips_prefix
    );
    run_test!(
        "test_sqlite_metastore_missing_connection_string",
        test_sqlite_metastore_missing_connection_string
    );
    run_test!("test_rdbms_postgres", test_rdbms_postgres);
    run_test!("test_rdbms_mysql", test_rdbms_mysql);
    run_test!(
        "test_rdbms_missing_connection_string",
        test_rdbms_missing_connection_string
    );
    run_test!("test_dynamodb_metastore", test_dynamodb_metastore);
    run_test!(
        "test_normalize_alias_test_debug_memory",
        test_normalize_alias_test_debug_memory
    );
    run_test!(
        "test_normalize_alias_test_debug_sqlite",
        test_normalize_alias_test_debug_sqlite
    );
    run_test!("test_optional_int_fields_set", test_optional_int_fields_set);
    run_test!(
        "test_optional_int_fields_none_produces_none",
        test_optional_int_fields_none_produces_none
    );
    run_test!(
        "test_sequential_resolves_are_isolated",
        test_sequential_resolves_are_isolated
    );
    run_test!("test_region_map_set", test_region_map_set);
    run_test!("test_region_map_none", test_region_map_none);
    run_test!("test_verbose_true", test_verbose_true);
    run_test!("test_verbose_false", test_verbose_false);
    run_test!(
        "test_session_caching_default_true",
        test_session_caching_default_true
    );
    run_test!("test_preferred_region_set", test_preferred_region_set);
    run_test!(
        "test_replica_read_consistency_set",
        test_replica_read_consistency_set
    );
    run_test!("test_kms_defaults_to_static", test_kms_defaults_to_static);
    run_test!(
        "test_rdbms_go_mysql_dsn_with_tls",
        test_rdbms_go_mysql_dsn_with_tls
    );
    run_test!(
        "test_rdbms_go_mysql_dsn_tls_true",
        test_rdbms_go_mysql_dsn_tls_true
    );
    run_test!(
        "test_rdbms_go_mysql_dsn_no_tls",
        test_rdbms_go_mysql_dsn_no_tls
    );
    run_test!(
        "test_rdbms_standard_mysql_url_no_tls_mode",
        test_rdbms_standard_mysql_url_no_tls_mode
    );
    run_test!(
        "test_rdbms_sql_metastore_db_type_mysql",
        test_rdbms_sql_metastore_db_type_mysql
    );
    run_test!(
        "test_rdbms_sql_metastore_db_type_postgres",
        test_rdbms_sql_metastore_db_type_postgres
    );
    run_test!(
        "test_pool_config_passed_through",
        test_pool_config_passed_through
    );
    run_test!("test_static_master_key_hex", test_static_master_key_hex);
    run_test!("test_no_env_side_effects", test_no_env_side_effects);
    run_test!(
        "test_concurrent_resolves_are_safe",
        test_concurrent_resolves_are_safe
    );

    println!("\ntest result: ok. {pass} passed; {fail} failed");
    if fail > 0 {
        std::process::exit(1);
    }
}
