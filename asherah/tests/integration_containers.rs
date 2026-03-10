#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic
)]
//! Integration tests using testcontainers to spin up real MySQL, Postgres,
//! DynamoDB (via LocalStack), and KMS (via LocalStack) instances.
//!
//! These tests require Docker to be available. They are gated behind
//! feature flags (mysql, postgres, dynamodb) and will be skipped in
//! environments without Docker.
//!
//! The metastore and KMS constructors internally create their own tokio
//! runtimes, so all calls to them must happen on a blocking thread via
//! `spawn_blocking` to avoid "cannot start a runtime from within a runtime".
//!
//! The AWS SDK clients read `AWS_ENDPOINT_URL` at construction time. Since
//! env vars are process-global, we use `ENV_MUTEX` to serialize the
//! set_var → construct → (done reading) sequence across concurrent tests.

use std::sync::{Arc, Mutex};

static ENV_MUTEX: Mutex<()> = Mutex::new(());

use asherah::traits::{KeyManagementService, Metastore};
use asherah::types::{EnvelopeKeyRecord, KeyMeta};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use testcontainers_modules::{localstack::LocalStack, postgres::Postgres};

/// Helper: create a KMS key in LocalStack and return its key ID.
async fn create_kms_key(endpoint: &str) -> String {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::meta::region::RegionProviderChain::first_try(
            aws_sdk_kms::config::Region::new("us-east-1"),
        ))
        .load()
        .await;

    let kms_config = aws_sdk_kms::config::Builder::from(&config)
        .endpoint_url(endpoint)
        .build();

    let kms_client = aws_sdk_kms::Client::from_conf(kms_config);

    let key_resp = kms_client
        .create_key()
        .key_usage(aws_sdk_kms::types::KeyUsageType::EncryptDecrypt)
        .send()
        .await
        .unwrap();

    key_resp.key_metadata().unwrap().key_id().to_string()
}

/// Set `AWS_ENDPOINT_URL` and run a closure while holding the env mutex.
/// This prevents concurrent tests from clobbering the endpoint while
/// another test's AWS SDK client constructor is reading it. The mutex must
/// cover both the `set_var` and ALL client constructors (KMS, DynamoDB)
/// that read it.
fn with_endpoint<T>(endpoint: &str, f: impl FnOnce() -> T) -> T {
    let _guard = ENV_MUTEX.lock().unwrap();
    std::env::set_var("AWS_ENDPOINT_URL", endpoint);
    f()
}

/// Connect to MySQL with retries, returning the connected metastore.
fn connect_mysql_with_retries(url: &str) -> asherah::metastore_mysql::MySqlMetastore {
    let mut last_err = None;
    for _ in 0..30 {
        match asherah::metastore_mysql::MySqlMetastore::connect(url) {
            Ok(store) => return store,
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
    panic!(
        "MySQL connection failed after retries: {}",
        last_err.unwrap()
    );
}

/// Run the standard metastore contract tests against any Metastore impl.
fn run_contract<M: Metastore>(store: &M) {
    let ekr1 = EnvelopeKeyRecord {
        revoked: Some(false),
        id: "id1".into(),
        created: 100,
        encrypted_key: vec![1, 2, 3],
        parent_key_meta: Some(KeyMeta {
            id: "parent".into(),
            created: 10,
        }),
    };

    // First insert succeeds
    assert!(store.store(&ekr1.id, ekr1.created, &ekr1).unwrap());
    // Duplicate insert returns false
    assert!(!store.store(&ekr1.id, ekr1.created, &ekr1).unwrap());

    // Load returns equivalent record
    let got = store.load(&ekr1.id, ekr1.created).unwrap().unwrap();
    assert_eq!(got.created, ekr1.created);
    assert_eq!(got.revoked, ekr1.revoked);
    assert_eq!(got.parent_key_meta, ekr1.parent_key_meta);
    assert_eq!(got.encrypted_key, ekr1.encrypted_key);

    // load_latest returns highest created
    let ekr2 = EnvelopeKeyRecord {
        created: 200,
        ..ekr1.clone()
    };
    assert!(store.store(&ekr2.id, ekr2.created, &ekr2).unwrap());
    let latest = store.load_latest(&ekr2.id).unwrap().unwrap();
    assert_eq!(latest.created, 200);

    // load non-existent returns None
    assert!(store.load("nonexistent", 999).unwrap().is_none());
    assert!(store.load_latest("nonexistent").unwrap().is_none());
}

/// Start a MySQL container and return (container, connection_url).
/// Retries up to 3 times to work around transient Docker port-exposure issues.
async fn start_mysql() -> Option<(ContainerAsync<GenericImage>, String)> {
    for attempt in 0..3 {
        let container = match GenericImage::new("mysql", "8.1")
            .with_exposed_port(3306.tcp())
            .with_wait_for(WaitFor::message_on_stderr("port: 3306"))
            .with_env_var("MYSQL_DATABASE", "test")
            .with_env_var("MYSQL_ALLOW_EMPTY_PASSWORD", "yes")
            .with_startup_timeout(std::time::Duration::from_secs(120))
            .start()
            .await
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping MySQL test (Docker unavailable?): {e}");
                return None;
            }
        };
        // Use 127.0.0.1 — on macOS, `localhost` may resolve to IPv6 which
        // Docker Desktop doesn't always forward correctly
        match container.get_host_port_ipv4(3306).await {
            Ok(port) => {
                let url = format!("mysql://root@127.0.0.1:{port}/test");
                return Some((container, url));
            }
            Err(e) => {
                eprintln!("MySQL get_host_port_ipv4 failed (attempt {attempt}): {e}");
                continue;
            }
        }
    }
    eprintln!("skipping MySQL test: port retrieval failed after 3 attempts");
    None
}

/// Start a Postgres container and return (container, connection_string).
/// Retries up to 3 times to work around transient Docker port-exposure issues.
async fn start_postgres() -> Option<(ContainerAsync<Postgres>, String)> {
    for attempt in 0..3 {
        let container = match Postgres::default().start().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping Postgres test (Docker unavailable?): {e}");
                return None;
            }
        };
        match container.get_host_port_ipv4(5432).await {
            Ok(port) => {
                let url = format!(
                    "host=127.0.0.1 port={port} user=postgres password=postgres dbname=postgres"
                );
                return Some((container, url));
            }
            Err(e) => {
                eprintln!("Postgres get_host_port_ipv4 failed (attempt {attempt}): {e}");
                continue;
            }
        }
    }
    eprintln!("skipping Postgres test: port retrieval failed after 3 attempts");
    None
}

// ──────────────────────────── MySQL ────────────────────────────

#[tokio::test]
async fn mysql_metastore_contract() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        run_contract(&store);
    })
    .await
    .unwrap();
}

// ──────────────────────────── Postgres ────────────────────────────

#[tokio::test]
async fn postgres_metastore_contract() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        run_contract(&store);
    })
    .await
    .unwrap();
}

// ──────────────────────────── DynamoDB via LocalStack ────────────────────────────

async fn start_localstack() -> Result<ContainerAsync<LocalStack>, String> {
    LocalStack::default()
        .start()
        .await
        .map_err(|e| format!("Docker unavailable?: {e}"))
}

/// Start LocalStack, set AWS credentials, and return (container, endpoint).
/// Retries up to 3 times to work around transient Docker/testcontainers issues.
async fn start_localstack_with_creds() -> Option<(ContainerAsync<LocalStack>, String)> {
    std::env::set_var("AWS_ACCESS_KEY_ID", "test");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");

    for attempt in 0..3 {
        let container = match start_localstack().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping LocalStack test: {e}");
                return None;
            }
        };

        let host = match container.get_host().await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("LocalStack get_host failed (attempt {attempt}): {e}");
                continue;
            }
        };
        let port = match container.get_host_port_ipv4(4566).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("LocalStack get_host_port_ipv4 failed (attempt {attempt}): {e}");
                continue;
            }
        };
        let endpoint = format!("http://{host}:{port}");
        return Some((container, endpoint));
    }

    eprintln!("skipping LocalStack test: failed after 3 attempts");
    None
}

async fn create_dynamodb_table(endpoint: &str, table: &str) {
    use aws_sdk_dynamodb::types::{
        AttributeDefinition, KeySchemaElement, KeyType, ScalarAttributeType,
    };

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::meta::region::RegionProviderChain::first_try(
            aws_sdk_dynamodb::config::Region::new("us-east-1"),
        ))
        .load()
        .await;

    let ddb_config = aws_sdk_dynamodb::config::Builder::from(&config)
        .endpoint_url(endpoint)
        .build();

    let client = aws_sdk_dynamodb::Client::from_conf(ddb_config);

    client
        .create_table()
        .table_name(table)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("Id")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("Created")
                .attribute_type(ScalarAttributeType::N)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("Id")
                .key_type(KeyType::Hash)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("Created")
                .key_type(KeyType::Range)
                .build()
                .unwrap(),
        )
        .billing_mode(aws_sdk_dynamodb::types::BillingMode::PayPerRequest)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn dynamodb_metastore_contract() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKey";

    create_dynamodb_table(&endpoint, table).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let store = with_endpoint(&endpoint_clone, || {
            asherah::metastore_dynamodb::DynamoDbMetastore::new(table, Some("us-east-1".into()))
                .unwrap()
        });

        run_contract(&store);
    })
    .await
    .unwrap();
}

// ──────────────────────────── KMS via LocalStack ────────────────────────────

#[tokio::test]
async fn kms_envelope_roundtrip() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };

    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let kms = with_endpoint(&endpoint_clone, || {
            let aead = Arc::new(asherah::aead::AES256GCM::new());
            asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                aead,
                key_id,
                Some("us-east-1".into()),
            )
            .unwrap()
        });

        let original_key = b"this-is-a-32-byte-test-key!!1234";
        let encrypted = kms.encrypt_key(&(), original_key).unwrap();
        let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();

        assert_eq!(decrypted, original_key);
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Full-stack end-to-end tests: SessionFactory → real backend → encrypt → decrypt
// ════════════════════════════════════════════════════════════════

/// End-to-end: MySQL metastore + StaticKMS → SessionFactory → encrypt → decrypt
#[tokio::test]
async fn mysql_full_stack_roundtrip() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![1_u8; 32]).unwrap());
        let cfg = asherah::Config::new("integration-svc", "integration-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("mysql-e2e");

        let plaintext = b"end-to-end mysql test payload";
        let drr = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(drr).unwrap();
        assert_eq!(decrypted, plaintext);
    })
    .await
    .unwrap();
}

/// End-to-end: Postgres metastore + StaticKMS → SessionFactory → encrypt → decrypt
#[tokio::test]
async fn postgres_full_stack_roundtrip() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![2_u8; 32]).unwrap());
        let cfg = asherah::Config::new("integration-svc", "integration-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("pg-e2e");

        let plaintext = b"end-to-end postgres test payload";
        let drr = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(drr).unwrap();
        assert_eq!(decrypted, plaintext);
    })
    .await
    .unwrap();
}

/// End-to-end: DynamoDB metastore + KMS envelope → SessionFactory → encrypt → decrypt
/// This is the most realistic test — both metastore and KMS backed by LocalStack.
#[tokio::test]
async fn dynamodb_kms_full_stack_roundtrip() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyE2E";

    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (kms, store, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (kms, store, crypto)
        });
        let cfg = asherah::Config::new("integration-svc", "integration-prod");
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let session = factory.get_session("ddb-kms-e2e");

        let plaintext = b"end-to-end dynamodb + kms test payload";
        let drr = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(drr).unwrap();
        assert_eq!(decrypted, plaintext);

        // Encrypt again with different partition — should still decrypt
        let session2 = factory.get_session("ddb-kms-e2e-2");
        let drr2 = session2.encrypt(b"partition two").unwrap();
        let out2 = session2.decrypt(drr2).unwrap();
        assert_eq!(out2, b"partition two");
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Multi-region KMS via LocalStack
// ════════════════════════════════════════════════════════════════

/// Multi-region KMS envelope: create two keys, encrypt with preferred, decrypt with either.
#[tokio::test]
async fn kms_multi_region_envelope() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };

    // Create two KMS keys (simulating two regions — LocalStack ignores region
    // but the envelope logic routes by region label)
    let key_id_1 = create_kms_key(&endpoint).await;
    let key_id_2 = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let kms = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            // Build multi-region envelope with us-east-1 preferred
            asherah::kms_aws_envelope::AwsKmsEnvelope::new_multi(
                crypto.clone(),
                0, // preferred index
                vec![
                    ("us-east-1".into(), key_id_1),
                    ("us-east-1".into(), key_id_2), // same region endpoint, different key
                ],
            )
            .unwrap()
        });

        let original_key = b"multi-region-32-byte-test-key!!!";
        let encrypted = kms.encrypt_key(&(), original_key).unwrap();

        // Verify the envelope contains keks for both keys
        let env: serde_json::Value = serde_json::from_slice(&encrypted).unwrap();
        let keks = env["kmsKeks"].as_array().unwrap();
        assert_eq!(keks.len(), 2, "expected KEKs for both regions");

        // Decrypt succeeds
        let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();
        assert_eq!(decrypted, original_key);
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Concurrent access against real databases
// ════════════════════════════════════════════════════════════════

/// Concurrent encrypt/decrypt against MySQL-backed SessionFactory.
#[tokio::test]
async fn mysql_concurrent_roundtrip() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![3_u8; 32]).unwrap());
        let cfg = asherah::Config::new("concurrent-svc", "concurrent-prod");
        let factory = Arc::new(asherah::api::new_session_factory(
            cfg,
            Arc::new(store),
            kms,
            crypto,
        ));

        let mut handles = vec![];
        for i in 0..8 {
            let f = factory.clone();
            handles.push(std::thread::spawn(move || {
                let session = f.get_session(&format!("mysql-concurrent-{i}"));
                let msg = format!("concurrent payload {i}");
                let drr = session.encrypt(msg.as_bytes()).unwrap();
                let out = session.decrypt(drr).unwrap();
                assert_eq!(out, msg.as_bytes());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    })
    .await
    .unwrap();
}

/// Concurrent encrypt/decrypt against Postgres-backed SessionFactory.
#[tokio::test]
async fn postgres_concurrent_roundtrip() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![4_u8; 32]).unwrap());
        let cfg = asherah::Config::new("concurrent-svc", "concurrent-prod");
        let factory = Arc::new(asherah::api::new_session_factory(
            cfg,
            Arc::new(store),
            kms,
            crypto,
        ));

        let mut handles = vec![];
        for i in 0..8 {
            let f = factory.clone();
            handles.push(std::thread::spawn(move || {
                let session = f.get_session(&format!("pg-concurrent-{i}"));
                let msg = format!("concurrent payload {i}");
                let drr = session.encrypt(msg.as_bytes()).unwrap();
                let out = session.decrypt(drr).unwrap();
                assert_eq!(out, msg.as_bytes());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Key rotation against real backends
// ════════════════════════════════════════════════════════════════

/// Key rotation: expire keys after 1s, verify new IK is created against Postgres.
#[tokio::test]
async fn postgres_key_rotation() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![5_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("rotation-svc", "rotation-prod");
        cfg.policy.expire_key_after_s = 1;
        cfg.policy.create_date_precision_s = 1;
        cfg.policy.revoke_check_interval_s = 1;

        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("pg-rotation");

        // First encrypt
        let drr1 = session.encrypt(b"before rotation").unwrap();
        let ik_created_1 = drr1
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;

        // Wait for key expiration
        std::thread::sleep(std::time::Duration::from_millis(1200));

        // Second encrypt should use a rotated intermediate key
        let drr2 = session.encrypt(b"after rotation").unwrap();
        let ik_created_2 = drr2
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;

        assert!(
            ik_created_2 > ik_created_1,
            "expected rotated IK: {ik_created_2} > {ik_created_1}"
        );

        // Both records should still decrypt correctly
        let out1 = session.decrypt(drr1).unwrap();
        assert_eq!(out1, b"before rotation");
        let out2 = session.decrypt(drr2).unwrap();
        assert_eq!(out2, b"after rotation");
    })
    .await
    .unwrap();
}

/// Key rotation against DynamoDB + real KMS envelope.
#[tokio::test]
async fn dynamodb_kms_key_rotation() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyRotation";

    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (kms, store, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (kms, store, crypto)
        });
        let mut cfg = asherah::Config::new("rotation-svc", "rotation-prod");
        cfg.policy.expire_key_after_s = 1;
        cfg.policy.create_date_precision_s = 1;
        cfg.policy.revoke_check_interval_s = 1;

        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let session = factory.get_session("ddb-rotation");

        let drr1 = session.encrypt(b"before rotation").unwrap();
        let ik_created_1 = drr1
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;

        std::thread::sleep(std::time::Duration::from_millis(1200));

        let drr2 = session.encrypt(b"after rotation").unwrap();
        let ik_created_2 = drr2
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;

        assert!(
            ik_created_2 > ik_created_1,
            "expected rotated IK: {ik_created_2} > {ik_created_1}"
        );

        let out1 = session.decrypt(drr1).unwrap();
        assert_eq!(out1, b"before rotation");
        let out2 = session.decrypt(drr2).unwrap();
        assert_eq!(out2, b"after rotation");
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Cross-partition isolation
// ════════════════════════════════════════════════════════════════

/// Verify that data encrypted under one partition cannot be decrypted by another.
#[tokio::test]
async fn postgres_cross_partition_isolation() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![6_u8; 32]).unwrap());
        let cfg = asherah::Config::new("isolation-svc", "isolation-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);

        let session_a = factory.get_session("partition-a");
        let session_b = factory.get_session("partition-b");

        let drr = session_a.encrypt(b"secret for A").unwrap();

        // Decrypting with the wrong partition's session should fail
        let result = session_b.decrypt(drr);
        assert!(
            result.is_err(),
            "decrypting with wrong partition should fail"
        );
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// AwsKms (direct, non-envelope) via LocalStack
// ════════════════════════════════════════════════════════════════

/// Test the direct (non-envelope) AwsKms encrypt/decrypt roundtrip.
#[tokio::test]
async fn kms_direct_roundtrip() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };

    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let kms = with_endpoint(&endpoint_clone, || {
            let aead = Arc::new(asherah::aead::AES256GCM::new());
            asherah::kms_aws::AwsKms::new(aead, key_id, Some("us-east-1".into())).unwrap()
        });

        let original_key = b"direct-kms-32-byte-test-key!!!!1";
        let encrypted = kms.encrypt_key(&(), original_key).unwrap();

        // Ciphertext should differ from plaintext
        assert_ne!(encrypted, original_key);

        let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();
        assert_eq!(decrypted, original_key);
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// AwsKmsBuilder (fluent multi-region builder) via LocalStack
// ════════════════════════════════════════════════════════════════

/// Test AwsKmsBuilder: build a multi-region KMS via the fluent API, encrypt/decrypt roundtrip.
#[tokio::test]
async fn kms_builder_multi_region() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };

    let key_id_1 = create_kms_key(&endpoint).await;
    let key_id_2 = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let kms = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            asherah::kms_builders::AwsKmsBuilder::new(crypto)
                .preferred_region("us-east-1")
                .add("us-east-1", &key_id_1)
                .add("us-east-1", &key_id_2)
                .build()
                .unwrap()
        });

        let original = b"builder-test-32-byte-key-pad!!!!";
        let encrypted = kms.encrypt_key(&(), original).unwrap();
        let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();
        assert_eq!(decrypted, original);
    })
    .await
    .unwrap();
}

/// AwsKmsBuilder with no entries should fail.
#[tokio::test]
async fn kms_builder_empty_entries_fails() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let result = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            asherah::kms_builders::AwsKmsBuilder::new(crypto).build()
        });
        assert!(result.is_err(), "build with no entries should fail");
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Error / resilience scenarios
// ════════════════════════════════════════════════════════════════

/// Encrypting with an invalid KMS key ID should produce an error, not a panic.
#[tokio::test]
async fn kms_encrypt_with_invalid_key_returns_error() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let kms = with_endpoint(&endpoint_clone, || {
            let aead = Arc::new(asherah::aead::AES256GCM::new());
            asherah::kms_aws::AwsKms::new(
                aead,
                "invalid-key-id-does-not-exist",
                Some("us-east-1".into()),
            )
            .unwrap() // construction succeeds — key isn't validated until use
        });

        let result = kms.encrypt_key(&(), b"some-32-byte-key-for-testing!!!!");
        assert!(result.is_err(), "encrypt with invalid key should fail");
    })
    .await
    .unwrap();
}

/// Decrypting garbage ciphertext with a valid KMS key should produce an error.
#[tokio::test]
async fn kms_decrypt_garbage_returns_error() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };

    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let kms = with_endpoint(&endpoint_clone, || {
            let aead = Arc::new(asherah::aead::AES256GCM::new());
            asherah::kms_aws::AwsKms::new(aead, key_id, Some("us-east-1".into())).unwrap()
        });

        let result = kms.decrypt_key(&(), b"this is not valid ciphertext");
        assert!(result.is_err(), "decrypt garbage should fail");
    })
    .await
    .unwrap();
}

/// Envelope KMS: decrypting tampered envelope JSON should fail gracefully.
#[tokio::test]
async fn kms_envelope_decrypt_tampered_fails() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };

    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let kms = with_endpoint(&endpoint_clone, || {
            let aead = Arc::new(asherah::aead::AES256GCM::new());
            asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                aead,
                key_id,
                Some("us-east-1".into()),
            )
            .unwrap()
        });

        let original = b"this-is-a-32-byte-test-key!!1234";
        let mut encrypted = kms.encrypt_key(&(), original).unwrap();

        // Tamper with the encrypted envelope bytes
        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 0xFF;
        }

        let result = kms.decrypt_key(&(), &encrypted);
        assert!(result.is_err(), "decrypt tampered envelope should fail");
    })
    .await
    .unwrap();
}

/// Full-stack: decrypting a tampered DataRowRecord should fail.
#[tokio::test]
async fn postgres_decrypt_tampered_drr_fails() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![7_u8; 32]).unwrap());
        let cfg = asherah::Config::new("tamper-svc", "tamper-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("tamper-test");

        let mut drr = session.encrypt(b"sensitive data").unwrap();
        // Tamper with the encrypted data
        if let Some(byte) = drr.data.first_mut() {
            *byte ^= 0xFF;
        }
        let result = session.decrypt(drr);
        assert!(result.is_err(), "decrypting tampered DRR should fail");
    })
    .await
    .unwrap();
}

/// MySQL metastore: connecting to a bad URL should return an error, not panic.
#[tokio::test]
async fn mysql_bad_connection_returns_error() {
    // No container needed — we're testing that a bad URL fails gracefully
    tokio::task::spawn_blocking(|| {
        let result =
            asherah::metastore_mysql::MySqlMetastore::connect("mysql://root@127.0.0.1:1/nonexist");
        assert!(result.is_err(), "connecting to bad MySQL URL should fail");
    })
    .await
    .unwrap();
}

/// Postgres metastore: connecting to a bad URL should return an error, not panic.
#[tokio::test]
async fn postgres_bad_connection_returns_error() {
    tokio::task::spawn_blocking(|| {
        let result = asherah::metastore_postgres::PostgresMetastore::connect(
            "host=127.0.0.1 port=1 user=nobody dbname=nonexist connect_timeout=1",
        );
        assert!(
            result.is_err(),
            "connecting to bad Postgres URL should fail"
        );
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Additional full-stack variant matrix tests
// ════════════════════════════════════════════════════════════════

/// End-to-end: MySQL metastore + KMS Envelope → SessionFactory → encrypt → decrypt
#[tokio::test]
async fn mysql_kms_envelope_full_stack_roundtrip() {
    let (mysql_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(mysql_container);
            return;
        }
    };

    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let store = connect_mysql_with_retries(&url);
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("mysql-env-svc", "mysql-env-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("mysql-envelope-e2e");

        let plaintext = b"mysql + kms envelope e2e test";
        let drr = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(drr).unwrap();
        assert_eq!(decrypted, plaintext);
    })
    .await
    .unwrap();
}

/// End-to-end: Postgres metastore + KMS Envelope → SessionFactory → encrypt → decrypt
#[tokio::test]
async fn postgres_kms_envelope_full_stack_roundtrip() {
    let (pg_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(pg_container);
            return;
        }
    };

    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("pg-env-svc", "pg-env-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("pg-envelope-e2e");

        let plaintext = b"postgres + kms envelope e2e test";
        let drr = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(drr).unwrap();
        assert_eq!(decrypted, plaintext);
    })
    .await
    .unwrap();
}

/// End-to-end: DynamoDB metastore + StaticKMS → SessionFactory → encrypt → decrypt
#[tokio::test]
async fn dynamodb_static_kms_full_stack_roundtrip() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyStaticE2E";

    create_dynamodb_table(&endpoint, table).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![8_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("ddb-static-svc", "ddb-static-prod");
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let session = factory.get_session("ddb-static-e2e");

        let plaintext = b"dynamodb + static kms e2e test";
        let drr = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(drr).unwrap();
        assert_eq!(decrypted, plaintext);
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Cross-partition isolation: MySQL and DynamoDB
// ════════════════════════════════════════════════════════════════

/// Cross-partition isolation against MySQL.
#[tokio::test]
async fn mysql_cross_partition_isolation() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![9_u8; 32]).unwrap());
        let cfg = asherah::Config::new("mysql-iso-svc", "mysql-iso-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);

        let session_a = factory.get_session("mysql-part-a");
        let session_b = factory.get_session("mysql-part-b");

        let drr = session_a.encrypt(b"secret for A only").unwrap();
        let result = session_b.decrypt(drr);
        assert!(
            result.is_err(),
            "decrypting with wrong partition should fail"
        );
    })
    .await
    .unwrap();
}

/// Cross-partition isolation against DynamoDB.
#[tokio::test]
async fn dynamodb_cross_partition_isolation() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyCrossPartition";

    create_dynamodb_table(&endpoint, table).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![10_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("ddb-iso-svc", "ddb-iso-prod");
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);

        let session_a = factory.get_session("ddb-part-a");
        let session_b = factory.get_session("ddb-part-b");

        let drr = session_a.encrypt(b"secret for A only").unwrap();
        let result = session_b.decrypt(drr);
        assert!(
            result.is_err(),
            "decrypting with wrong partition should fail"
        );
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Tampered DRR: MySQL and DynamoDB
// ════════════════════════════════════════════════════════════════

/// Tampered DRR against MySQL.
#[tokio::test]
async fn mysql_decrypt_tampered_drr_fails() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![11_u8; 32]).unwrap());
        let cfg = asherah::Config::new("mysql-tamper-svc", "mysql-tamper-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("mysql-tamper");

        let mut drr = session.encrypt(b"tamper test data").unwrap();
        if let Some(byte) = drr.data.first_mut() {
            *byte ^= 0xFF;
        }
        let result = session.decrypt(drr);
        assert!(result.is_err(), "decrypting tampered DRR should fail");
    })
    .await
    .unwrap();
}

/// Tampered DRR against DynamoDB.
#[tokio::test]
async fn dynamodb_decrypt_tampered_drr_fails() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyTamper";

    create_dynamodb_table(&endpoint, table).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![12_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("ddb-tamper-svc", "ddb-tamper-prod");
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let session = factory.get_session("ddb-tamper");

        let mut drr = session.encrypt(b"tamper test data").unwrap();
        if let Some(byte) = drr.data.first_mut() {
            *byte ^= 0xFF;
        }
        let result = session.decrypt(drr);
        assert!(result.is_err(), "decrypting tampered DRR should fail");
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Key rotation: MySQL + StaticKMS
// ════════════════════════════════════════════════════════════════

/// Key rotation against MySQL + StaticKMS.
#[tokio::test]
async fn mysql_key_rotation() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![13_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("mysql-rot-svc", "mysql-rot-prod");
        cfg.policy.expire_key_after_s = 1;
        cfg.policy.create_date_precision_s = 1;
        cfg.policy.revoke_check_interval_s = 1;

        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("mysql-rotation");

        let drr1 = session.encrypt(b"before rotation").unwrap();
        let ik_created_1 = drr1
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;

        std::thread::sleep(std::time::Duration::from_millis(1200));

        let drr2 = session.encrypt(b"after rotation").unwrap();
        let ik_created_2 = drr2
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;

        assert!(
            ik_created_2 > ik_created_1,
            "expected rotated IK: {ik_created_2} > {ik_created_1}"
        );

        let out1 = session.decrypt(drr1).unwrap();
        assert_eq!(out1, b"before rotation");
        let out2 = session.decrypt(drr2).unwrap();
        assert_eq!(out2, b"after rotation");
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Concurrent: DynamoDB
// ════════════════════════════════════════════════════════════════

/// Concurrent encrypt/decrypt against DynamoDB-backed SessionFactory.
#[tokio::test]
async fn dynamodb_concurrent_roundtrip() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyConcurrent";

    create_dynamodb_table(&endpoint, table).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![14_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("ddb-concurrent-svc", "ddb-concurrent-prod");
        let factory = Arc::new(asherah::api::new_session_factory(cfg, store, kms, crypto));

        let mut handles = vec![];
        for i in 0..8 {
            let f = factory.clone();
            handles.push(std::thread::spawn(move || {
                let session = f.get_session(&format!("ddb-concurrent-{i}"));
                let msg = format!("concurrent payload {i}");
                let drr = session.encrypt(msg.as_bytes()).unwrap();
                let out = session.decrypt(drr).unwrap();
                assert_eq!(out, msg.as_bytes());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Session caching against real backend
// ════════════════════════════════════════════════════════════════

/// Session caching enabled against Postgres.
#[tokio::test]
async fn postgres_session_caching() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![15_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("pg-cache-svc", "pg-cache-prod");
        cfg.policy.cache_sessions = true;
        cfg.policy.session_cache_max_size = 100;
        cfg.policy.session_cache_ttl_s = 300;

        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);

        // Get same session ID twice — second should hit cache
        let session1 = factory.get_session("pg-cached");
        let drr = session1.encrypt(b"session cache test").unwrap();
        let out = session1.decrypt(drr.clone()).unwrap();
        assert_eq!(out, b"session cache test");

        // Second session for same partition should still work (cached or fresh)
        let session2 = factory.get_session("pg-cached");
        let out2 = session2.decrypt(drr).unwrap();
        assert_eq!(out2, b"session cache test");

        // Encrypt with cached session should work
        let drr2 = session2.encrypt(b"session cache test 2").unwrap();
        let out3 = session2.decrypt(drr2).unwrap();
        assert_eq!(out3, b"session cache test 2");

        factory.close().unwrap();
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Region suffix against real backend
// ════════════════════════════════════════════════════════════════

/// Region suffix via RegionSuffixMetastore wrapping MySQL.
#[tokio::test]
async fn mysql_region_suffix() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let inner = Arc::new(connect_mysql_with_retries(&url));
        let store = Arc::new(asherah::metastore_region::RegionSuffixMetastore::new(
            inner,
            "us-west-2",
        ));
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![16_u8; 32]).unwrap());
        let cfg = asherah::Config::new("mysql-region-svc", "mysql-region-prod");
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let session = factory.get_session("mysql-region-test");

        let drr = session.encrypt(b"region suffix test").unwrap();

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
            "IK ID should have region suffix: {ik_id}"
        );

        let out = session.decrypt(drr).unwrap();
        assert_eq!(out, b"region suffix test");
    })
    .await
    .unwrap();
}

/// Region suffix via config against Postgres.
#[tokio::test]
async fn postgres_region_suffix_via_config() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![17_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("pg-region-svc", "pg-region-prod");
        cfg.region_suffix = Some("eu-central-1".into());
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("pg-region-test");

        let drr = session.encrypt(b"region suffix via config").unwrap();

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
            ik_id.contains("eu-central-1"),
            "IK ID should have region suffix: {ik_id}"
        );

        let out = session.decrypt(drr).unwrap();
        assert_eq!(out, b"region suffix via config");
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Store/Load API against real backend
// ════════════════════════════════════════════════════════════════

/// Store/Load API against Postgres.
#[tokio::test]
async fn postgres_store_load_api() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let metastore = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![18_u8; 32]).unwrap());
        let cfg = asherah::Config::new("pg-store-svc", "pg-store-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(metastore), kms, crypto);
        let session = factory.get_session("pg-store-load");

        let data_store = asherah::store::InMemoryStore::new();
        let key = session.store(b"store load test", &data_store).unwrap();
        let loaded = session.load(&key, &data_store).unwrap();
        assert_eq!(loaded, b"store load test");
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Concurrent: MySQL + KMS Envelope
// ════════════════════════════════════════════════════════════════

/// Concurrent encrypt/decrypt against MySQL + KMS Envelope.
#[tokio::test]
async fn mysql_kms_envelope_concurrent() {
    let (mysql_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(mysql_container);
            return;
        }
    };

    let key_id = create_kms_key(&endpoint).await;

    // Build factory on a plain thread so the KMS envelope creates its own
    // internal tokio runtime, which is then available to child threads.
    let factory = with_endpoint(&endpoint, || {
        std::thread::spawn(move || {
            let store = connect_mysql_with_retries(&url);
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let cfg = asherah::Config::new("mysql-env-conc-svc", "mysql-env-conc-prod");
            Arc::new(asherah::api::new_session_factory(
                cfg,
                Arc::new(store),
                kms,
                crypto,
            ))
        })
        .join()
        .unwrap()
    });

    tokio::task::spawn_blocking(move || {
        let mut handles = vec![];
        for i in 0..8 {
            let f = factory.clone();
            handles.push(std::thread::spawn(move || {
                let session = f.get_session(&format!("mysql-env-conc-{i}"));
                let msg = format!("envelope concurrent {i}");
                let drr = session.encrypt(msg.as_bytes()).unwrap();
                let out = session.decrypt(drr).unwrap();
                assert_eq!(out, msg.as_bytes());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Multi-region KMS + real metastore full stack
// ════════════════════════════════════════════════════════════════

/// Full-stack: Postgres + multi-region KMS envelope.
#[tokio::test]
async fn postgres_multi_region_kms_full_stack() {
    let (pg_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(pg_container);
            return;
        }
    };

    let key_id_1 = create_kms_key(&endpoint).await;
    let key_id_2 = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_multi(
                    crypto.clone(),
                    0,
                    vec![
                        ("us-east-1".into(), key_id_1),
                        ("us-east-1".into(), key_id_2),
                    ],
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("pg-multi-kms-svc", "pg-multi-kms-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("pg-multi-kms");

        let plaintext = b"postgres + multi-region kms test";
        let drr = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(drr).unwrap();
        assert_eq!(decrypted, plaintext);
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// AwsKmsBuilder + real metastore full stack
// ════════════════════════════════════════════════════════════════

/// Full-stack: DynamoDB + AwsKmsBuilder-constructed KMS.
#[tokio::test]
async fn dynamodb_kms_builder_full_stack() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyBuilder";

    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (kms, store, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms_dyn = asherah::kms_builders::AwsKmsBuilder::new(crypto.clone())
                .preferred_region("us-east-1")
                .add("us-east-1", &key_id)
                .build()
                .unwrap();
            let kms = Arc::new(asherah::builders::DynKms(kms_dyn));
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (kms, store, crypto)
        });
        let cfg = asherah::Config::new("ddb-builder-svc", "ddb-builder-prod");
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let session = factory.get_session("ddb-builder");

        let plaintext = b"dynamodb + kms builder full stack test";
        let drr = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(drr).unwrap();
        assert_eq!(decrypted, plaintext);
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Key rotation: Postgres + KMS Envelope, MySQL + KMS Envelope
// ════════════════════════════════════════════════════════════════

/// Key rotation: Postgres + KMS Envelope.
#[tokio::test]
async fn postgres_kms_envelope_key_rotation() {
    let (pg_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(pg_container);
            return;
        }
    };

    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("pg-env-rot-svc", "pg-env-rot-prod");
        cfg.policy.expire_key_after_s = 1;
        cfg.policy.create_date_precision_s = 1;
        cfg.policy.revoke_check_interval_s = 1;

        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("pg-env-rotation");

        let drr1 = session.encrypt(b"before rotation").unwrap();
        let ik_created_1 = drr1
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;

        std::thread::sleep(std::time::Duration::from_millis(1200));

        let drr2 = session.encrypt(b"after rotation").unwrap();
        let ik_created_2 = drr2
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;

        assert!(
            ik_created_2 > ik_created_1,
            "expected rotated IK: {ik_created_2} > {ik_created_1}"
        );

        let out1 = session.decrypt(drr1).unwrap();
        assert_eq!(out1, b"before rotation");
        let out2 = session.decrypt(drr2).unwrap();
        assert_eq!(out2, b"after rotation");
    })
    .await
    .unwrap();
}

/// Key rotation: MySQL + KMS Envelope.
#[tokio::test]
async fn mysql_kms_envelope_key_rotation() {
    let (mysql_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(mysql_container);
            return;
        }
    };

    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let store = connect_mysql_with_retries(&url);
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("mysql-env-rot-svc", "mysql-env-rot-prod");
        cfg.policy.expire_key_after_s = 1;
        cfg.policy.create_date_precision_s = 1;
        cfg.policy.revoke_check_interval_s = 1;

        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let session = factory.get_session("mysql-env-rotation");

        let drr1 = session.encrypt(b"before rotation").unwrap();
        let ik_created_1 = drr1
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;

        std::thread::sleep(std::time::Duration::from_millis(1200));

        let drr2 = session.encrypt(b"after rotation").unwrap();
        let ik_created_2 = drr2
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;

        assert!(
            ik_created_2 > ik_created_1,
            "expected rotated IK: {ik_created_2} > {ik_created_1}"
        );

        let out1 = session.decrypt(drr1).unwrap();
        assert_eq!(out1, b"before rotation");
        let out2 = session.decrypt(drr2).unwrap();
        assert_eq!(out2, b"after rotation");
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// DynamoDB + KMS Envelope concurrent
// ════════════════════════════════════════════════════════════════

/// Concurrent encrypt/decrypt against DynamoDB + KMS Envelope (both on same LocalStack).
#[tokio::test]
async fn dynamodb_kms_envelope_concurrent() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyEnvConcurrent";

    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;

    // Build factory on a plain thread so the KMS envelope creates its own
    // internal tokio runtime, which is then available to child threads.
    let factory = with_endpoint(&endpoint, || {
        std::thread::spawn(move || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let cfg = asherah::Config::new("ddb-env-conc-svc", "ddb-env-conc-prod");
            Arc::new(asherah::api::new_session_factory(cfg, store, kms, crypto))
        })
        .join()
        .unwrap()
    });

    tokio::task::spawn_blocking(move || {
        let mut handles = vec![];
        for i in 0..8 {
            let f = factory.clone();
            handles.push(std::thread::spawn(move || {
                let session = f.get_session(&format!("ddb-env-conc-{i}"));
                let msg = format!("ddb envelope concurrent {i}");
                let drr = session.encrypt(msg.as_bytes()).unwrap();
                let out = session.decrypt(drr).unwrap();
                assert_eq!(out, msg.as_bytes());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Shared IK cache against real backends
// ════════════════════════════════════════════════════════════════

/// Shared IK cache: multiple partitions share the same IK cache against Postgres.
#[tokio::test]
async fn postgres_shared_ik_cache() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![19_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("pg-shared-ik-svc", "pg-shared-ik-prod");
        cfg.policy.shared_intermediate_key_cache = true;
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 100;

        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);

        // Use multiple partitions — they should share the IK cache
        let session_a = factory.get_session("shared-ik-a");
        let session_b = factory.get_session("shared-ik-b");
        let session_c = factory.get_session("shared-ik-c");

        // Encrypt with each partition
        let drr_a = session_a.encrypt(b"partition a data").unwrap();
        let drr_b = session_b.encrypt(b"partition b data").unwrap();
        let drr_c = session_c.encrypt(b"partition c data").unwrap();

        // Each partition should decrypt its own data
        let out_a = session_a.decrypt(drr_a).unwrap();
        assert_eq!(out_a, b"partition a data");
        let out_b = session_b.decrypt(drr_b).unwrap();
        assert_eq!(out_b, b"partition b data");
        let out_c = session_c.decrypt(drr_c).unwrap();
        assert_eq!(out_c, b"partition c data");

        // Cross-partition should fail (shared cache doesn't break isolation)
        let drr_a2 = session_a.encrypt(b"cross test").unwrap();
        let result = session_b.decrypt(drr_a2);
        assert!(
            result.is_err(),
            "shared IK cache should not break partition isolation"
        );

        factory.close().unwrap();
    })
    .await
    .unwrap();
}

/// Shared IK cache concurrent: multiple threads using shared cache against MySQL.
#[tokio::test]
async fn mysql_shared_ik_cache_concurrent() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![20_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("mysql-shared-ik-svc", "mysql-shared-ik-prod");
        cfg.policy.shared_intermediate_key_cache = true;
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 100;

        let factory = Arc::new(asherah::api::new_session_factory(
            cfg,
            Arc::new(store),
            kms,
            crypto,
        ));

        let mut handles = vec![];
        for i in 0..8 {
            let f = factory.clone();
            handles.push(std::thread::spawn(move || {
                let session = f.get_session(&format!("mysql-shared-ik-{i}"));
                let msg = format!("shared ik concurrent {i}");
                let drr = session.encrypt(msg.as_bytes()).unwrap();
                let out = session.decrypt(drr).unwrap();
                assert_eq!(out, msg.as_bytes());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        factory.close().unwrap();
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Complete matrix: all remaining Metastore × KMS × Feature combos
// ════════════════════════════════════════════════════════════════

// ── Concurrent: Postgres+Envelope ──

#[tokio::test]
async fn postgres_kms_envelope_concurrent() {
    let (pg_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(pg_container);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let factory = with_endpoint(&endpoint, || {
        std::thread::spawn(move || {
            let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let cfg = asherah::Config::new("pg-env-conc-svc", "pg-env-conc-prod");
            Arc::new(asherah::api::new_session_factory(
                cfg,
                Arc::new(store),
                kms,
                crypto,
            ))
        })
        .join()
        .unwrap()
    });
    tokio::task::spawn_blocking(move || {
        let mut handles = vec![];
        for i in 0..8 {
            let f = factory.clone();
            handles.push(std::thread::spawn(move || {
                let s = f.get_session(&format!("pg-env-conc-{i}"));
                let msg = format!("pg env concurrent {i}");
                let drr = s.encrypt(msg.as_bytes()).unwrap();
                assert_eq!(s.decrypt(drr).unwrap(), msg.as_bytes());
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    })
    .await
    .unwrap();
}

// ── Rotation: DynamoDB+Static ──

#[tokio::test]
async fn dynamodb_static_key_rotation() {
    let (_c, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyStaticRotation";
    create_dynamodb_table(&endpoint, table).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![21_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("ddb-srot-svc", "ddb-srot-prod");
        cfg.policy.expire_key_after_s = 1;
        cfg.policy.create_date_precision_s = 1;
        cfg.policy.revoke_check_interval_s = 1;
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let session = factory.get_session("ddb-srot");
        let drr1 = session.encrypt(b"before").unwrap();
        let ik1 = drr1
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let drr2 = session.encrypt(b"after").unwrap();
        let ik2 = drr2
            .key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .created;
        assert!(ik2 > ik1, "rotated IK: {ik2} > {ik1}");
        assert_eq!(session.decrypt(drr1).unwrap(), b"before");
        assert_eq!(session.decrypt(drr2).unwrap(), b"after");
    })
    .await
    .unwrap();
}

// ── Cross-partition: Envelope variants ──

#[tokio::test]
async fn mysql_kms_envelope_cross_partition() {
    let (mc, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(mc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let store = connect_mysql_with_retries(&url);
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("m-ecp-svc", "m-ecp-prod");
        let f = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let drr = f.get_session("m-ecp-a").encrypt(b"secret").unwrap();
        assert!(f.get_session("m-ecp-b").decrypt(drr).is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn postgres_kms_envelope_cross_partition() {
    let (pc, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(pc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("p-ecp-svc", "p-ecp-prod");
        let f = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let drr = f.get_session("p-ecp-a").encrypt(b"secret").unwrap();
        assert!(f.get_session("p-ecp-b").decrypt(drr).is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_kms_envelope_cross_partition() {
    let (_c, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyEnvCrossPart";
    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("d-ecp-svc", "d-ecp-prod");
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let drr = f.get_session("d-ecp-a").encrypt(b"secret").unwrap();
        assert!(f.get_session("d-ecp-b").decrypt(drr).is_err());
    })
    .await
    .unwrap();
}

// ── Tampered DRR: Envelope variants ──

#[tokio::test]
async fn mysql_kms_envelope_tampered_drr() {
    let (mc, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(mc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let store = connect_mysql_with_retries(&url);
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("m-et-svc", "m-et-prod");
        let f = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let s = f.get_session("m-et");
        let mut drr = s.encrypt(b"tamper").unwrap();
        drr.data[0] ^= 0xFF;
        assert!(s.decrypt(drr).is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn postgres_kms_envelope_tampered_drr() {
    let (pc, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(pc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("p-et-svc", "p-et-prod");
        let f = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let s = f.get_session("p-et");
        let mut drr = s.encrypt(b"tamper").unwrap();
        drr.data[0] ^= 0xFF;
        assert!(s.decrypt(drr).is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_kms_envelope_tampered_drr() {
    let (_c, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyEnvTamper";
    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("d-et-svc", "d-et-prod");
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let s = f.get_session("d-et");
        let mut drr = s.encrypt(b"tamper").unwrap();
        drr.data[0] ^= 0xFF;
        assert!(s.decrypt(drr).is_err());
    })
    .await
    .unwrap();
}

// ── Session caching: all missing combos ──

#[tokio::test]
async fn mysql_session_caching() {
    let (_c, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![22_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("m-sc-svc", "m-sc-prod");
        cfg.policy.cache_sessions = true;
        cfg.policy.session_cache_max_size = 100;
        cfg.policy.session_cache_ttl_s = 300;
        let f = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let s1 = f.get_session("m-sc");
        let drr = s1.encrypt(b"cached").unwrap();
        assert_eq!(s1.decrypt(drr.clone()).unwrap(), b"cached");
        assert_eq!(f.get_session("m-sc").decrypt(drr).unwrap(), b"cached");
        f.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn mysql_kms_envelope_session_caching() {
    let (mc, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(mc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let store = connect_mysql_with_retries(&url);
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("m-esc-svc", "m-esc-prod");
        cfg.policy.cache_sessions = true;
        cfg.policy.session_cache_max_size = 100;
        cfg.policy.session_cache_ttl_s = 300;
        let f = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let s1 = f.get_session("m-esc");
        let drr = s1.encrypt(b"env cached").unwrap();
        assert_eq!(s1.decrypt(drr.clone()).unwrap(), b"env cached");
        assert_eq!(f.get_session("m-esc").decrypt(drr).unwrap(), b"env cached");
        f.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn postgres_kms_envelope_session_caching() {
    let (pc, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(pc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("p-esc-svc", "p-esc-prod");
        cfg.policy.cache_sessions = true;
        cfg.policy.session_cache_max_size = 100;
        cfg.policy.session_cache_ttl_s = 300;
        let f = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let s1 = f.get_session("p-esc");
        let drr = s1.encrypt(b"env cached").unwrap();
        assert_eq!(s1.decrypt(drr.clone()).unwrap(), b"env cached");
        assert_eq!(f.get_session("p-esc").decrypt(drr).unwrap(), b"env cached");
        f.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_session_caching() {
    let (_c, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeySessionCache";
    create_dynamodb_table(&endpoint, table).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![23_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("d-sc-svc", "d-sc-prod");
        cfg.policy.cache_sessions = true;
        cfg.policy.session_cache_max_size = 100;
        cfg.policy.session_cache_ttl_s = 300;
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let s1 = f.get_session("d-sc");
        let drr = s1.encrypt(b"ddb cached").unwrap();
        assert_eq!(s1.decrypt(drr.clone()).unwrap(), b"ddb cached");
        assert_eq!(f.get_session("d-sc").decrypt(drr).unwrap(), b"ddb cached");
        f.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_kms_envelope_session_caching() {
    let (_c, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyEnvSessCache";
    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("d-esc-svc", "d-esc-prod");
        cfg.policy.cache_sessions = true;
        cfg.policy.session_cache_max_size = 100;
        cfg.policy.session_cache_ttl_s = 300;
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let s1 = f.get_session("d-esc");
        let drr = s1.encrypt(b"ddb env cached").unwrap();
        assert_eq!(s1.decrypt(drr.clone()).unwrap(), b"ddb env cached");
        assert_eq!(
            f.get_session("d-esc").decrypt(drr).unwrap(),
            b"ddb env cached"
        );
        f.close().unwrap();
    })
    .await
    .unwrap();
}

// ── Region suffix: all missing combos ──

#[tokio::test]
async fn mysql_kms_envelope_region_suffix() {
    let (mc, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(mc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let inner = Arc::new(connect_mysql_with_retries(&url));
            let store = Arc::new(asherah::metastore_region::RegionSuffixMetastore::new(
                inner,
                "ap-south-1",
            ));
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("m-er-svc", "m-er-prod");
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let s = f.get_session("m-er");
        let drr = s.encrypt(b"region").unwrap();
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
            ik_id.contains("ap-south-1"),
            "IK ID should have suffix: {ik_id}"
        );
        assert_eq!(s.decrypt(drr).unwrap(), b"region");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn postgres_kms_envelope_region_suffix() {
    let (pc, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(pc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let inner =
                Arc::new(asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap());
            let store = Arc::new(asherah::metastore_region::RegionSuffixMetastore::new(
                inner,
                "eu-west-1",
            ));
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("p-er-svc", "p-er-prod");
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let s = f.get_session("p-er");
        let drr = s.encrypt(b"region").unwrap();
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
            ik_id.contains("eu-west-1"),
            "IK ID should have suffix: {ik_id}"
        );
        assert_eq!(s.decrypt(drr).unwrap(), b"region");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_region_suffix() {
    let (_c, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyRegionSuffix";
    create_dynamodb_table(&endpoint, table).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let inner = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(asherah::metastore_region::RegionSuffixMetastore::new(
                inner,
                "us-west-2",
            ));
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![24_u8; 32]).unwrap());
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("d-sr-svc", "d-sr-prod");
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let s = f.get_session("d-sr");
        let drr = s.encrypt(b"ddb region").unwrap();
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
            "IK ID should have suffix: {ik_id}"
        );
        assert_eq!(s.decrypt(drr).unwrap(), b"ddb region");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_kms_envelope_region_suffix() {
    let (_c, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyEnvRegion";
    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let inner = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(asherah::metastore_region::RegionSuffixMetastore::new(
                inner,
                "ap-northeast-1",
            ));
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("d-er-svc", "d-er-prod");
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let s = f.get_session("d-er");
        let drr = s.encrypt(b"ddb env region").unwrap();
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
            ik_id.contains("ap-northeast-1"),
            "IK ID should have suffix: {ik_id}"
        );
        assert_eq!(s.decrypt(drr).unwrap(), b"ddb env region");
    })
    .await
    .unwrap();
}

// ── Store/Load API: all missing combos ──

#[tokio::test]
async fn mysql_store_load_api() {
    let (_c, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![25_u8; 32]).unwrap());
        let cfg = asherah::Config::new("m-sl-svc", "m-sl-prod");
        let f = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let s = f.get_session("m-sl");
        let ds = asherah::store::InMemoryStore::new();
        let key = s.store(b"mysql store", &ds).unwrap();
        assert_eq!(s.load(&key, &ds).unwrap(), b"mysql store");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn mysql_kms_envelope_store_load_api() {
    let (mc, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(mc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (metastore, kms, crypto) = with_endpoint(&ep, || {
            let metastore = connect_mysql_with_retries(&url);
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (metastore, kms, crypto)
        });
        let cfg = asherah::Config::new("m-esl-svc", "m-esl-prod");
        let f = asherah::api::new_session_factory(cfg, Arc::new(metastore), kms, crypto);
        let s = f.get_session("m-esl");
        let ds = asherah::store::InMemoryStore::new();
        let key = s.store(b"mysql env store", &ds).unwrap();
        assert_eq!(s.load(&key, &ds).unwrap(), b"mysql env store");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn postgres_kms_envelope_store_load_api() {
    let (pc, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(pc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (metastore, kms, crypto) = with_endpoint(&ep, || {
            let metastore = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (metastore, kms, crypto)
        });
        let cfg = asherah::Config::new("p-esl-svc", "p-esl-prod");
        let f = asherah::api::new_session_factory(cfg, Arc::new(metastore), kms, crypto);
        let s = f.get_session("p-esl");
        let ds = asherah::store::InMemoryStore::new();
        let key = s.store(b"pg env store", &ds).unwrap();
        assert_eq!(s.load(&key, &ds).unwrap(), b"pg env store");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_store_load_api() {
    let (_c, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyStoreLoad";
    create_dynamodb_table(&endpoint, table).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![26_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("d-sl-svc", "d-sl-prod");
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let s = f.get_session("d-sl");
        let ds = asherah::store::InMemoryStore::new();
        let key = s.store(b"ddb store", &ds).unwrap();
        assert_eq!(s.load(&key, &ds).unwrap(), b"ddb store");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_kms_envelope_store_load_api() {
    let (_c, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyEnvStoreLoad";
    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let cfg = asherah::Config::new("d-esl-svc", "d-esl-prod");
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let s = f.get_session("d-esl");
        let ds = asherah::store::InMemoryStore::new();
        let key = s.store(b"ddb env store", &ds).unwrap();
        assert_eq!(s.load(&key, &ds).unwrap(), b"ddb env store");
    })
    .await
    .unwrap();
}

// ── Shared IK cache: all missing combos ──

#[tokio::test]
async fn mysql_kms_envelope_shared_ik_cache() {
    let (mc, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(mc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let store = connect_mysql_with_retries(&url);
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("m-esik-svc", "m-esik-prod");
        cfg.policy.shared_intermediate_key_cache = true;
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 100;
        let f = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let sa = f.get_session("m-esik-a");
        let sb = f.get_session("m-esik-b");
        let da = sa.encrypt(b"a").unwrap();
        let db = sb.encrypt(b"b").unwrap();
        assert_eq!(sa.decrypt(da).unwrap(), b"a");
        assert_eq!(sb.decrypt(db).unwrap(), b"b");
        assert!(sb.decrypt(sa.encrypt(b"x").unwrap()).is_err());
        f.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn postgres_kms_envelope_shared_ik_cache() {
    let (pc, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => {
            drop(pc);
            return;
        }
    };
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("p-esik-svc", "p-esik-prod");
        cfg.policy.shared_intermediate_key_cache = true;
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 100;
        let f = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let sa = f.get_session("p-esik-a");
        let sb = f.get_session("p-esik-b");
        let da = sa.encrypt(b"a").unwrap();
        let db = sb.encrypt(b"b").unwrap();
        assert_eq!(sa.decrypt(da).unwrap(), b"a");
        assert_eq!(sb.decrypt(db).unwrap(), b"b");
        assert!(sb.decrypt(sa.encrypt(b"x").unwrap()).is_err());
        f.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_shared_ik_cache() {
    let (_c, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeySharedIK";
    create_dynamodb_table(&endpoint, table).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![27_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("d-sik-svc", "d-sik-prod");
        cfg.policy.shared_intermediate_key_cache = true;
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 100;
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let sa = f.get_session("d-sik-a");
        let sb = f.get_session("d-sik-b");
        let da = sa.encrypt(b"a").unwrap();
        let db = sb.encrypt(b"b").unwrap();
        assert_eq!(sa.decrypt(da).unwrap(), b"a");
        assert_eq!(sb.decrypt(db).unwrap(), b"b");
        assert!(sb.decrypt(sa.encrypt(b"x").unwrap()).is_err());
        f.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_kms_envelope_shared_ik_cache() {
    let (_c, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EncryptionKeyEnvSharedIK";
    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;
    let ep = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&ep, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("d-esik-svc", "d-esik-prod");
        cfg.policy.shared_intermediate_key_cache = true;
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 100;
        let f = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let sa = f.get_session("d-esik-a");
        let sb = f.get_session("d-esik-b");
        let da = sa.encrypt(b"a").unwrap();
        let db = sb.encrypt(b"b").unwrap();
        assert_eq!(sa.decrypt(da).unwrap(), b"a");
        assert_eq!(sb.decrypt(db).unwrap(), b"b");
        assert!(sb.decrypt(sa.encrypt(b"x").unwrap()).is_err());
        f.close().unwrap();
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Cache eviction policy integration tests
// ════════════════════════════════════════════════════════════════
// These tests use small cache sizes to force evictions and verify
// that encrypt/decrypt still works after keys are evicted and
// reloaded from the real metastore.

/// LRU IK cache eviction against MySQL: evict keys, verify reload.
#[tokio::test]
async fn mysql_lru_ik_cache_eviction() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![30_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("mysql-lru-svc", "mysql-lru-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "lru".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "lru".into();

        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);

        // Create sessions for 4 partitions — cache max is 2, so evictions must happen
        let partitions: Vec<String> = (0..4).map(|i| format!("lru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let session = factory.get_session(p);
            let drr = session.encrypt(format!("data-{p}").as_bytes()).unwrap();
            drrs.push((p.clone(), drr));
        }

        // Now decrypt all — evicted keys should be reloaded from metastore
        for (p, drr) in &drrs {
            let session = factory.get_session(p);
            let pt = session.decrypt(drr.clone()).unwrap();
            assert_eq!(pt, format!("data-{p}").as_bytes());
        }

        factory.close().unwrap();
    })
    .await
    .unwrap();
}

/// LFU IK cache eviction against Postgres.
#[tokio::test]
async fn postgres_lfu_ik_cache_eviction() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![31_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("pg-lfu-svc", "pg-lfu-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "lfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "lfu".into();

        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);

        let partitions: Vec<String> = (0..4).map(|i| format!("lfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let session = factory.get_session(p);
            let drr = session.encrypt(format!("data-{p}").as_bytes()).unwrap();
            drrs.push((p.clone(), drr));
        }

        for (p, drr) in &drrs {
            let session = factory.get_session(p);
            let pt = session.decrypt(drr.clone()).unwrap();
            assert_eq!(pt, format!("data-{p}").as_bytes());
        }

        factory.close().unwrap();
    })
    .await
    .unwrap();
}

/// SLRU session cache eviction against DynamoDB.
#[tokio::test]
async fn dynamodb_slru_session_cache_eviction() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };

    let table = "SlruSessionEviction";
    create_dynamodb_table(&endpoint, table).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![32_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("d-slru-svc", "d-slru-prod");
        cfg.policy.cache_sessions = true;
        cfg.policy.session_cache_max_size = 2;
        cfg.policy.session_cache_eviction_policy = "slru".into();
        cfg.policy.session_cache_ttl_s = 300;

        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);

        // Create 4 sessions — cache max is 2, SLRU will evict
        let partitions: Vec<String> = (0..4).map(|i| format!("slru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let session = factory.get_session(p);
            let drr = session.encrypt(format!("data-{p}").as_bytes()).unwrap();
            drrs.push((p.clone(), drr));
        }

        // Decrypt all — evicted sessions should be recreated
        for (p, drr) in &drrs {
            let session = factory.get_session(p);
            let pt = session.decrypt(drr.clone()).unwrap();
            assert_eq!(pt, format!("data-{p}").as_bytes());
        }

        factory.close().unwrap();
    })
    .await
    .unwrap();
}

/// TinyLFU IK cache eviction against MySQL with KMS envelope.
#[tokio::test]
async fn mysql_kms_envelope_tinylfu_cache_eviction() {
    let (_mysql, mysql_url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };

    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&mysql_url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = with_endpoint(&endpoint_clone, || {
            Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            )
        });
        let mut cfg = asherah::Config::new("mysql-tlfu-svc", "mysql-tlfu-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "tinylfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "tinylfu".into();

        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);

        let partitions: Vec<String> = (0..4).map(|i| format!("tlfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let session = factory.get_session(p);
            let drr = session.encrypt(format!("data-{p}").as_bytes()).unwrap();
            drrs.push((p.clone(), drr));
        }

        for (p, drr) in &drrs {
            let session = factory.get_session(p);
            let pt = session.decrypt(drr.clone()).unwrap();
            assert_eq!(pt, format!("data-{p}").as_bytes());
        }

        factory.close().unwrap();
    })
    .await
    .unwrap();
}

/// LRU session + IK cache eviction against Postgres with KMS envelope.
#[tokio::test]
async fn postgres_kms_envelope_lru_session_cache_eviction() {
    let (_pg, pg_url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };

    let key_id = create_kms_key(&endpoint).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&pg_url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = with_endpoint(&endpoint_clone, || {
            Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            )
        });
        let mut cfg = asherah::Config::new("pg-elru-svc", "pg-elru-prod");
        cfg.policy.cache_sessions = true;
        cfg.policy.session_cache_max_size = 2;
        cfg.policy.session_cache_eviction_policy = "lru".into();
        cfg.policy.session_cache_ttl_s = 300;
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.intermediate_key_cache_eviction_policy = "lru".into();
        cfg.policy.intermediate_key_cache_max_size = 2;

        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);

        let partitions: Vec<String> = (0..4).map(|i| format!("elru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let session = factory.get_session(p);
            let drr = session.encrypt(format!("data-{p}").as_bytes()).unwrap();
            drrs.push((p.clone(), drr));
        }

        for (p, drr) in &drrs {
            let session = factory.get_session(p);
            let pt = session.decrypt(drr.clone()).unwrap();
            assert_eq!(pt, format!("data-{p}").as_bytes());
        }

        factory.close().unwrap();
    })
    .await
    .unwrap();
}

// ──── MySQL + Static: LFU, SLRU, TinyLFU ────

#[tokio::test]
async fn mysql_lfu_cache_eviction() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![33_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("mysql-lfu-svc", "mysql-lfu-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "lfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "lfu".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("mlfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn mysql_slru_cache_eviction() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![34_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("mysql-slru-svc", "mysql-slru-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "slru".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "slru".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("mslru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn mysql_tinylfu_cache_eviction() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![35_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("mysql-tlfu2-svc", "mysql-tlfu2-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "tinylfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "tinylfu".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("mtlfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

// ──── MySQL + Envelope: LRU, LFU, SLRU ────

#[tokio::test]
async fn mysql_kms_envelope_lru_cache_eviction() {
    let (_mysql, mysql_url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let key_id = create_kms_key(&endpoint).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&mysql_url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = with_endpoint(&endpoint_clone, || {
            Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            )
        });
        let mut cfg = asherah::Config::new("me-lru-svc", "me-lru-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "lru".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "lru".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("melru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn mysql_kms_envelope_lfu_cache_eviction() {
    let (_mysql, mysql_url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let key_id = create_kms_key(&endpoint).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&mysql_url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = with_endpoint(&endpoint_clone, || {
            Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            )
        });
        let mut cfg = asherah::Config::new("me-lfu-svc", "me-lfu-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "lfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "lfu".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("melfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn mysql_kms_envelope_slru_cache_eviction() {
    let (_mysql, mysql_url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let key_id = create_kms_key(&endpoint).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&mysql_url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = with_endpoint(&endpoint_clone, || {
            Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            )
        });
        let mut cfg = asherah::Config::new("me-slru-svc", "me-slru-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "slru".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "slru".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("meslru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

// ──── Postgres + Static: LRU, SLRU, TinyLFU ────

#[tokio::test]
async fn postgres_lru_cache_eviction() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![36_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("pg-lru-svc", "pg-lru-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "lru".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "lru".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("plru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn postgres_slru_cache_eviction() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![37_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("pg-slru-svc", "pg-slru-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "slru".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "slru".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("pslru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn postgres_tinylfu_cache_eviction() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![38_u8; 32]).unwrap());
        let mut cfg = asherah::Config::new("pg-tlfu-svc", "pg-tlfu-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "tinylfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "tinylfu".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("ptlfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

// ──── Postgres + Envelope: LFU, SLRU, TinyLFU ────

#[tokio::test]
async fn postgres_kms_envelope_lfu_cache_eviction() {
    let (_pg, pg_url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let key_id = create_kms_key(&endpoint).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&pg_url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = with_endpoint(&endpoint_clone, || {
            Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            )
        });
        let mut cfg = asherah::Config::new("pe-lfu-svc", "pe-lfu-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "lfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "lfu".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("pelfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn postgres_kms_envelope_slru_cache_eviction() {
    let (_pg, pg_url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let key_id = create_kms_key(&endpoint).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&pg_url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = with_endpoint(&endpoint_clone, || {
            Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            )
        });
        let mut cfg = asherah::Config::new("pe-slru-svc", "pe-slru-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "slru".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "slru".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("peslru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn postgres_kms_envelope_tinylfu_cache_eviction() {
    let (_pg, pg_url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };
    let (_ls, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let key_id = create_kms_key(&endpoint).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&pg_url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = with_endpoint(&endpoint_clone, || {
            Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            )
        });
        let mut cfg = asherah::Config::new("pe-tlfu-svc", "pe-tlfu-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "tinylfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "tinylfu".into();
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("petlfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

// ──── DynamoDB + Static: LRU, LFU, TinyLFU ────

#[tokio::test]
async fn dynamodb_lru_cache_eviction() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "LruCacheEviction";
    create_dynamodb_table(&endpoint, table).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![39_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("d-lru-svc", "d-lru-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "lru".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "lru".into();
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("dlru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_lfu_cache_eviction() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "LfuCacheEviction";
    create_dynamodb_table(&endpoint, table).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![40_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("d-lfu-svc", "d-lfu-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "lfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "lfu".into();
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("dlfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_tinylfu_cache_eviction() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "TinyLfuCacheEviction";
    create_dynamodb_table(&endpoint, table).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms =
                Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![41_u8; 32]).unwrap());
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("d-tlfu-svc", "d-tlfu-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "tinylfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "tinylfu".into();
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("dtlfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

// ──── DynamoDB + Envelope: LRU, LFU, SLRU, TinyLFU ────

#[tokio::test]
async fn dynamodb_kms_envelope_lru_cache_eviction() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EnvLruCacheEviction";
    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("de-lru-svc", "de-lru-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "lru".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "lru".into();
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("delru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_kms_envelope_lfu_cache_eviction() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EnvLfuCacheEviction";
    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("de-lfu-svc", "de-lfu-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "lfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "lfu".into();
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("delfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_kms_envelope_slru_cache_eviction() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EnvSlruCacheEviction";
    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("de-slru-svc", "de-slru-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "slru".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "slru".into();
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("deslru-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dynamodb_kms_envelope_tinylfu_cache_eviction() {
    let (_container, endpoint) = match start_localstack_with_creds().await {
        Some(v) => v,
        None => return,
    };
    let table = "EnvTinyLfuCacheEviction";
    create_dynamodb_table(&endpoint, table).await;
    let key_id = create_kms_key(&endpoint).await;
    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let (store, kms, crypto) = with_endpoint(&endpoint_clone, || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(
                asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            let store = Arc::new(
                asherah::metastore_dynamodb::DynamoDbMetastore::new(
                    table,
                    Some("us-east-1".into()),
                )
                .unwrap(),
            );
            (store, kms, crypto)
        });
        let mut cfg = asherah::Config::new("de-tlfu-svc", "de-tlfu-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.cache_system_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 2;
        cfg.policy.intermediate_key_cache_eviction_policy = "tinylfu".into();
        cfg.policy.system_key_cache_max_size = 2;
        cfg.policy.system_key_cache_eviction_policy = "tinylfu".into();
        let factory = asherah::api::new_session_factory(cfg, store, kms, crypto);
        let partitions: Vec<String> = (0..4).map(|i| format!("detlfu-p{i}")).collect();
        let mut drrs = vec![];
        for p in &partitions {
            let s = factory.get_session(p);
            drrs.push((
                p.clone(),
                s.encrypt(format!("data-{p}").as_bytes()).unwrap(),
            ));
        }
        for (p, drr) in &drrs {
            let s = factory.get_session(p);
            assert_eq!(
                s.decrypt(drr.clone()).unwrap(),
                format!("data-{p}").as_bytes()
            );
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

// ════════════════════════════════════════════════════════════════
// Connection pool reuse under sustained sequential operations
// ════════════════════════════════════════════════════════════════

/// 50 sequential encrypt/decrypt cycles through one MySQL-backed factory.
/// Exercises connection pool reuse and verifies no leaks or failures.
#[cfg(feature = "mysql")]
#[tokio::test]
async fn mysql_many_sequential_operations() {
    let (_container, url) = match start_mysql().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = connect_mysql_with_retries(&url);
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![99_u8; 32]).unwrap());
        let cfg = asherah::Config::new("mysql-seq-svc", "mysql-seq-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);

        for i in 0..50 {
            let partition = format!("mysql-seq-{}", i % 5);
            let session = factory.get_session(&partition);
            let plaintext = format!("sequential payload {i}");
            let drr = session.encrypt(plaintext.as_bytes()).unwrap();
            let decrypted = session.decrypt(drr).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes(), "mismatch on iteration {i}");
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}

/// 50 sequential encrypt/decrypt cycles through one Postgres-backed factory.
/// Exercises connection pool reuse and verifies no leaks or failures.
#[cfg(feature = "postgres")]
#[tokio::test]
async fn postgres_many_sequential_operations() {
    let (_container, url) = match start_postgres().await {
        Some(v) => v,
        None => return,
    };

    tokio::task::spawn_blocking(move || {
        let store = asherah::metastore_postgres::PostgresMetastore::connect(&url).unwrap();
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        let kms = Arc::new(asherah::kms::StaticKMS::new(crypto.clone(), vec![98_u8; 32]).unwrap());
        let cfg = asherah::Config::new("pg-seq-svc", "pg-seq-prod");
        let factory = asherah::api::new_session_factory(cfg, Arc::new(store), kms, crypto);

        for i in 0..50 {
            let partition = format!("pg-seq-{}", i % 5);
            let session = factory.get_session(&partition);
            let plaintext = format!("sequential payload {i}");
            let drr = session.encrypt(plaintext.as_bytes()).unwrap();
            let decrypted = session.decrypt(drr).unwrap();
            assert_eq!(decrypted, plaintext.as_bytes(), "mismatch on iteration {i}");
        }
        factory.close().unwrap();
    })
    .await
    .unwrap();
}
