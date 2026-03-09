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

use std::sync::Arc;

use asherah::traits::{KeyManagementService, Metastore};
use asherah::types::{EnvelopeKeyRecord, KeyMeta};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use testcontainers_modules::{localstack::LocalStack, postgres::Postgres};

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

// ──────────────────────────── MySQL ────────────────────────────

#[tokio::test]
async fn mysql_metastore_contract() {
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
            return;
        }
    };

    let port = container.get_host_port_ipv4(3306).await.unwrap();
    // Use 127.0.0.1 — on macOS, `localhost` may resolve to IPv6 which
    // Docker Desktop doesn't always forward correctly
    let url = format!("mysql://root@127.0.0.1:{port}/test");

    tokio::task::spawn_blocking(move || {
        let mut last_err = None;
        for _ in 0..30 {
            match asherah::metastore_mysql::MySqlMetastore::connect(&url) {
                Ok(store) => {
                    run_contract(&store);
                    return;
                }
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
    })
    .await
    .unwrap();
}

// ──────────────────────────── Postgres ────────────────────────────

#[tokio::test]
async fn postgres_metastore_contract() {
    let container = match Postgres::default().start().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skipping Postgres test (Docker unavailable?): {e}");
            return;
        }
    };

    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("host=127.0.0.1 port={port} user=postgres password=postgres dbname=postgres");

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
    let container = match start_localstack().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skipping DynamoDB test: {e}");
            return;
        }
    };

    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(4566).await.unwrap();
    let endpoint = format!("http://{host}:{port}");
    let table = "EncryptionKey";

    create_dynamodb_table(&endpoint, table).await;

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        std::env::set_var("AWS_ENDPOINT_URL", &endpoint_clone);
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");

        let store =
            asherah::metastore_dynamodb::DynamoDbMetastore::new(table, Some("us-east-1".into()))
                .unwrap();

        run_contract(&store);

        std::env::remove_var("AWS_ENDPOINT_URL");
    })
    .await
    .unwrap();
}

// ──────────────────────────── KMS via LocalStack ────────────────────────────

#[tokio::test]
async fn kms_envelope_roundtrip() {
    let container = match start_localstack().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skipping KMS test: {e}");
            return;
        }
    };

    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(4566).await.unwrap();
    let endpoint = format!("http://{host}:{port}");

    std::env::set_var("AWS_ACCESS_KEY_ID", "test");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::meta::region::RegionProviderChain::first_try(
            aws_sdk_kms::config::Region::new("us-east-1"),
        ))
        .load()
        .await;

    let kms_config = aws_sdk_kms::config::Builder::from(&config)
        .endpoint_url(&endpoint)
        .build();

    let kms_client = aws_sdk_kms::Client::from_conf(kms_config);

    let key_resp = kms_client
        .create_key()
        .key_usage(aws_sdk_kms::types::KeyUsageType::EncryptDecrypt)
        .send()
        .await
        .unwrap();

    let key_id = key_resp.key_metadata().unwrap().key_id().to_string();

    let endpoint_clone = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        std::env::set_var("AWS_ENDPOINT_URL", &endpoint_clone);

        let aead = Arc::new(asherah::aead::AES256GCM::new());
        let kms = asherah::kms_aws_envelope::AwsKmsEnvelope::new_single(
            aead,
            key_id,
            Some("us-east-1".into()),
        )
        .unwrap();

        let original_key = b"this-is-a-32-byte-test-key!!1234";
        let encrypted = kms.encrypt_key(&(), original_key).unwrap();
        let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();

        assert_eq!(decrypted, original_key);

        std::env::remove_var("AWS_ENDPOINT_URL");
    })
    .await
    .unwrap();
}
