#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic
)]
//! Integration tests for Vault Transit KMS and AWS Secrets Manager KMS backends.
//!
//! These tests require Docker to be available. They are gated behind feature flags:
//! - `vault`: Vault Transit tests (uses `hashicorp/vault` container)
//! - `secrets-manager`: Secrets Manager tests (uses LocalStack container)
//!
//! Run with:
//!   cargo test --test kms_integration --features vault,secrets-manager

use std::sync::Mutex;

#[allow(unused)]
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// Set `AWS_ENDPOINT_URL` and run a closure while holding the env mutex.
#[allow(unused)]
fn with_endpoint<T>(endpoint: &str, f: impl FnOnce() -> T) -> T {
    let _guard = ENV_MUTEX.lock().unwrap();
    std::env::set_var("AWS_ENDPOINT_URL", endpoint);
    f()
}

// ════════════════════════════════════════════════════════════════
// Vault Transit KMS tests
// ════════════════════════════════════════════════════════════════

#[cfg(feature = "vault")]
mod vault_tests {
    use super::*;
    use asherah::kms_vault_transit::VaultTransitKms;
    use asherah::traits::KeyManagementService;
    use std::sync::Arc;
    use testcontainers::core::{IntoContainerPort, WaitFor};
    use testcontainers::runners::AsyncRunner;
    use testcontainers::{ContainerAsync, GenericImage, ImageExt};
    use tokio::sync::OnceCell;

    struct SharedVault {
        _container: ContainerAsync<GenericImage>,
        addr: String,
    }

    static SHARED_VAULT: OnceCell<Option<SharedVault>> = OnceCell::const_new();

    async fn shared_vault() -> Option<String> {
        SHARED_VAULT
            .get_or_init(async || {
                start_vault().await.map(|(c, addr)| SharedVault {
                    _container: c,
                    addr,
                })
            })
            .await
            .as_ref()
            .map(|s| s.addr.clone())
    }

    /// Start a Vault container in dev mode and configure Transit secrets engine.
    async fn start_vault() -> Option<(ContainerAsync<GenericImage>, String)> {
        for attempt in 0..3 {
            let container = match GenericImage::new("hashicorp/vault", "latest")
                .with_exposed_port(8200.tcp())
                .with_wait_for(WaitFor::message_on_stderr("==> Vault server started!"))
                .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "test-token")
                .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
                .with_startup_timeout(std::time::Duration::from_secs(60))
                .start()
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("skipping Vault test (Docker unavailable?): {e}");
                    return None;
                }
            };

            match container.get_host_port_ipv4(8200).await {
                Ok(port) => {
                    let addr = format!("http://127.0.0.1:{port}");

                    // Wait for Vault to be ready and configure Transit
                    let addr_clone = addr.clone();
                    let setup_ok =
                        tokio::task::spawn_blocking(move || setup_vault_transit(&addr_clone))
                            .await
                            .unwrap();

                    if !setup_ok {
                        eprintln!("Vault Transit setup failed (attempt {attempt})");
                        continue;
                    }
                    return Some((container, addr));
                }
                Err(e) => {
                    eprintln!("Vault get_host_port_ipv4 failed (attempt {attempt}): {e}");
                    continue;
                }
            }
        }
        eprintln!("skipping Vault test: failed after 3 attempts");
        None
    }

    /// Enable Transit secrets engine and create test keys.
    fn setup_vault_transit(vault_addr: &str) -> bool {
        let client = reqwest::blocking::Client::new();
        let token = "test-token";

        // Retry until Vault is ready
        for _ in 0..30 {
            let resp = client.get(format!("{vault_addr}/v1/sys/health")).send();
            match resp {
                Ok(r) if r.status().is_success() => break,
                _ => std::thread::sleep(std::time::Duration::from_secs(1)),
            }
        }

        // Enable Transit secrets engine
        let resp = client
            .post(format!("{vault_addr}/v1/sys/mounts/transit"))
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({"type": "transit"}))
            .send();
        if let Err(e) = resp {
            eprintln!("Failed to enable Transit: {e}");
            return false;
        }

        // Create test-key
        let resp = client
            .post(format!("{vault_addr}/v1/transit/keys/test-key"))
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({"type": "aes256-gcm96"}))
            .send();
        if let Err(e) = resp {
            eprintln!("Failed to create test-key: {e}");
            return false;
        }

        // Create test-key-b (for cross-key incompatibility test)
        let resp = client
            .post(format!("{vault_addr}/v1/transit/keys/test-key-b"))
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({"type": "aes256-gcm96"}))
            .send();
        if let Err(e) = resp {
            eprintln!("Failed to create test-key-b: {e}");
            return false;
        }

        true
    }

    /// Helper to construct VaultTransitKms with env vars set under mutex.
    fn make_vault_kms(vault_addr: &str, key_name: &str) -> VaultTransitKms {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::set_var("VAULT_TOKEN", "test-token");
        std::env::remove_var("VAULT_AUTH_METHOD");
        VaultTransitKms::new(vault_addr, key_name, None).unwrap()
    }

    /// Helper to construct VaultTransitKms with env vars set under mutex (async).
    /// Env vars are set under lock, then lock is released before the async call.
    /// VaultTransitKms::new_async reads VAULT_TOKEN at the start, so the env
    /// vars just need to be present when the constructor begins.
    async fn make_vault_kms_async(vault_addr: &str, key_name: &str) -> VaultTransitKms {
        let addr = vault_addr.to_string();
        let key = key_name.to_string();
        {
            let guard = ENV_MUTEX.lock().unwrap();
            std::env::set_var("VAULT_TOKEN", "test-token");
            std::env::remove_var("VAULT_AUTH_METHOD");
            drop(guard);
        }
        VaultTransitKms::new_async(&addr, &key, None).await.unwrap()
    }

    // ── Basic encrypt/decrypt roundtrip ──

    #[tokio::test]
    async fn test_vault_transit_encrypt_decrypt_roundtrip() {
        let vault_addr = match shared_vault().await {
            Some(v) => v,
            None => return,
        };

        let kms = tokio::task::spawn_blocking({
            let addr = vault_addr.clone();
            move || make_vault_kms(&addr, "test-key")
        })
        .await
        .unwrap();

        tokio::task::spawn_blocking(move || {
            let original_key = b"this is a 32 byte key for tests!";
            let encrypted = kms.encrypt_key(&(), original_key).unwrap();
            // Vault Transit ciphertext starts with "vault:v1:"
            let ct_str = std::str::from_utf8(&encrypted).unwrap();
            assert!(
                ct_str.starts_with("vault:v1:"),
                "expected vault:v1: prefix, got: {ct_str}"
            );

            let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();
            assert_eq!(decrypted, original_key);
        })
        .await
        .unwrap();
    }

    // ── Async encrypt/decrypt ──

    #[tokio::test]
    async fn test_vault_transit_encrypt_decrypt_async() {
        let vault_addr = match shared_vault().await {
            Some(v) => v,
            None => return,
        };

        let kms = make_vault_kms_async(&vault_addr, "test-key").await;

        let original_key = b"async test key -- 32 bytes long!";
        let encrypted = kms.encrypt_key_async(&(), original_key).await.unwrap();
        let ct_str = std::str::from_utf8(&encrypted).unwrap();
        assert!(ct_str.starts_with("vault:v1:"));

        let decrypted = kms.decrypt_key_async(&(), &encrypted).await.unwrap();
        assert_eq!(decrypted, original_key);
    }

    // ── Different keys are incompatible ──

    #[tokio::test]
    async fn test_vault_transit_different_keys_incompatible() {
        let vault_addr = match shared_vault().await {
            Some(v) => v,
            None => return,
        };

        let (kms_a, kms_b) = tokio::task::spawn_blocking({
            let addr = vault_addr.clone();
            move || {
                let a = make_vault_kms(&addr, "test-key");
                let b = make_vault_kms(&addr, "test-key-b");
                (a, b)
            }
        })
        .await
        .unwrap();

        tokio::task::spawn_blocking(move || {
            let original = b"cross-key test data 32 bytes!!!";
            let encrypted_a = kms_a.encrypt_key(&(), original).unwrap();

            // Decrypting with key B should fail
            let result = kms_b.decrypt_key(&(), &encrypted_a);
            assert!(result.is_err(), "decrypting with wrong key should fail");
        })
        .await
        .unwrap();
    }

    // ── Invalid token fails ──

    #[tokio::test]
    async fn test_vault_transit_invalid_token_fails() {
        let vault_addr = match shared_vault().await {
            Some(v) => v,
            None => return,
        };

        let addr = vault_addr.clone();
        tokio::task::spawn_blocking(move || {
            // Construct KMS with a bad token
            let guard = ENV_MUTEX.lock().unwrap();
            std::env::set_var("VAULT_TOKEN", "bad-token-that-does-not-exist");
            std::env::remove_var("VAULT_AUTH_METHOD");
            let kms = VaultTransitKms::new(&addr, "test-key", None).unwrap();
            drop(guard);

            let result = kms.encrypt_key(&(), b"should fail with auth error!!!!");
            assert!(result.is_err(), "encrypt with invalid token should fail");
            let err_msg = format!("{}", result.unwrap_err());
            assert!(
                err_msg.contains("permission denied") || err_msg.contains("errors"),
                "expected auth-related error, got: {err_msg}"
            );
        })
        .await
        .unwrap();
    }

    // ── Full session roundtrip ──

    #[tokio::test]
    async fn test_vault_transit_full_session_roundtrip() {
        let vault_addr = match shared_vault().await {
            Some(v) => v,
            None => return,
        };

        let addr = vault_addr.clone();
        tokio::task::spawn_blocking(move || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(make_vault_kms(&addr, "test-key"));
            let metastore = Arc::new(asherah::metastore::InMemoryMetastore::new());
            let cfg = asherah::Config::new("vault-test-svc", "vault-test-prod");
            let factory = asherah::api::new_session_factory(cfg, metastore, kms, crypto);
            let session = factory.get_session("vault-e2e");

            let plaintext = b"vault transit full session roundtrip payload";
            let drr = session.encrypt(plaintext).unwrap();
            let decrypted = session.decrypt(drr).unwrap();
            assert_eq!(decrypted, plaintext);

            // Second partition should also work
            let session2 = factory.get_session("vault-e2e-2");
            let drr2 = session2.encrypt(b"partition two data").unwrap();
            let out2 = session2.decrypt(drr2).unwrap();
            assert_eq!(out2, b"partition two data");
        })
        .await
        .unwrap();
    }

    // ── AppRole auth ──

    #[tokio::test]
    async fn test_vault_transit_approle_auth() {
        let vault_addr = match shared_vault().await {
            Some(v) => v,
            None => return,
        };

        // Set up AppRole auth in Vault using the root token
        let addr_clone = vault_addr.clone();
        let (role_id, secret_id) = tokio::task::spawn_blocking(move || setup_approle(&addr_clone))
            .await
            .unwrap();

        // Now construct a VaultTransitKms using AppRole auth
        let addr = vault_addr.clone();
        tokio::task::spawn_blocking(move || {
            let guard = ENV_MUTEX.lock().unwrap();
            std::env::remove_var("VAULT_TOKEN");
            std::env::set_var("VAULT_AUTH_METHOD", "approle");
            std::env::set_var("VAULT_APPROLE_ROLE_ID", &role_id);
            std::env::set_var("VAULT_APPROLE_SECRET_ID", &secret_id);

            let kms = VaultTransitKms::new(&addr, "test-key", None).unwrap();
            drop(guard);

            let original = b"approle auth test data 32 bytes!";
            let encrypted = kms.encrypt_key(&(), original).unwrap();
            let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();
            assert_eq!(decrypted, original);
        })
        .await
        .unwrap();
    }

    /// Enable AppRole auth, create a role with transit policy, and return (role_id, secret_id).
    fn setup_approle(vault_addr: &str) -> (String, String) {
        let client = reqwest::blocking::Client::new();
        let token = "test-token";

        // 1. Enable AppRole auth
        client
            .post(format!("{vault_addr}/v1/sys/auth/approle"))
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({"type": "approle"}))
            .send()
            .unwrap();

        // 2. Create policy allowing transit encrypt/decrypt
        let policy_hcl = r#"
            path "transit/encrypt/*" {
                capabilities = ["create", "update"]
            }
            path "transit/decrypt/*" {
                capabilities = ["create", "update"]
            }
        "#;
        client
            .put(format!("{vault_addr}/v1/sys/policies/acl/test-transit"))
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({"policy": policy_hcl}))
            .send()
            .unwrap();

        // 3. Create role with that policy
        client
            .post(format!("{vault_addr}/v1/auth/approle/role/test-role"))
            .header("X-Vault-Token", token)
            .json(&serde_json::json!({"policies": "test-transit"}))
            .send()
            .unwrap();

        // 4. Get role_id
        let resp: serde_json::Value = client
            .get(format!(
                "{vault_addr}/v1/auth/approle/role/test-role/role-id"
            ))
            .header("X-Vault-Token", token)
            .send()
            .unwrap()
            .json()
            .unwrap();
        let role_id = resp["data"]["role_id"].as_str().unwrap().to_string();

        // 5. Generate secret_id
        let resp: serde_json::Value = client
            .post(format!(
                "{vault_addr}/v1/auth/approle/role/test-role/secret-id"
            ))
            .header("X-Vault-Token", token)
            .send()
            .unwrap()
            .json()
            .unwrap();
        let secret_id = resp["data"]["secret_id"].as_str().unwrap().to_string();

        (role_id, secret_id)
    }
}

// ════════════════════════════════════════════════════════════════
// Secrets Manager KMS tests
// ════════════════════════════════════════════════════════════════

#[cfg(feature = "secrets-manager")]
mod secrets_manager_tests {
    use super::*;
    use asherah::kms_secrets_manager::SecretsManagerKMS;
    use asherah::traits::KeyManagementService;
    use std::sync::Arc;
    use testcontainers::runners::AsyncRunner;
    use testcontainers::ContainerAsync;
    use testcontainers_modules::localstack::LocalStack;
    use tokio::sync::OnceCell;

    struct SharedLocalStack {
        _container: ContainerAsync<LocalStack>,
        endpoint: String,
    }

    static SHARED_LOCALSTACK: OnceCell<Option<SharedLocalStack>> = OnceCell::const_new();

    async fn shared_localstack() -> Option<String> {
        SHARED_LOCALSTACK
            .get_or_init(async || {
                start_localstack_with_creds()
                    .await
                    .map(|(c, endpoint)| SharedLocalStack {
                        _container: c,
                        endpoint,
                    })
            })
            .await
            .as_ref()
            .map(|s| s.endpoint.clone())
    }

    async fn start_localstack_with_creds() -> Option<(ContainerAsync<LocalStack>, String)> {
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");

        for attempt in 0..3 {
            let container = match LocalStack::default().start().await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("skipping LocalStack test: Docker unavailable?: {e}");
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

    /// Create a Secrets Manager client pointing at LocalStack.
    async fn sm_client(endpoint: &str) -> aws_sdk_secretsmanager::Client {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::meta::region::RegionProviderChain::first_try(
                aws_sdk_secretsmanager::config::Region::new("us-east-1"),
            ))
            .load()
            .await;

        let sm_config = aws_sdk_secretsmanager::config::Builder::from(&config)
            .endpoint_url(endpoint)
            .build();

        aws_sdk_secretsmanager::Client::from_conf(sm_config)
    }

    /// Create a hex-encoded secret in Secrets Manager. Returns (secret_id, raw_key_bytes).
    async fn create_hex_secret(endpoint: &str, name: &str) -> (String, Vec<u8>) {
        let client = sm_client(endpoint).await;
        // Intentionally deterministic test fixture (not cryptographically secure key generation).
        // Keep fixed for reproducible integration tests only.
        let key: Vec<u8> = vec![
            0x42, 0x17, 0xA9, 0x5C, 0xEE, 0x03, 0x7D, 0x91,
            0x2B, 0xD4, 0x68, 0xFA, 0x10, 0xC7, 0x35, 0x8E,
            0x59, 0xB2, 0x0F, 0xC1, 0x74, 0x2D, 0x99, 0xE6,
            0x1A, 0x83, 0x4E, 0xB7, 0x20, 0xCD, 0x56, 0xF8,
        ];
        let hex_str: String = key.iter().map(|b| format!("{b:02x}")).collect();

        client
            .create_secret()
            .name(name)
            .secret_string(&hex_str)
            .send()
            .await
            .unwrap();

        (name.to_string(), key)
    }

    /// Create a binary secret in Secrets Manager. Returns (secret_id, raw_key_bytes).
    async fn create_binary_secret(endpoint: &str, name: &str) -> (String, Vec<u8>) {
        let client = sm_client(endpoint).await;
        // Intentionally predictable test vector for reproducibility in integration tests only.
        // This is intentionally weak key material and MUST NOT be used in production.
        let key: Vec<u8> = (0..32).map(|i| 255 - i).collect();

        client
            .create_secret()
            .name(name)
            .secret_binary(aws_sdk_secretsmanager::primitives::Blob::new(key.clone()))
            .send()
            .await
            .unwrap();

        (name.to_string(), key)
    }

    /// Helper: construct SecretsManagerKMS under the env mutex.
    fn make_sm_kms(endpoint: &str, secret_id: &str) -> SecretsManagerKMS<asherah::aead::AES256GCM> {
        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        with_endpoint(endpoint, || {
            SecretsManagerKMS::new(crypto, secret_id, Some("us-east-1".to_string()), None).unwrap()
        })
    }

    // ── Hex key roundtrip ──

    #[tokio::test]
    async fn test_secrets_manager_hex_key_roundtrip() {
        let endpoint = match shared_localstack().await {
            Some(v) => v,
            None => return,
        };

        let (secret_id, _key) = create_hex_secret(&endpoint, "test/hex-key").await;

        let endpoint_clone = endpoint.clone();
        tokio::task::spawn_blocking(move || {
            let kms = make_sm_kms(&endpoint_clone, &secret_id);
            let original = b"secrets manager hex key roundtrip test!!";
            let encrypted = kms.encrypt_key(&(), original).unwrap();
            assert_ne!(encrypted, original.to_vec());
            let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();
            assert_eq!(decrypted, original);
        })
        .await
        .unwrap();
    }

    // ── Binary key roundtrip ──

    #[tokio::test]
    async fn test_secrets_manager_binary_key_roundtrip() {
        let endpoint = match shared_localstack().await {
            Some(v) => v,
            None => return,
        };

        let (secret_id, _key) = create_binary_secret(&endpoint, "test/binary-key").await;

        let endpoint_clone = endpoint.clone();
        tokio::task::spawn_blocking(move || {
            let kms = make_sm_kms(&endpoint_clone, &secret_id);
            let original = b"secrets manager binary key roundtrip test";
            let encrypted = kms.encrypt_key(&(), original).unwrap();
            assert_ne!(encrypted, original.to_vec());
            let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();
            assert_eq!(decrypted, original);
        })
        .await
        .unwrap();
    }

    // ── Async constructor ──

    #[tokio::test]
    async fn test_secrets_manager_async_constructor() {
        let endpoint = match shared_localstack().await {
            Some(v) => v,
            None => return,
        };

        let (secret_id, _key) = create_hex_secret(&endpoint, "test/async-key").await;

        let crypto = Arc::new(asherah::aead::AES256GCM::new());
        {
            let guard = ENV_MUTEX.lock().unwrap();
            std::env::set_var("AWS_ENDPOINT_URL", &endpoint);
            drop(guard);
        }
        let kms =
            SecretsManagerKMS::new_async(crypto, &secret_id, Some("us-east-1".to_string()), None)
                .await
                .unwrap();

        let original = b"async constructor test data!!!!!!";
        let encrypted = kms.encrypt_key(&(), original).unwrap();
        let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    // ── Nonexistent secret fails ──

    #[tokio::test]
    async fn test_secrets_manager_nonexistent_secret_fails() {
        let endpoint = match shared_localstack().await {
            Some(v) => v,
            None => return,
        };

        let endpoint_clone = endpoint.clone();
        tokio::task::spawn_blocking(move || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let result = with_endpoint(&endpoint_clone, || {
                SecretsManagerKMS::new(
                    crypto,
                    "nonexistent/secret/id",
                    Some("us-east-1".to_string()),
                    None,
                )
            });
            let err = result
                .err()
                .expect("constructing KMS with nonexistent secret should fail");
            let err_msg = format!("{err}");
            assert!(
                err_msg.contains("GetSecretValue failed")
                    || err_msg.contains("ResourceNotFoundException")
                    || err_msg.contains("not found"),
                "expected resource-not-found error, got: {err_msg}"
            );
        })
        .await
        .unwrap();
    }

    // ── Full session roundtrip ──

    #[tokio::test]
    async fn test_secrets_manager_full_session_roundtrip() {
        let endpoint = match shared_localstack().await {
            Some(v) => v,
            None => return,
        };

        let (secret_id, _key) = create_hex_secret(&endpoint, "test/session-key").await;

        let endpoint_clone = endpoint.clone();
        tokio::task::spawn_blocking(move || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());
            let kms = Arc::new(make_sm_kms(&endpoint_clone, &secret_id));
            let metastore = Arc::new(asherah::metastore::InMemoryMetastore::new());
            let cfg = asherah::Config::new("sm-test-svc", "sm-test-prod");
            let factory = asherah::api::new_session_factory(cfg, metastore, kms, crypto);
            let session = factory.get_session("sm-e2e");

            let plaintext = b"secrets manager full session roundtrip payload";
            let drr = session.encrypt(plaintext).unwrap();
            let decrypted = session.decrypt(drr).unwrap();
            assert_eq!(decrypted, plaintext);

            // Second partition should also work
            let session2 = factory.get_session("sm-e2e-2");
            let drr2 = session2.encrypt(b"sm partition two").unwrap();
            let out2 = session2.decrypt(drr2).unwrap();
            assert_eq!(out2, b"sm partition two");
        })
        .await
        .unwrap();
    }

    // ── Wire compatibility with StaticKMS ──

    #[tokio::test]
    async fn test_secrets_manager_matches_static_kms() {
        let endpoint = match shared_localstack().await {
            Some(v) => v,
            None => return,
        };

        // Create a secret with a known key
        let known_key: Vec<u8> = vec![0xAB_u8; 32];
        let hex_str: String = known_key.iter().map(|b| format!("{b:02x}")).collect();
        let client = sm_client(&endpoint).await;
        client
            .create_secret()
            .name("test/wire-compat-key")
            .secret_string(&hex_str)
            .send()
            .await
            .unwrap();

        let endpoint_clone = endpoint.clone();
        let known_key_clone = known_key.clone();
        tokio::task::spawn_blocking(move || {
            let crypto = Arc::new(asherah::aead::AES256GCM::new());

            // Encrypt with StaticKMS using the same key
            let static_kms = asherah::kms::StaticKMS::new(crypto.clone(), known_key_clone).unwrap();
            let original = b"wire compatibility test data!!!!!";
            let encrypted = static_kms.encrypt_key(&(), original).unwrap();

            // Decrypt with SecretsManagerKMS (same underlying key from SM)
            let sm_kms = make_sm_kms(&endpoint_clone, "test/wire-compat-key");
            let decrypted = sm_kms.decrypt_key(&(), &encrypted).unwrap();
            assert_eq!(decrypted, original);

            // And the reverse: encrypt with SM, decrypt with Static
            let encrypted2 = sm_kms.encrypt_key(&(), original).unwrap();
            let decrypted2 = static_kms.decrypt_key(&(), &encrypted2).unwrap();
            assert_eq!(decrypted2, original);
        })
        .await
        .unwrap();
    }
}
