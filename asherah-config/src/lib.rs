//! # Asherah Config
//!
//! Shared configuration types for Asherah language bindings. Handles
//! environment variable transport, config option parsing, and factory
//! construction from JSON or environment-based configuration.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

type Factory = asherah::session::PublicFactory<
    asherah::aead::AES256GCM,
    asherah::builders::DynKms,
    asherah::builders::DynMetastore,
>;

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(default)]
pub struct ConfigOptions {
    #[serde(rename = "ServiceName")]
    pub service_name: Option<String>,
    #[serde(rename = "ProductID")]
    pub product_id: Option<String>,
    #[serde(rename = "ExpireAfter")]
    pub expire_after: Option<i64>,
    #[serde(rename = "CheckInterval")]
    pub check_interval: Option<i64>,
    #[serde(rename = "Metastore")]
    pub metastore: Option<String>,
    #[serde(rename = "ConnectionString")]
    pub connection_string: Option<String>,
    #[serde(rename = "ReplicaReadConsistency")]
    pub replica_read_consistency: Option<String>,
    #[serde(rename = "DynamoDBEndpoint")]
    pub dynamo_db_endpoint: Option<String>,
    #[serde(rename = "DynamoDBRegion")]
    pub dynamo_db_region: Option<String>,
    #[serde(rename = "DynamoDBSigningRegion")]
    pub dynamo_db_signing_region: Option<String>,
    #[serde(rename = "DynamoDBTableName")]
    pub dynamo_db_table_name: Option<String>,
    #[serde(rename = "SessionCacheMaxSize")]
    pub session_cache_max_size: Option<u32>,
    #[serde(rename = "SessionCacheDuration")]
    pub session_cache_duration: Option<i64>,
    #[serde(rename = "KMS")]
    pub kms: Option<String>,
    #[serde(rename = "RegionMap")]
    pub region_map: Option<HashMap<String, String>>,
    #[serde(rename = "PreferredRegion")]
    pub preferred_region: Option<String>,
    #[serde(rename = "AwsProfileName")]
    pub aws_profile_name: Option<String>,
    #[serde(rename = "EnableRegionSuffix")]
    pub enable_region_suffix: Option<bool>,
    #[serde(rename = "EnableSessionCaching")]
    pub enable_session_caching: Option<bool>,
    #[serde(rename = "Verbose")]
    pub verbose: Option<bool>,
    /// SQL metastore DB type (e.g., "mysql", "postgres"). Go compatibility field.
    #[serde(rename = "SQLMetastoreDBType")]
    pub sql_metastore_db_type: Option<String>,
    /// Disable zero-copy optimization.
    #[serde(rename = "DisableZeroCopy")]
    pub disable_zero_copy: Option<bool>,
    /// Enable null data validation.
    #[serde(rename = "NullDataCheck")]
    pub null_data_check: Option<bool>,
    /// Enable canary buffer overflow detection.
    #[serde(rename = "EnableCanaries")]
    pub enable_canaries: Option<bool>,

    // --- Connection Pool ---
    /// Maximum number of open database connections (0 = unlimited).
    /// Alias for ASHERAH_POOL_SIZE. Env: ASHERAH_POOL_MAX_OPEN
    #[serde(rename = "PoolMaxOpen")]
    pub pool_max_open: Option<usize>,
    /// Maximum number of idle connections to retain (default: 2).
    /// Env: ASHERAH_POOL_MAX_IDLE
    #[serde(rename = "PoolMaxIdle")]
    pub pool_max_idle: Option<usize>,
    /// Maximum lifetime of a connection in seconds (0 = unlimited).
    /// Env: ASHERAH_POOL_MAX_LIFETIME
    #[serde(rename = "PoolMaxLifetime")]
    pub pool_max_lifetime: Option<u64>,
    /// Maximum time in seconds a connection can sit idle (0 = unlimited).
    /// Env: ASHERAH_POOL_MAX_IDLE_TIME
    #[serde(rename = "PoolMaxIdleTime")]
    pub pool_max_idle_time: Option<u64>,

    // --- KMS: Static ---
    /// Hex-encoded static master key (for KMS=static).
    #[serde(rename = "StaticMasterKeyHex")]
    pub static_master_key_hex: Option<String>,

    // --- KMS: AWS ---
    /// AWS KMS key ID or ARN (single-region mode).
    #[serde(rename = "KmsKeyId")]
    pub kms_key_id: Option<String>,

    // --- KMS: AWS Secrets Manager ---
    /// Secrets Manager secret ARN or name containing the master key.
    #[serde(rename = "SecretsManagerSecretId")]
    pub secrets_manager_secret_id: Option<String>,

    // --- KMS: HashiCorp Vault Transit ---
    /// Vault server URL (e.g., https://vault.example.com:8200).
    #[serde(rename = "VaultAddr")]
    pub vault_addr: Option<String>,
    /// Vault authentication token (for token auth).
    #[serde(rename = "VaultToken")]
    pub vault_token: Option<String>,
    /// Vault auth method: "kubernetes", "approle", "cert".
    #[serde(rename = "VaultAuthMethod")]
    pub vault_auth_method: Option<String>,
    /// Vault role name (for Kubernetes and AppRole auth).
    #[serde(rename = "VaultAuthRole")]
    pub vault_auth_role: Option<String>,
    /// Vault auth backend mount path (default: auth method name).
    #[serde(rename = "VaultAuthMount")]
    pub vault_auth_mount: Option<String>,
    /// AppRole role ID.
    #[serde(rename = "VaultApproleRoleId")]
    pub vault_approle_role_id: Option<String>,
    /// AppRole secret ID.
    #[serde(rename = "VaultApproleSecretId")]
    pub vault_approle_secret_id: Option<String>,
    /// Path to TLS client certificate PEM (for cert auth).
    #[serde(rename = "VaultClientCert")]
    pub vault_client_cert: Option<String>,
    /// Path to TLS client key PEM (for cert auth).
    #[serde(rename = "VaultClientKey")]
    pub vault_client_key: Option<String>,
    /// Path to Kubernetes service account token (default: /var/run/secrets/...).
    #[serde(rename = "VaultK8sTokenPath")]
    pub vault_k8s_token_path: Option<String>,
    /// Vault Transit key name (required for KMS=vault).
    #[serde(rename = "VaultTransitKey")]
    pub vault_transit_key: Option<String>,
    /// Vault Transit mount path (default: "transit").
    #[serde(rename = "VaultTransitMount")]
    pub vault_transit_mount: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AppliedConfig {
    pub verbose: bool,
    pub enable_session_caching: bool,
    pub enable_canaries: bool,
}

use asherah::builders::{KmsConfig, MetastoreConfig, PolicyConfig, PoolConfig, ResolvedConfig};

impl ConfigOptions {
    pub fn from_json(json: &str) -> Result<Self> {
        let cfg = serde_json::from_str(json).context("invalid config JSON")?;
        Ok(cfg)
    }

    /// Resolve into a structured config — no env var reads or writes.
    pub fn resolve(&self) -> Result<(ResolvedConfig, AppliedConfig)> {
        fn normalize_alias(value: &str) -> String {
            match value.to_lowercase().as_str() {
                "test-debug-memory" => "memory".to_string(),
                "test-debug-sqlite" => "sqlite".to_string(),
                "test-debug-static" => "static".to_string(),
                other => other.to_string(),
            }
        }

        let service_name = self
            .service_name
            .as_ref()
            .ok_or_else(|| anyhow!("ServiceName is required"))?
            .clone();
        let product_id = self
            .product_id
            .as_ref()
            .ok_or_else(|| anyhow!("ProductID is required"))?
            .clone();
        let metastore_raw = self
            .metastore
            .as_ref()
            .ok_or_else(|| anyhow!("Metastore is required"))?;
        let metastore_kind = normalize_alias(metastore_raw);

        let pool = PoolConfig {
            max_open: self.pool_max_open,
            max_idle: self.pool_max_idle,
            max_lifetime_s: self.pool_max_lifetime,
            max_idle_time_s: self.pool_max_idle_time,
        };

        let metastore = match metastore_kind.as_str() {
            "memory" => MetastoreConfig::Memory,
            "sqlite" => {
                let conn = self.connection_string.as_ref().ok_or_else(|| {
                    anyhow!("ConnectionString is required when Metastore is sqlite")
                })?;
                MetastoreConfig::Sqlite {
                    path: normalize_sqlite_path(conn),
                }
            }
            "rdbms" => {
                let conn = self.connection_string.as_ref().ok_or_else(|| {
                    anyhow!("ConnectionString is required when Metastore is rdbms")
                })?;
                resolve_rdbms_connection(
                    conn,
                    self.sql_metastore_db_type.as_deref(),
                    self.replica_read_consistency.clone(),
                    pool.clone(),
                )?
            }
            "dynamodb" => {
                let effective_region = self
                    .dynamo_db_signing_region
                    .as_deref()
                    .or(self.dynamo_db_region.as_deref())
                    .map(String::from);
                MetastoreConfig::DynamoDb {
                    table: self
                        .dynamo_db_table_name
                        .clone()
                        .unwrap_or_else(|| "EncryptionKey".to_string()),
                    region: effective_region,
                    endpoint: self.dynamo_db_endpoint.clone(),
                    region_suffix: self.enable_region_suffix.unwrap_or(false),
                }
            }
            other => {
                return Err(anyhow!("Unsupported Metastore value: {other}"));
            }
        };

        let aws_profile_name = self.aws_profile_name.clone();

        let kms_raw = self.kms.as_deref().unwrap_or("static");
        let kms_kind = normalize_alias(kms_raw);
        let kms = match kms_kind.as_str() {
            "static" => KmsConfig::Static {
                key_hex: self.static_master_key_hex.clone().unwrap_or_default(),
            },
            "aws" => KmsConfig::Aws {
                region_map: self.region_map.clone(),
                preferred_region: self.preferred_region.clone(),
                key_id: self.kms_key_id.clone(),
                region: self
                    .dynamo_db_signing_region
                    .as_deref()
                    .or(self.dynamo_db_region.as_deref())
                    .map(String::from),
            },
            "secrets-manager" => KmsConfig::SecretsManager {
                secret_id: self.secrets_manager_secret_id.clone().ok_or_else(|| {
                    anyhow!("SecretsManagerSecretId required for KMS=secrets-manager")
                })?,
                region: None,
            },
            "vault" | "vault-transit" => KmsConfig::Vault {
                addr: self
                    .vault_addr
                    .clone()
                    .ok_or_else(|| anyhow!("VaultAddr required for KMS=vault"))?,
                transit_key: self
                    .vault_transit_key
                    .clone()
                    .ok_or_else(|| anyhow!("VaultTransitKey required for KMS=vault"))?,
                transit_mount: self.vault_transit_mount.clone(),
            },
            other => {
                anyhow::bail!("Unknown KMS type '{other}'");
            }
        };

        let policy = PolicyConfig {
            expire_key_after_s: self.expire_after,
            create_date_precision_s: None,
            revoke_check_interval_s: self.check_interval,
            session_cache_max_size: self.session_cache_max_size.map(|v| v as usize),
            session_cache_ttl_s: self.session_cache_duration,
            shared_intermediate_key_cache: None,
            intermediate_key_cache_max_size: None,
        };

        let enable_session_caching = self.enable_session_caching.unwrap_or(true);
        let verbose = self.verbose.unwrap_or(false);
        let enable_canaries = self.enable_canaries.unwrap_or(false);

        let resolved = ResolvedConfig {
            service_name,
            product_id,
            region_suffix: None,
            aws_profile_name,
            metastore,
            kms,
            policy,
        };

        let applied = AppliedConfig {
            verbose,
            enable_session_caching,
            enable_canaries,
        };

        Ok((resolved, applied))
    }
}

fn normalize_sqlite_path(conn: &str) -> String {
    if let Some(stripped) = conn.strip_prefix("sqlite://") {
        stripped.to_string()
    } else {
        conn.to_string()
    }
}

/// Extract Go `go-sql-driver/mysql` `tls` parameter value from a connection string.
/// Splits at the last `@` first so that `?` characters in passwords are not
/// mistaken for the query-string separator.
fn extract_go_mysql_tls(conn: &str) -> Option<String> {
    // Look for query params only in the part after the last '@' (i.e. not in userinfo)
    let after_userinfo = conn.rsplit_once('@').map(|(_, r)| r).unwrap_or(conn);
    let query = after_userinfo.split_once('?').map(|(_, q)| q)?;
    for param in query.split('&') {
        if let Some(("tls", value)) = param.split_once('=') {
            return Some(value.to_string());
        }
    }
    None
}

fn resolve_rdbms_connection(
    conn: &str,
    db_type_hint: Option<&str>,
    replica_consistency: Option<String>,
    pool: PoolConfig,
) -> Result<MetastoreConfig> {
    use asherah::builders::{classify_connection_string, DbKind};

    let kind = classify_connection_string(conn);
    let kind = match kind {
        DbKind::Unknown(s) => match db_type_hint.map(|h| h.to_lowercase()).as_deref() {
            Some("mysql") => DbKind::Mysql(format!("mysql://{s}")),
            Some("postgres" | "postgresql") => DbKind::Postgres(format!("postgres://{s}")),
            _ => DbKind::Unknown(s),
        },
        other => other,
    };

    match kind {
        DbKind::Postgres(url) => Ok(MetastoreConfig::Postgres {
            url,
            replica_consistency,
            pool,
        }),
        DbKind::Mysql(url) => {
            let tls_mode = extract_go_mysql_tls(conn);
            Ok(MetastoreConfig::Mysql {
                url,
                tls_mode,
                replica_consistency,
                pool,
            })
        }
        DbKind::Sqlite(path) => Ok(MetastoreConfig::Sqlite { path }),
        DbKind::Unknown(s) => {
            anyhow::bail!(
                "Unrecognized RDBMS connection string format: '{s}'. \
                 Set SQLMetastoreDBType to 'mysql' or 'postgres', or use a \
                 standard connection URL (mysql://... or postgres://...)"
            );
        }
    }
}

/// Build a factory from structured config — no env var side effects.
pub fn factory_from_config(config: &ConfigOptions) -> Result<(Factory, AppliedConfig)> {
    let (resolved, applied) = config.resolve()?;
    let factory = asherah::builders::factory_from_resolved(&resolved)?;
    Ok((factory, applied))
}

/// Async variant — safe for concurrent use since no env vars are touched.
pub async fn factory_from_config_async(config: &ConfigOptions) -> Result<(Factory, AppliedConfig)> {
    let (resolved, applied) = config.resolve()?;
    let factory = asherah::builders::factory_from_resolved_async(&resolved).await?;
    Ok((factory, applied))
}
