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
    #[serde(rename = "EnableRegionSuffix")]
    pub enable_region_suffix: Option<bool>,
    #[serde(rename = "EnableSessionCaching")]
    pub enable_session_caching: Option<bool>,
    #[serde(rename = "Verbose")]
    pub verbose: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct AppliedConfig {
    pub verbose: bool,
    pub enable_session_caching: bool,
}

fn set_env_opt_str(key: &str, value: Option<&str>) {
    match value {
        Some(v) if !v.is_empty() => std::env::set_var(key, v),
        Some(_) | None => std::env::remove_var(key),
    }
}

fn set_env_opt_i64(key: &str, value: Option<i64>) {
    match value {
        Some(v) => std::env::set_var(key, v.to_string()),
        None => std::env::remove_var(key),
    }
}

fn set_env_opt_u32(key: &str, value: Option<u32>) {
    match value {
        Some(v) => std::env::set_var(key, v.to_string()),
        None => std::env::remove_var(key),
    }
}

fn set_env_opt_bool(key: &str, value: Option<bool>) {
    match value {
        Some(true) => std::env::set_var(key, "1"),
        Some(false) => std::env::set_var(key, "0"),
        None => std::env::remove_var(key),
    }
}

impl ConfigOptions {
    pub fn from_json(json: &str) -> Result<Self> {
        let cfg = serde_json::from_str(json).context("invalid config JSON")?;
        Ok(cfg)
    }

    pub fn apply_env(&self) -> Result<AppliedConfig> {
        // Normalize legacy/debug aliases to supported values.
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
            .ok_or_else(|| anyhow!("ServiceName is required"))?;
        let product_id = self
            .product_id
            .as_ref()
            .ok_or_else(|| anyhow!("ProductID is required"))?;
        let metastore_raw = self
            .metastore
            .as_ref()
            .ok_or_else(|| anyhow!("Metastore is required"))?;
        let metastore = normalize_alias(metastore_raw);

        set_env_opt_str("SERVICE_NAME", Some(service_name));
        set_env_opt_str("PRODUCT_ID", Some(product_id));

        set_env_opt_i64("EXPIRE_AFTER_SECS", self.expire_after);
        set_env_opt_i64("REVOKE_CHECK_INTERVAL_SECS", self.check_interval);
        set_env_opt_i64("SESSION_CACHE_DURATION_SECS", self.session_cache_duration);
        set_env_opt_u32("SESSION_CACHE_MAX_SIZE", self.session_cache_max_size);
        set_env_opt_str(
            "REPLICA_READ_CONSISTENCY",
            self.replica_read_consistency.as_deref(),
        );

        let enable_session_caching = self.enable_session_caching.unwrap_or(true);
        set_env_opt_bool("SESSION_CACHE", Some(enable_session_caching));

        std::env::set_var("Metastore", &metastore);
        match metastore.as_str() {
            "memory" => {
                std::env::remove_var("SQLITE_PATH");
                std::env::remove_var("POSTGRES_URL");
                std::env::remove_var("MYSQL_URL");
                std::env::remove_var("DDB_TABLE");
            }
            "sqlite" => {
                if let Some(conn) = &self.connection_string {
                    std::env::set_var("SQLITE_PATH", normalize_sqlite_path(conn));
                } else {
                    return Err(anyhow!(
                        "ConnectionString is required when Metastore is sqlite"
                    ));
                }
                std::env::remove_var("POSTGRES_URL");
                std::env::remove_var("MYSQL_URL");
                std::env::remove_var("DDB_TABLE");
            }
            "rdbms" => {
                if let Some(conn) = &self.connection_string {
                    apply_rdbms_connection(conn);
                } else {
                    return Err(anyhow!(
                        "ConnectionString is required when Metastore is rdbms"
                    ));
                }
                std::env::remove_var("DDB_TABLE");
            }
            "dynamodb" => {
                set_env_opt_str("DDB_TABLE", self.dynamo_db_table_name.as_deref());
                set_env_opt_str("AWS_REGION", self.dynamo_db_region.as_deref());
                set_env_opt_str("AWS_ENDPOINT_URL", self.dynamo_db_endpoint.as_deref());
                set_env_opt_bool("DDB_REGION_SUFFIX", self.enable_region_suffix);
                std::env::remove_var("SQLITE_PATH");
                std::env::remove_var("POSTGRES_URL");
                std::env::remove_var("MYSQL_URL");
            }
            other => {
                return Err(anyhow!("Unsupported Metastore value: {other}"));
            }
        }

        set_env_opt_str("CONNECTION_STRING", self.connection_string.as_deref());

        if let Some(region_map) = &self.region_map {
            let as_json = serde_json::to_string(region_map).context("RegionMap JSON")?;
            std::env::set_var("REGION_MAP", as_json);
        } else {
            std::env::remove_var("REGION_MAP");
        }

        let kms_raw = self.kms.as_deref().unwrap_or("static");
        let kms = normalize_alias(kms_raw);
        std::env::set_var("KMS", &kms);
        set_env_opt_str("PREFERRED_REGION", self.preferred_region.as_deref());

        let verbose = self.verbose.unwrap_or(false);
        if verbose {
            std::env::set_var("ASHERAH_VERBOSE", "1");
        } else {
            std::env::remove_var("ASHERAH_VERBOSE");
        }

        Ok(AppliedConfig {
            verbose,
            enable_session_caching,
        })
    }
}

fn normalize_sqlite_path(conn: &str) -> String {
    if let Some(stripped) = conn.strip_prefix("sqlite://") {
        stripped.to_string()
    } else {
        conn.to_string()
    }
}

fn apply_rdbms_connection(conn: &str) {
    let lower = conn.to_lowercase();
    std::env::remove_var("SQLITE_PATH");
    std::env::remove_var("POSTGRES_URL");
    std::env::remove_var("MYSQL_URL");
    if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
        std::env::set_var("POSTGRES_URL", conn);
    } else if lower.starts_with("mysql://") {
        std::env::set_var("MYSQL_URL", conn);
    } else if lower.starts_with("sqlite://") {
        std::env::set_var("SQLITE_PATH", normalize_sqlite_path(conn));
    } else {
        std::env::set_var("SQLITE_PATH", conn);
    }
}

pub fn factory_from_config(config: &ConfigOptions) -> Result<(Factory, AppliedConfig)> {
    let applied = config.apply_env()?;
    let factory = asherah::builders::factory_from_env()?;
    Ok((factory, applied))
}
