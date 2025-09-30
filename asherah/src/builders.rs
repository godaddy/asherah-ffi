use std::sync::Arc;

use crate::traits::Metastore;

type MetastoreEnvResult = (Arc<dyn Metastore>, String, String, Option<String>);

pub enum StoreChoice {
    InMemory,
    #[cfg(feature = "postgres")]
    Postgres,
    #[cfg(feature = "mysql")]
    MySql,
    #[cfg(feature = "dynamodb")]
    DynamoDb,
}

pub struct FromEnvResult<M: Metastore + Clone + 'static> {
    pub metastore: Arc<M>,
    pub service: String,
    pub product: String,
    pub region_suffix: Option<String>,
}

// Build Config pieces and a Metastore from environment variables.
// Supported env vars:
//  SERVICE_NAME, PRODUCT_ID, REGION_SUFFIX
//  POSTGRES_URL | MYSQL_URL | (DDB_TABLE [+ AWS_REGION/AWS_ENDPOINT_URL])
pub fn metastore_from_env() -> anyhow::Result<MetastoreEnvResult> {
    let service = std::env::var("SERVICE_NAME").unwrap_or_else(|_| "service".to_string());
    let product = std::env::var("PRODUCT_ID").unwrap_or_else(|_| "product".to_string());
    let region_suffix = std::env::var("REGION_SUFFIX").ok();

    // Decide by explicit Metastore or environment
    let mchoice = std::env::var("Metastore")
        .unwrap_or_else(|_| "memory".to_string())
        .to_lowercase();
    if std::env::var("ASHERAH_INTEROP_DEBUG").is_ok() {
        eprintln!(
            "metastore_from_env choice={} sqlite_path={:?}",
            mchoice,
            std::env::var("SQLITE_PATH").ok()
        );
    }
    if mchoice == "sqlite" || std::env::var("SQLITE_PATH").is_ok() {
        #[cfg(feature = "sqlite")]
        {
            let path = std::env::var("SQLITE_PATH").unwrap_or_else(|_| ":memory:".to_string());
            let sqlite = crate::metastore_sqlite::SqliteMetastore::open(&path)?;
            return Ok((Arc::new(sqlite), service, product, region_suffix));
        }
        #[cfg(not(feature = "sqlite"))]
        anyhow::bail!("Enable feature 'sqlite' to use SQLite metastore");
    }

    if mchoice == "dynamodb" || std::env::var("DDB_TABLE").is_ok() {
        #[cfg(feature = "dynamodb")]
        {
            let table = std::env::var("DDB_TABLE").unwrap_or_else(|_| "EncryptionKey".to_string());
            let region = std::env::var("AWS_REGION").ok();
            let ddb = crate::metastore_dynamodb::DynamoDbMetastore::new(table, region)?;
            return Ok((Arc::new(ddb), service, product, region_suffix));
        }
        #[cfg(not(feature = "dynamodb"))]
        anyhow::bail!("Enable feature 'dynamodb' to use DynamoDB metastore");
    }
    if mchoice == "rdbms" || std::env::var("POSTGRES_URL").is_ok() {
        #[cfg(feature = "postgres")]
        if let Ok(url) = std::env::var("POSTGRES_URL") {
            let pg = crate::metastore_postgres::PostgresMetastore::connect(&url)?;
            return Ok((Arc::new(pg), service, product, region_suffix));
        }
        #[cfg(not(feature = "postgres"))]
        if std::env::var("POSTGRES_URL").is_ok() {
            anyhow::bail!("Enable feature 'postgres' to use Postgres metastore");
        }
    }
    if mchoice == "rdbms" || std::env::var("MYSQL_URL").is_ok() {
        #[cfg(feature = "mysql")]
        if let Ok(url) = std::env::var("MYSQL_URL") {
            let my = crate::metastore_mysql::MySqlMetastore::connect(&url)?;
            return Ok((Arc::new(my), service, product, region_suffix));
        }
        #[cfg(not(feature = "mysql"))]
        if std::env::var("MYSQL_URL").is_ok() {
            anyhow::bail!("Enable feature 'mysql' to use MySQL metastore");
        }
    }
    // Fallback to in-memory
    let mem = crate::metastore::InMemoryMetastore::new();
    Ok((Arc::new(mem), service, product, region_suffix))
}

// Build a Config from env and return it.
pub fn config_from_env() -> crate::Config {
    let service = std::env::var("SERVICE_NAME").unwrap_or_else(|_| "service".to_string());
    let product = std::env::var("PRODUCT_ID").unwrap_or_else(|_| "product".to_string());
    let mut cfg = crate::Config::new(service, product);
    if let Ok(sfx) = std::env::var("REGION_SUFFIX") {
        cfg = cfg.with_region_suffix(sfx);
    }
    // Policy envs (optional)
    fn get_i64(k: &str) -> Option<i64> {
        std::env::var(k).ok().and_then(|v| v.parse::<i64>().ok())
    }
    fn get_usize(k: &str) -> Option<usize> {
        std::env::var(k).ok().and_then(|v| v.parse::<usize>().ok())
    }
    fn get_bool(k: &str) -> Option<bool> {
        std::env::var(k)
            .ok()
            .and_then(|v| match v.to_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => Some(true),
                "0" | "false" | "no" | "off" => Some(false),
                _ => None,
            })
    }
    if let Some(v) = get_i64("EXPIRE_AFTER_SECS") {
        cfg.policy.expire_key_after_s = v;
    }
    if let Some(v) = get_i64("CREATE_DATE_PRECISION_SECS") {
        cfg.policy.create_date_precision_s = v;
    }
    if let Some(v) = get_i64("REVOKE_CHECK_INTERVAL_SECS") {
        cfg.policy.revoke_check_interval_s = v;
    }
    if let Some(b) = get_bool("SESSION_CACHE") {
        cfg.policy.cache_sessions = b;
    }
    if let Some(v) = get_usize("SESSION_CACHE_MAX_SIZE") {
        cfg.policy.session_cache_max_size = v;
    }
    if let Some(v) = get_i64("SESSION_CACHE_DURATION_SECS") {
        cfg.policy.session_cache_ttl_s = v;
    }
    if let Some(b) = get_bool("CACHE_SYSTEM_KEYS") {
        cfg.policy.cache_system_keys = b;
    }
    if let Some(b) = get_bool("CACHE_INTERMEDIATE_KEYS") {
        cfg.policy.cache_intermediate_keys = b;
    }
    if let Some(b) = get_bool("SHARED_INTERMEDIATE_KEY_CACHE") {
        cfg.policy.shared_intermediate_key_cache = b;
    }
    cfg
}

// === Dynamic wrappers to pass trait-objects through generic factory ===
#[derive(Clone)]
pub struct DynKms(pub Arc<dyn crate::traits::KeyManagementService>);
impl crate::traits::KeyManagementService for DynKms {
    fn encrypt_key(&self, ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.0.encrypt_key(ctx, key_bytes)
    }
    fn decrypt_key(&self, ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.0.decrypt_key(ctx, blob)
    }
}

#[derive(Clone)]
pub struct DynMetastore(pub Arc<dyn crate::traits::Metastore>);
impl crate::traits::Metastore for DynMetastore {
    fn load(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<crate::types::EnvelopeKeyRecord>, anyhow::Error> {
        self.0.load(id, created)
    }
    fn load_latest(
        &self,
        id: &str,
    ) -> Result<Option<crate::types::EnvelopeKeyRecord>, anyhow::Error> {
        self.0.load_latest(id)
    }
    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &crate::types::EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        self.0.store(id, created, ekr)
    }
    fn region_suffix(&self) -> Option<String> {
        self.0.region_suffix()
    }
}

// Build a full PublicFactory from environment.
// Supported env:
//  SERVICE_NAME, PRODUCT_ID, REGION_SUFFIX
//  KMS: "static" | "aws" (default: static)
//  STATIC_MASTER_KEY_HEX (required if KMS=static)
//  Metastore: "rdbms" | "dynamodb" | "memory" (default: memory)
//  CONNECTION_STRING (for rdbms)
//  DDB_TABLE (for dynamodb)
//  AWS_REGION (for aws kms / ddb)
pub fn factory_from_env(
) -> anyhow::Result<crate::session::PublicFactory<crate::aead::AES256GCM, DynKms, DynMetastore>> {
    let cfg = config_from_env();
    let (store_dyn, _svc, _prod, _sfx) = metastore_from_env()?;
    let metastore = Arc::new(DynMetastore(store_dyn));
    let crypto = Arc::new(crate::aead::AES256GCM::new());
    let kms_kind = std::env::var("KMS")
        .unwrap_or_else(|_| "static".into())
        .to_lowercase();
    let kms_dyn: Arc<dyn crate::traits::KeyManagementService> = match kms_kind.as_str() {
        "aws" => {
            // Envelope-compatible KMS: single region via KMS_KEY_ID, multi-region via REGION_MAP (+ PREFERRED_REGION)
            if let Ok(map_json) = std::env::var("REGION_MAP") {
                let regions: std::collections::HashMap<String, String> =
                    serde_json::from_str(&map_json)?;
                let preferred = std::env::var("PREFERRED_REGION").ok();
                let mut entries: Vec<(String, String)> = Vec::new();
                let mut pref_idx = 0usize;
                for (i, (region, key)) in regions.iter().enumerate() {
                    if preferred.as_ref() == Some(region) {
                        pref_idx = i;
                    }
                    entries.push((region.clone(), key.clone()));
                }
                let kms = crate::kms_aws_envelope::AwsKmsEnvelope::new_multi(
                    crypto.clone(),
                    pref_idx,
                    entries,
                )?;
                Arc::new(kms)
            } else {
                let key_id = std::env::var("KMS_KEY_ID")
                    .map_err(|_| anyhow::anyhow!("KMS_KEY_ID required for KMS=aws"))?;
                let region = std::env::var("AWS_REGION").ok();
                let kms = crate::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id,
                    region,
                )?;
                Arc::new(kms)
            }
        }
        _ => {
            let hex = std::env::var("STATIC_MASTER_KEY_HEX").unwrap_or_else(|_| "00".repeat(32));
            let mut key = vec![0u8; hex.len() / 2];
            for i in 0..key.len() {
                key[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap_or(0);
            }
            let kms = crate::kms::StaticKMS::new(crypto.clone(), key);
            Arc::new(kms)
        }
    };
    let kms = Arc::new(DynKms(kms_dyn));
    Ok(crate::api::new_session_factory(cfg, metastore, kms, crypto))
}
