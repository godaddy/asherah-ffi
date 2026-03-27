use std::sync::Arc;

use async_trait::async_trait;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};

use crate::traits::Metastore;

type MetastoreEnvResult = (Arc<dyn Metastore>, String, String, Option<String>);

/// Classify a connection string as MySQL, Postgres, or SQLite.
/// Detects both URL-scheme prefixes and Go `go-sql-driver/mysql` DSN format
/// (`user:pass@tcp(host:port)/db`).
#[derive(Debug)]
pub enum DbKind {
    Mysql(String),
    Postgres(String),
    Sqlite(String),
    Unknown(String),
}

/// Convert a Go `go-sql-driver/mysql` DSN to a standard `mysql://` URL.
///
/// Go format: `[user[:pass]@][tcp[(host[:port])]]/dbname[?params]`
/// Output:    `mysql://user:pass@host:port/dbname[?params]`
///
/// Go-specific query params (`tls`, `parseTime`, `loc`, `allowNativePasswords`,
/// etc.) are stripped since the Rust `mysql` crate doesn't recognize them.
/// The `tls` value is preserved separately via the `MYSQL_TLS_MODE` env var
/// (set by asherah-config).
pub fn convert_go_mysql_dsn(dsn: &str) -> String {
    // Split userinfo from the rest at the last '@'.
    // Must happen BEFORE splitting on '?' because passwords can contain '?' and '@'.
    let (userinfo, rest) = match dsn.rsplit_once('@') {
        Some((u, r)) => (u, r),
        None => ("", dsn),
    };

    // Split off query string from the non-userinfo part only
    let (rest_base, query) = match rest.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (rest, None),
    };

    // Extract host:port from tcp(host:port) or tcp(host)
    let (host_port, db_part) = if let Some(after_tcp) = rest_base
        .strip_prefix("tcp(")
        .or_else(|| rest_base.strip_prefix("tcp ("))
    {
        match after_tcp.split_once(')') {
            Some((addr, remainder)) => {
                let db = remainder.strip_prefix('/').unwrap_or(remainder);
                // Default port if not specified
                let hp = if addr.contains(':') {
                    addr.to_string()
                } else {
                    format!("{addr}:3306")
                };
                (hp, db.to_string())
            }
            None => {
                // Malformed, pass through
                return format!("mysql://{dsn}");
            }
        }
    } else {
        // No tcp(...) — might be just host/db or /db
        match rest_base.split_once('/') {
            Some((host, db)) => {
                let hp = if host.is_empty() {
                    "localhost:3306".to_string()
                } else if host.contains(':') {
                    host.to_string()
                } else {
                    format!("{host}:3306")
                };
                (hp, db.to_string())
            }
            None => (rest_base.to_string(), String::new()),
        }
    };

    // Filter out Go-specific query params that the Rust mysql crate doesn't understand
    let filtered_query = query.map(|q| {
        let go_params = [
            "tls",
            "parseTime",
            "loc",
            "allowNativePasswords",
            "allowOldPasswords",
            "charset",
            "collation",
            "clientFoundRows",
            "columnsWithAlias",
            "interpolateParams",
            "maxAllowedPacket",
            "multiStatements",
            "readTimeout",
            "writeTimeout",
            "timeout",
            "rejectReadOnly",
            "checkConnLiveness",
        ];
        let kept: Vec<&str> = q
            .split('&')
            .filter(|p| {
                if let Some((key, _)) = p.split_once('=') {
                    !go_params.contains(&key)
                } else {
                    true
                }
            })
            .collect();
        if kept.is_empty() {
            String::new()
        } else {
            format!("?{}", kept.join("&"))
        }
    });

    let qs = filtered_query.unwrap_or_default();

    if userinfo.is_empty() {
        format!("mysql://{host_port}/{db_part}{qs}")
    } else {
        // Percent-encode username and password for the URL.
        // Go DSN format uses raw special characters in passwords, but
        // the mysql:// URL scheme requires them to be percent-encoded.
        let encoded_userinfo = if let Some((user, pass)) = userinfo.split_once(':') {
            let enc_user = percent_encode(user.as_bytes(), NON_ALPHANUMERIC);
            let enc_pass = percent_encode(pass.as_bytes(), NON_ALPHANUMERIC);
            format!("{enc_user}:{enc_pass}")
        } else {
            percent_encode(userinfo.as_bytes(), NON_ALPHANUMERIC).to_string()
        };
        format!("mysql://{encoded_userinfo}@{host_port}/{db_part}{qs}")
    }
}

/// Classify a connection string and normalize it for our Rust drivers.
pub fn classify_connection_string(conn: &str) -> DbKind {
    let lower = conn.to_lowercase();
    if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
        DbKind::Postgres(conn.to_string())
    } else if lower.starts_with("mysql://") {
        let rest = &conn["mysql://".len()..];
        if rest.contains("tcp(") {
            // mysql:// prefix on a Go DSN body — strip prefix and convert
            DbKind::Mysql(convert_go_mysql_dsn(rest))
        } else {
            DbKind::Mysql(conn.to_string())
        }
    } else if lower.starts_with("sqlite://") {
        DbKind::Sqlite(conn.strip_prefix("sqlite://").unwrap_or(conn).to_string())
    } else if conn.contains("tcp(") {
        // Go go-sql-driver/mysql DSN format: user:pass@tcp(host:port)/db
        DbKind::Mysql(convert_go_mysql_dsn(conn))
    } else {
        DbKind::Unknown(conn.to_string())
    }
}

#[derive(Debug)]
pub enum StoreChoice {
    InMemory,
    #[cfg(feature = "postgres")]
    Postgres,
    #[cfg(feature = "mysql")]
    MySql,
    #[cfg(feature = "dynamodb")]
    DynamoDb,
}

#[derive(Debug)]
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
        log::debug!(
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
    // If explicitly rdbms but no DB URL resolved, fail instead of silently falling back
    if mchoice == "rdbms" {
        anyhow::bail!(
            "Metastore=rdbms requires POSTGRES_URL or MYSQL_URL to be set \
             (and the corresponding feature enabled)"
        );
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
    // SESSION_CACHE, CACHE_SYSTEM_KEYS, CACHE_INTERMEDIATE_KEYS env vars
    // are accepted but ignored — caches are always enabled.
    if get_bool("SESSION_CACHE") == Some(false) {
        log::warn!("SESSION_CACHE=false is ignored — session cache is always enabled");
    }
    if get_bool("CACHE_SYSTEM_KEYS") == Some(false) {
        log::warn!("CACHE_SYSTEM_KEYS=false is ignored — system key cache is always enabled");
    }
    if get_bool("CACHE_INTERMEDIATE_KEYS") == Some(false) {
        log::warn!(
            "CACHE_INTERMEDIATE_KEYS=false is ignored — intermediate key cache is always enabled"
        );
    }
    if let Some(v) = get_usize("SESSION_CACHE_MAX_SIZE") {
        cfg.policy.session_cache_max_size = v;
    }
    if let Some(v) = get_i64("SESSION_CACHE_DURATION_SECS") {
        cfg.policy.session_cache_ttl_s = v;
    }
    if let Some(b) = get_bool("SHARED_INTERMEDIATE_KEY_CACHE") {
        cfg.policy.shared_intermediate_key_cache = b;
    }
    cfg.policy.enforce_minimums();
    // Apply explicit IK cache size AFTER enforce_minimums so cold benchmarks
    // can set it below the minimum (e.g. 1) for cache-miss testing.
    if let Some(v) = get_usize("INTERMEDIATE_KEY_CACHE_MAX_SIZE") {
        cfg.policy.intermediate_key_cache_max_size = v;
        // Simple policy never evicts — switch to LRU so the max is enforced
        if cfg.policy.intermediate_key_cache_eviction_policy == "simple" {
            cfg.policy.intermediate_key_cache_eviction_policy = "lru".to_string();
        }
    }
    cfg
}

// === Dynamic wrappers to pass trait-objects through generic factory ===
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct DynKms(pub Arc<dyn crate::traits::KeyManagementService>);
#[async_trait]
impl crate::traits::KeyManagementService for DynKms {
    fn encrypt_key(&self, ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.0.encrypt_key(ctx, key_bytes)
    }
    fn decrypt_key(&self, ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.0.decrypt_key(ctx, blob)
    }
    async fn encrypt_key_async(
        &self,
        ctx: &(),
        key_bytes: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        self.0.encrypt_key_async(ctx, key_bytes).await
    }
    async fn decrypt_key_async(&self, ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.0.decrypt_key_async(ctx, blob).await
    }
}

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct DynMetastore(pub Arc<dyn Metastore>);
#[async_trait]
impl Metastore for DynMetastore {
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
    async fn load_async(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<crate::types::EnvelopeKeyRecord>, anyhow::Error> {
        self.0.load_async(id, created).await
    }
    async fn load_latest_async(
        &self,
        id: &str,
    ) -> Result<Option<crate::types::EnvelopeKeyRecord>, anyhow::Error> {
        self.0.load_latest_async(id).await
    }
    async fn store_async(
        &self,
        id: &str,
        created: i64,
        ekr: &crate::types::EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        self.0.store_async(id, created, ekr).await
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
                let mut pref_idx = 0_usize;
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
        "static" | "test-debug-static" => {
            log::warn!(
                "Using static master key (KMS={kms_kind}). \
                 This is for testing only — do NOT use in production."
            );
            let hex = std::env::var("STATIC_MASTER_KEY_HEX").unwrap_or_else(|_| {
                // Default matches Go asherah's hardcoded key "thisIsAStaticMasterKeyForTesting"
                "746869734973415374617469634d61737465724b6579466f7254657374696e67".to_string()
            });
            if !hex.len().is_multiple_of(2) {
                anyhow::bail!(
                    "STATIC_MASTER_KEY_HEX has odd length ({}) — must be even",
                    hex.len()
                );
            }
            let mut key = vec![0_u8; hex.len() / 2];
            for i in 0..key.len() {
                key[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| {
                    anyhow::anyhow!(
                        "STATIC_MASTER_KEY_HEX contains invalid hex at position {}",
                        2 * i
                    )
                })?;
            }
            let kms = crate::kms::StaticKMS::new(crypto.clone(), key)?;
            Arc::new(kms)
        }
        other => {
            anyhow::bail!("Unknown KMS type '{other}'. Valid values: 'aws', 'static'");
        }
    };
    let kms = Arc::new(DynKms(kms_dyn));
    Ok(crate::api::new_session_factory(cfg, metastore, kms, crypto))
}

/// Async variant of metastore_from_env — uses async constructors for DynamoDB.
/// Postgres uses spawn_blocking (sync crate). MySQL/SQLite/memory are sync-safe.
pub async fn metastore_from_env_async() -> anyhow::Result<MetastoreEnvResult> {
    let service = std::env::var("SERVICE_NAME").unwrap_or_else(|_| "service".to_string());
    let product = std::env::var("PRODUCT_ID").unwrap_or_else(|_| "product".to_string());
    let region_suffix = std::env::var("REGION_SUFFIX").ok();
    let mchoice = std::env::var("Metastore")
        .unwrap_or_else(|_| "memory".to_string())
        .to_lowercase();

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
            let ddb =
                crate::metastore_dynamodb::DynamoDbMetastore::new_async(table, region).await?;
            return Ok((Arc::new(ddb), service, product, region_suffix));
        }
        #[cfg(not(feature = "dynamodb"))]
        anyhow::bail!("Enable feature 'dynamodb' to use DynamoDB metastore");
    }
    if mchoice == "rdbms" || std::env::var("POSTGRES_URL").is_ok() {
        #[cfg(feature = "postgres")]
        if let Ok(url) = std::env::var("POSTGRES_URL") {
            // Postgres uses sync crate — construct on a plain thread
            let pg = tokio::task::spawn_blocking(move || {
                crate::metastore_postgres::PostgresMetastore::connect(&url)
            })
            .await
            .map_err(|e| anyhow::anyhow!("postgres connect join error: {e}"))??;
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
            let my = crate::metastore_mysql::MySqlMetastore::connect_async(&url).await?;
            return Ok((Arc::new(my), service, product, region_suffix));
        }
        #[cfg(not(feature = "mysql"))]
        if std::env::var("MYSQL_URL").is_ok() {
            anyhow::bail!("Enable feature 'mysql' to use MySQL metastore");
        }
    }
    if mchoice == "rdbms" {
        anyhow::bail!(
            "Metastore=rdbms requires POSTGRES_URL or MYSQL_URL to be set \
             (and the corresponding feature enabled)"
        );
    }
    let mem = crate::metastore::InMemoryMetastore::new();
    Ok((Arc::new(mem), service, product, region_suffix))
}

/// Async variant of factory_from_env — uses async constructors for DynamoDB/KMS.
pub async fn factory_from_env_async(
) -> anyhow::Result<crate::session::PublicFactory<crate::aead::AES256GCM, DynKms, DynMetastore>> {
    let cfg = config_from_env();
    let (store_dyn, _svc, _prod, _sfx) = metastore_from_env_async().await?;
    let metastore = Arc::new(DynMetastore(store_dyn));
    let crypto = Arc::new(crate::aead::AES256GCM::new());
    let kms_kind = std::env::var("KMS")
        .unwrap_or_else(|_| "static".into())
        .to_lowercase();
    let kms_dyn: Arc<dyn crate::traits::KeyManagementService> = match kms_kind.as_str() {
        "aws" => {
            if let Ok(map_json) = std::env::var("REGION_MAP") {
                let regions: std::collections::HashMap<String, String> =
                    serde_json::from_str(&map_json)?;
                let preferred = std::env::var("PREFERRED_REGION").ok();
                let mut entries: Vec<(String, String)> = Vec::new();
                let mut pref_idx = 0_usize;
                for (i, (region, key)) in regions.iter().enumerate() {
                    if preferred.as_ref() == Some(region) {
                        pref_idx = i;
                    }
                    entries.push((region.clone(), key.clone()));
                }
                let kms = crate::kms_aws_envelope::AwsKmsEnvelope::new_multi_async(
                    crypto.clone(),
                    pref_idx,
                    entries,
                )
                .await?;
                Arc::new(kms)
            } else {
                let key_id = std::env::var("KMS_KEY_ID")
                    .map_err(|_| anyhow::anyhow!("KMS_KEY_ID required for KMS=aws"))?;
                let region = std::env::var("AWS_REGION").ok();
                let kms = crate::kms_aws_envelope::AwsKmsEnvelope::new_single_async(
                    crypto.clone(),
                    key_id,
                    region,
                )
                .await?;
                Arc::new(kms)
            }
        }
        "static" | "test-debug-static" => {
            log::warn!(
                "Using static master key (KMS={kms_kind}). \
                 This is for testing only — do NOT use in production."
            );
            let hex = std::env::var("STATIC_MASTER_KEY_HEX").unwrap_or_else(|_| {
                "746869734973415374617469634d61737465724b6579466f7254657374696e67".to_string()
            });
            if !hex.len().is_multiple_of(2) {
                anyhow::bail!(
                    "STATIC_MASTER_KEY_HEX has odd length ({}) — must be even",
                    hex.len()
                );
            }
            let mut key = vec![0_u8; hex.len() / 2];
            for i in 0..key.len() {
                key[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| {
                    anyhow::anyhow!(
                        "STATIC_MASTER_KEY_HEX contains invalid hex at position {}",
                        2 * i
                    )
                })?;
            }
            let kms = crate::kms::StaticKMS::new(crypto.clone(), key)?;
            Arc::new(kms)
        }
        other => {
            anyhow::bail!("Unknown KMS type '{other}'. Valid values: 'aws', 'static'");
        }
    };
    let kms = Arc::new(DynKms(kms_dyn));
    Ok(crate::api::new_session_factory(cfg, metastore, kms, crypto))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_go_mysql_dsn_full() {
        let dsn = "root:pass@tcp(localhost:3306)/testdb?tls=skip-verify";
        match classify_connection_string(dsn) {
            DbKind::Mysql(url) => assert_eq!(url, "mysql://root:pass@localhost:3306/testdb"),
            other => panic!("expected Mysql, got {other:?}"),
        }
    }

    #[test]
    fn test_convert_go_mysql_dsn_no_params() {
        let dsn = "user:password@tcp(db.example.com:3306)/mydb";
        match classify_connection_string(dsn) {
            DbKind::Mysql(url) => {
                assert_eq!(url, "mysql://user:password@db.example.com:3306/mydb")
            }
            other => panic!("expected Mysql, got {other:?}"),
        }
    }

    #[test]
    fn test_convert_go_mysql_dsn_no_port() {
        let dsn = "root@tcp(localhost)/testdb";
        match classify_connection_string(dsn) {
            DbKind::Mysql(url) => assert_eq!(url, "mysql://root@localhost:3306/testdb"),
            other => panic!("expected Mysql, got {other:?}"),
        }
    }

    #[test]
    fn test_convert_go_mysql_dsn_multiple_go_params() {
        let dsn = "root:pass@tcp(host:3306)/db?parseTime=true&tls=skip-verify&loc=UTC";
        match classify_connection_string(dsn) {
            DbKind::Mysql(url) => assert_eq!(url, "mysql://root:pass@host:3306/db"),
            other => panic!("expected Mysql, got {other:?}"),
        }
    }

    #[test]
    fn test_convert_go_mysql_dsn_with_mysql_prefix() {
        let dsn = "mysql://root:pass@tcp(localhost:3306)/testdb?tls=skip-verify";
        match classify_connection_string(dsn) {
            DbKind::Mysql(url) => assert_eq!(url, "mysql://root:pass@localhost:3306/testdb"),
            other => panic!("expected Mysql, got {other:?}"),
        }
    }

    #[test]
    fn test_convert_go_mysql_dsn_special_chars_in_password() {
        // Passwords with %, @, ?, &, : etc. must be percent-encoded in the URL
        let dsn = "admin:p@ss%ml61!&?=x@tcp(db:3306)/mydb?tls=skip-verify";
        match classify_connection_string(dsn) {
            DbKind::Mysql(url) => {
                assert_eq!(url, "mysql://admin:p%40ss%25ml61%21%26%3F%3Dx@db:3306/mydb");
            }
            other => panic!("expected Mysql, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_standard_mysql_url() {
        let url = "mysql://root:pass@localhost:3306/testdb";
        match classify_connection_string(url) {
            DbKind::Mysql(u) => assert_eq!(u, url),
            other => panic!("expected Mysql, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_postgres_url() {
        let url = "postgres://user:pass@localhost/db";
        match classify_connection_string(url) {
            DbKind::Postgres(u) => assert_eq!(u, url),
            other => panic!("expected Postgres, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_sqlite_url() {
        let url = "sqlite:///tmp/test.db";
        match classify_connection_string(url) {
            DbKind::Sqlite(path) => assert_eq!(path, "/tmp/test.db"),
            other => panic!("expected Sqlite, got {other:?}"),
        }
    }

    #[test]
    fn test_classify_unknown_fallback() {
        let conn = "/some/path/to/db";
        match classify_connection_string(conn) {
            DbKind::Unknown(s) => assert_eq!(s, conn),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }
}
