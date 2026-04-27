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

// ── ResolvedConfig ──────────────────────────────────────────────────
//
// Structured config for building factories without env var side effects.

#[derive(Clone, Debug, Default)]
pub struct PoolConfig {
    pub max_open: Option<usize>,
    pub max_idle: Option<usize>,
    pub max_lifetime_s: Option<u64>,
    pub max_idle_time_s: Option<u64>,
}

#[derive(Clone, Debug)]
pub enum MetastoreConfig {
    Memory,
    Sqlite {
        path: String,
    },
    Postgres {
        url: String,
        replica_consistency: Option<String>,
        pool: PoolConfig,
    },
    Mysql {
        url: String,
        tls_mode: Option<String>,
        replica_consistency: Option<String>,
        pool: PoolConfig,
    },
    DynamoDb {
        table: String,
        region: Option<String>,
        endpoint: Option<String>,
        region_suffix: bool,
    },
}

#[derive(Clone, Debug)]
pub enum KmsConfig {
    Static {
        key_hex: String,
    },
    Aws {
        region_map: Option<std::collections::HashMap<String, String>>,
        preferred_region: Option<String>,
        key_id: Option<String>,
        region: Option<String>,
    },
    SecretsManager {
        secret_id: String,
        region: Option<String>,
    },
    Vault {
        addr: String,
        transit_key: String,
        transit_mount: Option<String>,
    },
}

#[derive(Clone, Debug, Default)]
pub struct PolicyConfig {
    pub expire_key_after_s: Option<i64>,
    pub create_date_precision_s: Option<i64>,
    pub revoke_check_interval_s: Option<i64>,
    pub session_cache_max_size: Option<usize>,
    pub session_cache_ttl_s: Option<i64>,
    pub shared_intermediate_key_cache: Option<bool>,
    pub intermediate_key_cache_max_size: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct ResolvedConfig {
    pub service_name: String,
    pub product_id: String,
    pub region_suffix: Option<String>,
    pub metastore: MetastoreConfig,
    pub kms: KmsConfig,
    pub policy: PolicyConfig,
}

fn build_config_from_policy(
    service: &str,
    product: &str,
    region_suffix: Option<&str>,
    policy: &PolicyConfig,
) -> crate::Config {
    let mut cfg = crate::Config::new(service.to_string(), product.to_string());
    if let Some(sfx) = region_suffix {
        cfg = cfg.with_region_suffix(sfx.to_string());
    }
    if let Some(v) = policy.expire_key_after_s {
        cfg.policy.expire_key_after_s = v;
    }
    if let Some(v) = policy.create_date_precision_s {
        cfg.policy.create_date_precision_s = v;
    }
    if let Some(v) = policy.revoke_check_interval_s {
        cfg.policy.revoke_check_interval_s = v;
    }
    if let Some(v) = policy.session_cache_max_size {
        cfg.policy.session_cache_max_size = v;
    }
    if let Some(v) = policy.session_cache_ttl_s {
        cfg.policy.session_cache_ttl_s = v;
    }
    if let Some(b) = policy.shared_intermediate_key_cache {
        cfg.policy.shared_intermediate_key_cache = b;
    }
    cfg.policy.enforce_minimums();
    if let Some(v) = policy.intermediate_key_cache_max_size {
        cfg.policy.intermediate_key_cache_max_size = v;
        if cfg.policy.intermediate_key_cache_eviction_policy == "simple" {
            cfg.policy.intermediate_key_cache_eviction_policy = "lru".to_string();
        }
    }
    cfg
}

#[allow(unused_variables)]
fn build_metastore(ms: &MetastoreConfig) -> anyhow::Result<Arc<dyn Metastore>> {
    match ms {
        MetastoreConfig::Memory => Ok(Arc::new(crate::metastore::InMemoryMetastore::new())),
        MetastoreConfig::Sqlite { path } => {
            #[cfg(feature = "sqlite")]
            {
                Ok(Arc::new(crate::metastore_sqlite::SqliteMetastore::open(
                    path,
                )?))
            }
            #[cfg(not(feature = "sqlite"))]
            anyhow::bail!("Enable feature 'sqlite' to use SQLite metastore")
        }
        MetastoreConfig::Postgres {
            url,
            replica_consistency,
            pool,
        } => {
            #[cfg(feature = "postgres")]
            {
                Ok(Arc::new(
                    crate::metastore_postgres::PostgresMetastore::connect_with(
                        url,
                        pool.max_open,
                        pool.max_idle,
                        replica_consistency.clone(),
                    )?,
                ))
            }
            #[cfg(not(feature = "postgres"))]
            anyhow::bail!("Enable feature 'postgres' to use Postgres metastore")
        }
        MetastoreConfig::Mysql {
            url,
            tls_mode,
            replica_consistency,
            pool,
        } => {
            #[cfg(feature = "mysql")]
            {
                let pool_cfg = crate::pool_mysql::PoolConfig::from_values(
                    pool.max_open,
                    pool.max_idle,
                    pool.max_lifetime_s,
                    pool.max_idle_time_s,
                );
                Ok(Arc::new(
                    crate::metastore_mysql::MySqlMetastore::connect_with(
                        url,
                        pool_cfg,
                        tls_mode.as_deref(),
                        replica_consistency.as_deref(),
                    )?,
                ))
            }
            #[cfg(not(feature = "mysql"))]
            anyhow::bail!("Enable feature 'mysql' to use MySQL metastore")
        }
        MetastoreConfig::DynamoDb {
            table,
            region,
            endpoint,
            region_suffix,
        } => {
            #[cfg(feature = "dynamodb")]
            {
                Ok(Arc::new(
                    crate::metastore_dynamodb::DynamoDbMetastore::new_with(
                        table.clone(),
                        region.clone(),
                        endpoint.clone(),
                        *region_suffix,
                    )?,
                ))
            }
            #[cfg(not(feature = "dynamodb"))]
            anyhow::bail!("Enable feature 'dynamodb' to use DynamoDB metastore")
        }
    }
}

#[allow(unused_variables)]
async fn build_metastore_async(ms: &MetastoreConfig) -> anyhow::Result<Arc<dyn Metastore>> {
    match ms {
        MetastoreConfig::Memory => Ok(Arc::new(crate::metastore::InMemoryMetastore::new())),
        MetastoreConfig::Sqlite { path } => {
            #[cfg(feature = "sqlite")]
            {
                Ok(Arc::new(crate::metastore_sqlite::SqliteMetastore::open(
                    path,
                )?))
            }
            #[cfg(not(feature = "sqlite"))]
            anyhow::bail!("Enable feature 'sqlite' to use SQLite metastore")
        }
        MetastoreConfig::Postgres {
            url,
            replica_consistency,
            pool,
        } => {
            #[cfg(feature = "postgres")]
            {
                let url = url.clone();
                let max_open = pool.max_open;
                let max_idle = pool.max_idle;
                let replica_consistency = replica_consistency.clone();
                let pg = tokio::task::spawn_blocking(move || {
                    crate::metastore_postgres::PostgresMetastore::connect_with(
                        &url,
                        max_open,
                        max_idle,
                        replica_consistency,
                    )
                })
                .await
                .map_err(|e| anyhow::anyhow!("postgres connect join error: {e}"))??;
                Ok(Arc::new(pg))
            }
            #[cfg(not(feature = "postgres"))]
            anyhow::bail!("Enable feature 'postgres' to use Postgres metastore")
        }
        MetastoreConfig::Mysql {
            url,
            tls_mode,
            replica_consistency,
            pool,
        } => {
            #[cfg(feature = "mysql")]
            {
                let url = url.clone();
                let pool_cfg = crate::pool_mysql::PoolConfig::from_values(
                    pool.max_open,
                    pool.max_idle,
                    pool.max_lifetime_s,
                    pool.max_idle_time_s,
                );
                let tls_mode = tls_mode.clone();
                let replica_consistency = replica_consistency.clone();
                let my = tokio::task::spawn_blocking(move || {
                    crate::metastore_mysql::MySqlMetastore::connect_with(
                        &url,
                        pool_cfg,
                        tls_mode.as_deref(),
                        replica_consistency.as_deref(),
                    )
                })
                .await
                .map_err(|e| anyhow::anyhow!("mysql connect join error: {e}"))??;
                Ok(Arc::new(my))
            }
            #[cfg(not(feature = "mysql"))]
            anyhow::bail!("Enable feature 'mysql' to use MySQL metastore")
        }
        MetastoreConfig::DynamoDb {
            table,
            region,
            endpoint,
            region_suffix,
        } => {
            #[cfg(feature = "dynamodb")]
            {
                Ok(Arc::new(
                    crate::metastore_dynamodb::DynamoDbMetastore::new_with_async(
                        table.clone(),
                        region.clone(),
                        endpoint.clone(),
                        *region_suffix,
                    )
                    .await?,
                ))
            }
            #[cfg(not(feature = "dynamodb"))]
            anyhow::bail!("Enable feature 'dynamodb' to use DynamoDB metastore")
        }
    }
}

fn decode_static_key_hex(hex: &str) -> anyhow::Result<Vec<u8>> {
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
    Ok(key)
}

#[allow(unused_variables)]
fn build_kms(
    kms: &KmsConfig,
    crypto: &Arc<crate::aead::AES256GCM>,
) -> anyhow::Result<Arc<dyn crate::traits::KeyManagementService>> {
    match kms {
        KmsConfig::Static { key_hex } => {
            log::warn!(
                "Using static master key. \
                 This is for testing only — do NOT use in production."
            );
            let hex = if key_hex.is_empty() {
                "746869734973415374617469634d61737465724b6579466f7254657374696e67"
            } else {
                key_hex.as_str()
            };
            let key = decode_static_key_hex(hex)?;
            Ok(Arc::new(crate::kms::StaticKMS::new(crypto.clone(), key)?))
        }
        KmsConfig::Aws {
            region_map,
            preferred_region,
            key_id,
            region,
        } => {
            if let Some(regions) = region_map {
                let mut entries: Vec<(String, String)> = Vec::new();
                let mut pref_idx = 0_usize;
                for (i, (r, k)) in regions.iter().enumerate() {
                    if preferred_region.as_ref() == Some(r) {
                        pref_idx = i;
                    }
                    entries.push((r.clone(), k.clone()));
                }
                let kms = crate::kms_aws_envelope::AwsKmsEnvelope::new_multi(
                    crypto.clone(),
                    pref_idx,
                    entries,
                )?;
                Ok(Arc::new(kms))
            } else {
                let key_id = key_id
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("KMS_KEY_ID required for KMS=aws"))?;
                let kms = crate::kms_aws_envelope::AwsKmsEnvelope::new_single(
                    crypto.clone(),
                    key_id.clone(),
                    region.clone(),
                )?;
                Ok(Arc::new(kms))
            }
        }
        KmsConfig::SecretsManager { secret_id, region } => {
            #[cfg(feature = "secrets-manager")]
            {
                let kms = crate::kms_secrets_manager::SecretsManagerKMS::new(
                    crypto.clone(),
                    secret_id.clone(),
                    region.clone(),
                )?;
                Ok(Arc::new(kms))
            }
            #[cfg(not(feature = "secrets-manager"))]
            anyhow::bail!("Enable feature 'secrets-manager' to use Secrets Manager KMS")
        }
        KmsConfig::Vault {
            addr,
            transit_key,
            transit_mount,
        } => {
            #[cfg(feature = "vault")]
            {
                let kms = crate::kms_vault_transit::VaultTransitKms::new(
                    addr.clone(),
                    transit_key,
                    transit_mount.as_deref(),
                )?;
                Ok(Arc::new(kms))
            }
            #[cfg(not(feature = "vault"))]
            anyhow::bail!("Enable feature 'vault' to use Vault Transit KMS")
        }
    }
}

#[allow(unused_variables)]
async fn build_kms_async(
    kms: &KmsConfig,
    crypto: &Arc<crate::aead::AES256GCM>,
) -> anyhow::Result<Arc<dyn crate::traits::KeyManagementService>> {
    match kms {
        KmsConfig::Static { .. } => build_kms(kms, crypto),
        KmsConfig::Aws {
            region_map,
            preferred_region,
            key_id,
            region,
        } => {
            if let Some(regions) = region_map {
                let mut entries: Vec<(String, String)> = Vec::new();
                let mut pref_idx = 0_usize;
                for (i, (r, k)) in regions.iter().enumerate() {
                    if preferred_region.as_ref() == Some(r) {
                        pref_idx = i;
                    }
                    entries.push((r.clone(), k.clone()));
                }
                let kms = crate::kms_aws_envelope::AwsKmsEnvelope::new_multi_async(
                    crypto.clone(),
                    pref_idx,
                    entries,
                )
                .await?;
                Ok(Arc::new(kms))
            } else {
                let key_id = key_id
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("KMS_KEY_ID required for KMS=aws"))?;
                let kms = crate::kms_aws_envelope::AwsKmsEnvelope::new_single_async(
                    crypto.clone(),
                    key_id.clone(),
                    region.clone(),
                )
                .await?;
                Ok(Arc::new(kms))
            }
        }
        KmsConfig::SecretsManager { secret_id, region } => {
            #[cfg(feature = "secrets-manager")]
            {
                let kms = crate::kms_secrets_manager::SecretsManagerKMS::new_async(
                    crypto.clone(),
                    secret_id.clone(),
                    region.clone(),
                )
                .await?;
                Ok(Arc::new(kms))
            }
            #[cfg(not(feature = "secrets-manager"))]
            anyhow::bail!("Enable feature 'secrets-manager' to use Secrets Manager KMS")
        }
        KmsConfig::Vault {
            addr,
            transit_key,
            transit_mount,
        } => {
            #[cfg(feature = "vault")]
            {
                let kms = crate::kms_vault_transit::VaultTransitKms::new_async(
                    addr.clone(),
                    transit_key,
                    transit_mount.as_deref(),
                )
                .await?;
                Ok(Arc::new(kms))
            }
            #[cfg(not(feature = "vault"))]
            anyhow::bail!("Enable feature 'vault' to use Vault Transit KMS")
        }
    }
}

/// Build a factory from fully resolved config — no env var reads or writes.
pub fn factory_from_resolved(
    config: &ResolvedConfig,
) -> anyhow::Result<crate::session::PublicFactory<crate::aead::AES256GCM, DynKms, DynMetastore>> {
    let cfg = build_config_from_policy(
        &config.service_name,
        &config.product_id,
        config.region_suffix.as_deref(),
        &config.policy,
    );
    let store_dyn = build_metastore(&config.metastore)?;
    let metastore = Arc::new(DynMetastore(store_dyn));
    let crypto = Arc::new(crate::aead::AES256GCM::new());
    let kms_dyn = build_kms(&config.kms, &crypto)?;
    let kms = Arc::new(DynKms(kms_dyn));
    Ok(crate::api::new_session_factory(cfg, metastore, kms, crypto))
}

/// Async variant of factory_from_resolved.
pub async fn factory_from_resolved_async(
    config: &ResolvedConfig,
) -> anyhow::Result<crate::session::PublicFactory<crate::aead::AES256GCM, DynKms, DynMetastore>> {
    let cfg = build_config_from_policy(
        &config.service_name,
        &config.product_id,
        config.region_suffix.as_deref(),
        &config.policy,
    );
    let store_dyn = build_metastore_async(&config.metastore).await?;
    let metastore = Arc::new(DynMetastore(store_dyn));
    let crypto = Arc::new(crate::aead::AES256GCM::new());
    let kms_dyn = build_kms_async(&config.kms, &crypto).await?;
    let kms = Arc::new(DynKms(kms_dyn));
    Ok(crate::api::new_session_factory(cfg, metastore, kms, crypto))
}

/// Parse environment variables into a `ResolvedConfig`.
#[allow(unused_variables)]
pub fn resolve_from_env() -> anyhow::Result<ResolvedConfig> {
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
    fn get_u64(k: &str) -> Option<u64> {
        std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok())
    }

    let service_name = std::env::var("SERVICE_NAME").unwrap_or_else(|_| "service".to_string());
    let product_id = std::env::var("PRODUCT_ID").unwrap_or_else(|_| "product".to_string());
    let region_suffix = std::env::var("REGION_SUFFIX").ok();

    let pool = PoolConfig {
        max_open: get_usize("ASHERAH_POOL_MAX_OPEN").or_else(|| get_usize("ASHERAH_POOL_SIZE")),
        max_idle: get_usize("ASHERAH_POOL_MAX_IDLE"),
        max_lifetime_s: get_u64("ASHERAH_POOL_MAX_LIFETIME"),
        max_idle_time_s: get_u64("ASHERAH_POOL_MAX_IDLE_TIME"),
    };
    let replica_consistency = std::env::var("REPLICA_READ_CONSISTENCY").ok();

    let mchoice = std::env::var("Metastore")
        .unwrap_or_else(|_| "memory".to_string())
        .to_lowercase();

    let metastore = if mchoice == "sqlite" || std::env::var("SQLITE_PATH").is_ok() {
        #[cfg(feature = "sqlite")]
        {
            let path = std::env::var("SQLITE_PATH").unwrap_or_else(|_| ":memory:".to_string());
            MetastoreConfig::Sqlite { path }
        }
        #[cfg(not(feature = "sqlite"))]
        anyhow::bail!("Enable feature 'sqlite' to use SQLite metastore")
    } else if mchoice == "dynamodb" || std::env::var("DDB_TABLE").is_ok() {
        #[cfg(feature = "dynamodb")]
        {
            MetastoreConfig::DynamoDb {
                table: std::env::var("DDB_TABLE").unwrap_or_else(|_| "EncryptionKey".to_string()),
                region: std::env::var("AWS_REGION").ok(),
                endpoint: std::env::var("AWS_ENDPOINT_URL").ok(),
                region_suffix: get_bool("DDB_REGION_SUFFIX").unwrap_or(false),
            }
        }
        #[cfg(not(feature = "dynamodb"))]
        anyhow::bail!("Enable feature 'dynamodb' to use DynamoDB metastore")
    } else if mchoice == "rdbms" || std::env::var("POSTGRES_URL").is_ok() {
        #[cfg(feature = "postgres")]
        if let Ok(url) = std::env::var("POSTGRES_URL") {
            MetastoreConfig::Postgres {
                url,
                replica_consistency: replica_consistency.clone(),
                pool: pool.clone(),
            }
        } else {
            #[cfg(feature = "mysql")]
            if let Ok(url) = std::env::var("MYSQL_URL") {
                MetastoreConfig::Mysql {
                    url,
                    tls_mode: std::env::var("MYSQL_TLS_MODE").ok(),
                    replica_consistency: replica_consistency.clone(),
                    pool: pool.clone(),
                }
            } else {
                anyhow::bail!(
                    "Metastore=rdbms requires POSTGRES_URL or MYSQL_URL to be set \
                     (and the corresponding feature enabled)"
                )
            }
            #[cfg(not(feature = "mysql"))]
            anyhow::bail!(
                "Metastore=rdbms requires POSTGRES_URL or MYSQL_URL to be set \
                 (and the corresponding feature enabled)"
            )
        }
        #[cfg(not(feature = "postgres"))]
        if std::env::var("POSTGRES_URL").is_ok() {
            anyhow::bail!("Enable feature 'postgres' to use Postgres metastore")
        } else {
            #[cfg(feature = "mysql")]
            if let Ok(url) = std::env::var("MYSQL_URL") {
                MetastoreConfig::Mysql {
                    url,
                    tls_mode: std::env::var("MYSQL_TLS_MODE").ok(),
                    replica_consistency: replica_consistency.clone(),
                    pool: pool.clone(),
                }
            } else {
                anyhow::bail!(
                    "Metastore=rdbms requires POSTGRES_URL or MYSQL_URL to be set \
                     (and the corresponding feature enabled)"
                )
            }
            #[cfg(not(feature = "mysql"))]
            anyhow::bail!(
                "Metastore=rdbms requires POSTGRES_URL or MYSQL_URL to be set \
                 (and the corresponding feature enabled)"
            )
        }
    } else if let Ok(url) = std::env::var("MYSQL_URL") {
        #[cfg(feature = "mysql")]
        {
            MetastoreConfig::Mysql {
                url,
                tls_mode: std::env::var("MYSQL_TLS_MODE").ok(),
                replica_consistency: replica_consistency.clone(),
                pool: pool.clone(),
            }
        }
        #[cfg(not(feature = "mysql"))]
        {
            drop(url);
            anyhow::bail!("Enable feature 'mysql' to use MySQL metastore")
        }
    } else {
        MetastoreConfig::Memory
    };

    let kms_kind = std::env::var("KMS")
        .unwrap_or_else(|_| "static".into())
        .to_lowercase();
    let kms = match kms_kind.as_str() {
        "static" | "test-debug-static" => KmsConfig::Static {
            key_hex: std::env::var("STATIC_MASTER_KEY_HEX").unwrap_or_default(),
        },
        "aws" => {
            let region_map = std::env::var("REGION_MAP")
                .ok()
                .map(|j| serde_json::from_str(&j))
                .transpose()?;
            KmsConfig::Aws {
                region_map,
                preferred_region: std::env::var("PREFERRED_REGION").ok(),
                key_id: std::env::var("KMS_KEY_ID").ok(),
                region: std::env::var("AWS_REGION").ok(),
            }
        }
        #[cfg(feature = "secrets-manager")]
        "secrets-manager" => {
            let secret_id = std::env::var("SECRETS_MANAGER_SECRET_ID").map_err(|_| {
                anyhow::anyhow!("SECRETS_MANAGER_SECRET_ID required for KMS=secrets-manager")
            })?;
            KmsConfig::SecretsManager {
                secret_id,
                region: std::env::var("AWS_REGION").ok(),
            }
        }
        #[cfg(not(feature = "secrets-manager"))]
        "secrets-manager" => {
            anyhow::bail!("Enable feature 'secrets-manager' to use Secrets Manager KMS");
        }
        #[cfg(feature = "vault")]
        "vault" | "vault-transit" => {
            let addr = std::env::var("VAULT_ADDR")
                .map_err(|_| anyhow::anyhow!("VAULT_ADDR required for KMS=vault"))?;
            let transit_key = std::env::var("VAULT_TRANSIT_KEY")
                .map_err(|_| anyhow::anyhow!("VAULT_TRANSIT_KEY required for KMS=vault"))?;
            KmsConfig::Vault {
                addr,
                transit_key,
                transit_mount: std::env::var("VAULT_TRANSIT_MOUNT").ok(),
            }
        }
        #[cfg(not(feature = "vault"))]
        "vault" | "vault-transit" => {
            anyhow::bail!("Enable feature 'vault' to use Vault Transit KMS");
        }
        other => {
            anyhow::bail!("Unknown KMS type '{other}'. Valid values: 'aws', 'static', 'secrets-manager', 'vault'");
        }
    };

    let policy = PolicyConfig {
        expire_key_after_s: get_i64("EXPIRE_AFTER_SECS"),
        create_date_precision_s: get_i64("CREATE_DATE_PRECISION_SECS"),
        revoke_check_interval_s: get_i64("REVOKE_CHECK_INTERVAL_SECS"),
        session_cache_max_size: get_usize("SESSION_CACHE_MAX_SIZE"),
        session_cache_ttl_s: get_i64("SESSION_CACHE_DURATION_SECS"),
        shared_intermediate_key_cache: get_bool("SHARED_INTERMEDIATE_KEY_CACHE"),
        intermediate_key_cache_max_size: get_usize("INTERMEDIATE_KEY_CACHE_MAX_SIZE"),
    };

    Ok(ResolvedConfig {
        service_name,
        product_id,
        region_suffix,
        metastore,
        kms,
        policy,
    })
}

/// Build a full PublicFactory from environment variables.
pub fn factory_from_env(
) -> anyhow::Result<crate::session::PublicFactory<crate::aead::AES256GCM, DynKms, DynMetastore>> {
    let resolved = resolve_from_env()?;
    factory_from_resolved(&resolved)
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
            let my = tokio::task::spawn_blocking(move || {
                crate::metastore_mysql::MySqlMetastore::connect(&url)
            })
            .await
            .map_err(|e| anyhow::anyhow!("mysql connect join error: {e}"))??;
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
    let resolved = resolve_from_env()?;
    factory_from_resolved_async(&resolved).await
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
