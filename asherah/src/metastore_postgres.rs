use async_trait::async_trait;

use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use anyhow::Context;
use postgres::Client;
use std::sync::{Arc, Mutex};

/// Default max open connections, matching our MySQL default.
const DEFAULT_MAX_OPEN: usize = 10;

/// Default max idle connections, matching Go's database/sql MaxIdleConns default.
const DEFAULT_MAX_IDLE: usize = 2;

struct PoolInner {
    conns: Vec<Client>,
    checked_out: usize,
}

struct PgPool {
    url: String,
    replica_consistency: Option<String>,
    inner: Mutex<PoolInner>,
    max_idle: usize,
    max_open: usize,
}

/// A connection checked out from the pool. Returns to the pool on drop.
struct PgPooledClient {
    pool: Arc<PgPool>,
    client: Option<Client>,
}

impl Drop for PgPooledClient {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            let mut inner = self.pool.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.checked_out -= 1;
            if !client.is_closed() && inner.conns.len() < self.pool.max_idle {
                inner.conns.push(client);
            }
        }
    }
}

impl std::ops::Deref for PgPooledClient {
    type Target = Client;
    fn deref(&self) -> &Client {
        self.client
            .as_ref()
            .expect("PgPooledClient accessed after drop")
    }
}

impl std::ops::DerefMut for PgPooledClient {
    fn deref_mut(&mut self) -> &mut Client {
        self.client
            .as_mut()
            .expect("PgPooledClient accessed after drop")
    }
}

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct PostgresMetastore {
    pool: Arc<PgPool>,
}

/// Extract the `sslmode` value from a Postgres connection string.
///
/// Handles both URL format (`postgres://...?sslmode=require`)
/// and key-value format (`host=localhost sslmode=require`).
fn parse_sslmode(url: &str) -> Option<String> {
    if url.contains("://") {
        // URL format — parse query string
        url.split_once('?').and_then(|(_, query)| {
            query.split('&').find_map(|param| {
                param
                    .split_once('=')
                    .filter(|(k, _)| *k == "sslmode")
                    .map(|(_, v)| v.to_string())
            })
        })
    } else {
        // Key-value format: "host=localhost sslmode=require dbname=test"
        url.split_whitespace().find_map(|part| {
            part.split_once('=')
                .filter(|(k, _)| *k == "sslmode")
                .map(|(_, v)| v.to_string())
        })
    }
}

/// Connect to Postgres using the appropriate TLS mode based on sslmode in the connection string.
///
/// sslmode mapping (matching Go lib/pq behavior):
///   "disable"     → no TLS
///   "require"     → TLS required, skip certificate verification
///   "verify-ca"   → TLS required, verify server certificate against CA
///   "verify-full" → TLS required, verify certificate + hostname
///   "allow"/"prefer" or absent → no TLS (NoTls fallback)
fn connect_client(url: &str) -> anyhow::Result<Client> {
    let sslmode = parse_sslmode(url);
    match sslmode.as_deref() {
        Some("require") => {
            // Go lib/pq: require = TLS but no cert verification
            let connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()?;
            let tls = postgres_native_tls::MakeTlsConnector::new(connector);
            Ok(Client::connect(url, tls)?)
        }
        Some("verify-ca") => {
            // Verify server certificate but skip hostname check
            let connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_hostnames(true)
                .build()?;
            let tls = postgres_native_tls::MakeTlsConnector::new(connector);
            Ok(Client::connect(url, tls)?)
        }
        Some("verify-full") => {
            // Full verification (default TLS behavior)
            let connector = native_tls::TlsConnector::builder().build()?;
            let tls = postgres_native_tls::MakeTlsConnector::new(connector);
            Ok(Client::connect(url, tls)?)
        }
        // "disable", "allow", "prefer", or absent → no TLS
        _ => Ok(Client::connect(url, postgres::NoTls)?),
    }
}

impl PostgresMetastore {
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let replica_consistency = match std::env::var("REPLICA_READ_CONSISTENCY") {
            Ok(c) => match c.as_str() {
                "eventual" | "global" | "session" => Some(c),
                _ => {
                    anyhow::bail!(
                        "invalid REPLICA_READ_CONSISTENCY value: '{}' (expected eventual, global, or session)",
                        c
                    );
                }
            },
            Err(_) => None,
        };

        let max_open = std::env::var("ASHERAH_POOL_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_OPEN);
        let max_idle = DEFAULT_MAX_IDLE.min(max_open);

        Ok(Self {
            pool: Arc::new(PgPool {
                url: url.to_string(),
                replica_consistency,
                inner: Mutex::new(PoolInner {
                    conns: Vec::with_capacity(max_idle),
                    checked_out: 0,
                }),
                max_idle,
                max_open,
            }),
        })
    }

    fn client(&self) -> anyhow::Result<PgPooledClient> {
        // Try to reuse an idle connection from the pool
        {
            let mut inner = self.pool.inner.lock().unwrap_or_else(|e| e.into_inner());
            while let Some(client) = inner.conns.pop() {
                if !client.is_closed() {
                    inner.checked_out += 1;
                    return Ok(PgPooledClient {
                        pool: Arc::clone(&self.pool),
                        client: Some(client),
                    });
                }
            }

            // No idle connection available — check if we can open a new one
            let total = inner.checked_out + inner.conns.len();
            if total >= self.pool.max_open {
                anyhow::bail!(
                    "Postgres connection pool exhausted (max_open={})",
                    self.pool.max_open
                );
            }
            inner.checked_out += 1;
        }

        // Create a new connection (outside the lock)
        let client = connect_client(&self.pool.url).map_err(|e| {
            // Decrement checked_out since we failed to create the connection
            let mut inner = self.pool.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.checked_out -= 1;
            log::error!("Postgres connection failed: {e:#}");
            e
        })?;

        // Apply replica read consistency on new connections
        let mut pooled = PgPooledClient {
            pool: Arc::clone(&self.pool),
            client: Some(client),
        };
        if let Some(ref consistency) = self.pool.replica_consistency {
            if let Err(e) = pooled.batch_execute(&format!(
                "SET apg_write_forward.consistency_mode = '{consistency}'"
            )) {
                // pooled will be dropped, which decrements checked_out
                return Err(e.into());
            }
        }

        Ok(pooled)
    }
}

#[async_trait]
impl Metastore for PostgresMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("postgres load: id={id} created={created}");
        let mut c = self.client()?;
        let created_f = created as f64;
        let row = c.query_opt(
            "SELECT key_record::text FROM encryption_key WHERE id=$1 AND created=to_timestamp($2)",
            &[&id, &created_f],
        ).with_context(|| format!("Postgres load query failed for id={id} created={created}"))?;
        match row {
            Some(row) => {
                let txt: String = row.get(0);
                log::debug!("postgres load hit: id={id} created={created}");
                let ekr = EnvelopeKeyRecord::from_json_fast(&txt).with_context(|| {
                    format!("Postgres load: failed to parse key_record JSON for id={id}")
                })?;
                Ok(Some(ekr))
            }
            None => {
                log::debug!("postgres load miss: id={id} created={created}");
                Ok(None)
            }
        }
    }
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("postgres load_latest: id={id}");
        let mut c = self.client()?;
        let row = c.query_opt(
            "SELECT key_record::text FROM encryption_key WHERE id=$1 ORDER BY created DESC LIMIT 1",
            &[&id],
        ).with_context(|| format!("Postgres load_latest query failed for id={id}"))?;
        match row {
            Some(row) => {
                let txt: String = row.get(0);
                log::debug!("postgres load_latest hit: id={id}");
                let ekr = EnvelopeKeyRecord::from_json_fast(&txt).with_context(|| {
                    format!("Postgres load_latest: failed to parse key_record JSON for id={id}")
                })?;
                Ok(Some(ekr))
            }
            None => {
                log::debug!("postgres load_latest miss: id={id}");
                Ok(None)
            }
        }
    }
    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        log::debug!("postgres store: id={id} created={created}");
        let mut c = self.client()?;
        let v = ekr.to_json_fast();
        let created_f = created as f64;
        let v_json: serde_json::Value = serde_json::from_str(&v).with_context(|| {
            format!("Postgres store: failed to re-parse key_record JSON for id={id}")
        })?;
        let res = c.execute(
            "INSERT INTO encryption_key(id, created, key_record) VALUES ($1, to_timestamp($2), $3) ON CONFLICT DO NOTHING",
            &[&id, &created_f, &v_json],
        ).with_context(|| format!("Postgres store insert failed for id={id} created={created}"))?;
        let stored = res > 0;
        log::debug!("postgres store: id={id} created={created} stored={stored}");
        Ok(stored)
    }

    // The sync postgres crate does blocking I/O with internal block_on for
    // connection management. spawn_blocking is safe here because blocking pool
    // threads don't have the runtime "entered" (only Handle is available).
    async fn load_async(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let this = self.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || this.load(&id, created))
            .await
            .map_err(|e| anyhow::anyhow!("postgres load_async join error: {e}"))?
    }

    async fn load_latest_async(
        &self,
        id: &str,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let this = self.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || this.load_latest(&id))
            .await
            .map_err(|e| anyhow::anyhow!("postgres load_latest_async join error: {e}"))?
    }

    async fn store_async(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        let this = self.clone();
        let id = id.to_string();
        let ekr = ekr.clone();
        tokio::task::spawn_blocking(move || this.store(&id, created, &ekr))
            .await
            .map_err(|_| anyhow::anyhow!("postgres store_async thread panicked"))?
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // URL format tests
    #[test]
    fn parse_sslmode_url_require() {
        assert_eq!(
            parse_sslmode("postgres://host/db?sslmode=require").as_deref(),
            Some("require")
        );
    }

    #[test]
    fn parse_sslmode_url_verify_full() {
        assert_eq!(
            parse_sslmode("postgres://host/db?sslmode=verify-full").as_deref(),
            Some("verify-full")
        );
    }

    #[test]
    fn parse_sslmode_url_verify_ca() {
        assert_eq!(
            parse_sslmode("postgres://host/db?sslmode=verify-ca").as_deref(),
            Some("verify-ca")
        );
    }

    #[test]
    fn parse_sslmode_url_disable() {
        assert_eq!(
            parse_sslmode("postgres://host/db?sslmode=disable").as_deref(),
            Some("disable")
        );
    }

    #[test]
    fn parse_sslmode_url_absent() {
        assert_eq!(parse_sslmode("postgres://host/db"), None);
    }

    #[test]
    fn parse_sslmode_url_other_params() {
        assert_eq!(
            parse_sslmode(
                "postgres://host/db?connect_timeout=10&sslmode=require&application_name=test"
            )
            .as_deref(),
            Some("require")
        );
    }

    #[test]
    fn parse_sslmode_url_no_query() {
        assert_eq!(parse_sslmode("postgres://user:pass@host:5432/db"), None);
    }

    // Key-value format tests
    #[test]
    fn parse_sslmode_kv_require() {
        assert_eq!(
            parse_sslmode("host=localhost sslmode=require dbname=test").as_deref(),
            Some("require")
        );
    }

    #[test]
    fn parse_sslmode_kv_absent() {
        assert_eq!(parse_sslmode("host=localhost dbname=test"), None);
    }

    #[test]
    fn parse_sslmode_kv_disable() {
        assert_eq!(
            parse_sslmode("host=localhost sslmode=disable").as_deref(),
            Some("disable")
        );
    }

    #[test]
    fn parse_sslmode_empty_string() {
        assert_eq!(parse_sslmode(""), None);
    }
}
