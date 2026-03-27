use std::cell::RefCell;
use std::fmt::Write;

use async_trait::async_trait;
use mysql::prelude::Queryable;
use mysql::{Opts, OptsBuilder, Pool, PoolConstraints, PoolOpts, PooledConn, SslOpts};
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlSslMode};
use sqlx::{MySqlPool, Row};

use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use anyhow::Context;

thread_local! {
    /// Thread-local MySQL connection cache for the sync path.
    static TL_CONN: RefCell<Option<PooledConn>> = const { RefCell::new(None) };
}

/// Convert Unix epoch seconds to a "YYYY-MM-DD HH:MM:SS" UTC datetime string.
fn epoch_to_utc_datetime(epoch: i64) -> String {
    let day_secs = epoch.rem_euclid(86400);
    let hour = day_secs / 3600;
    let min = (day_secs % 3600) / 60;
    let sec = day_secs % 60;
    let z = epoch.div_euclid(86400) + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let mut buf = String::with_capacity(19);
    let _ = write!(buf, "{y:04}-{m:02}-{d:02} {hour:02}:{min:02}:{sec:02}");
    buf
}

/// MySQL metastore with dual connection pools:
/// - Sync pool (mysql crate): direct blocking I/O with thread-local caching, zero runtime overhead
/// - Async pool (sqlx): truly async I/O for Node.js encrypt_async/decrypt_async
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct MySqlMetastore {
    sync_pool: Pool,
    async_pool: MySqlPool,
}

impl MySqlMetastore {
    /// Sync constructor.
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let sync_pool = Self::create_sync_pool(url)?;
        let rt = tokio::runtime::Runtime::new()?;
        let async_pool = rt.block_on(Self::create_async_pool(url))?;
        drop(rt);
        Ok(Self {
            sync_pool,
            async_pool,
        })
    }

    /// Async constructor.
    pub async fn connect_async(url: &str) -> anyhow::Result<Self> {
        let sync_pool = Self::create_sync_pool(url)?;
        let async_pool = Self::create_async_pool(url).await?;
        Ok(Self {
            sync_pool,
            async_pool,
        })
    }

    fn create_sync_pool(url: &str) -> anyhow::Result<Pool> {
        let opts: Opts = url.try_into()?;
        let constraints = opts.get_pool_opts().constraints();
        let need_pool_defaults = constraints.min() == PoolConstraints::DEFAULT.min()
            && constraints.max() == PoolConstraints::DEFAULT.max();
        let mut builder = OptsBuilder::from_opts(opts);

        if let Ok(tls_mode) = std::env::var("MYSQL_TLS_MODE") {
            match tls_mode.as_str() {
                "skip-verify" => {
                    builder = builder.ssl_opts(Some(
                        SslOpts::default()
                            .with_danger_accept_invalid_certs(true)
                            .with_danger_skip_domain_validation(true),
                    ));
                }
                "false" => {
                    builder = builder.ssl_opts(None::<SslOpts>);
                }
                _ => {
                    builder = builder.ssl_opts(Some(SslOpts::default()));
                }
            }
        }

        if let Ok(consistency) = std::env::var("REPLICA_READ_CONSISTENCY") {
            match consistency.as_str() {
                "eventual" | "global" | "session" => {
                    builder = builder.init(vec![format!(
                        "SET aurora_replica_read_consistency = '{consistency}'"
                    )]);
                }
                _ => {
                    anyhow::bail!("invalid REPLICA_READ_CONSISTENCY value: '{consistency}'");
                }
            }
        }

        if need_pool_defaults {
            let max_pool = std::env::var("ASHERAH_POOL_SIZE")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(10);
            builder = builder.pool_opts(PoolOpts::default().with_constraints(
                PoolConstraints::new(1, max_pool.max(1)).expect("valid: min=1 <= max>=1"),
            ));
        }

        Ok(Pool::new(builder)?)
    }

    async fn create_async_pool(url: &str) -> anyhow::Result<MySqlPool> {
        let opts: MySqlConnectOptions = url
            .parse()
            .with_context(|| format!("invalid MySQL URL for async pool: {url}"))?;
        let opts = if let Ok(tls_mode) = std::env::var("MYSQL_TLS_MODE") {
            match tls_mode.as_str() {
                "skip-verify" => opts.ssl_mode(MySqlSslMode::Required),
                "false" => opts.ssl_mode(MySqlSslMode::Disabled),
                _ => opts.ssl_mode(MySqlSslMode::VerifyCa),
            }
        } else {
            opts
        };
        let max_pool = std::env::var("ASHERAH_POOL_SIZE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(10);
        let pool = MySqlPoolOptions::new()
            .min_connections(1)
            .max_connections(max_pool.max(1))
            .connect_with(opts)
            .await
            .context("MySQL async pool creation failed")?;
        Ok(pool)
    }

    fn conn(&self) -> anyhow::Result<PooledConn> {
        let reused = TL_CONN.with(|cell| cell.borrow_mut().take());
        if let Some(conn) = reused {
            return Ok(conn);
        }
        self.sync_pool.get_conn().map_err(|e| {
            log::error!("MySQL connection pool error: {e:#}");
            anyhow::anyhow!("MySQL connection failed: {e}")
        })
    }

    fn return_conn(conn: PooledConn) {
        TL_CONN.with(|cell| {
            *cell.borrow_mut() = Some(conn);
        });
    }
}

#[async_trait]
impl Metastore for MySqlMetastore {
    // ── Sync methods (mysql crate — zero runtime overhead) ──

    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("mysql load: id={id} created={created}");
        let mut conn = self.conn()?;
        let ts = epoch_to_utc_datetime(created);
        let row: Option<(String,)> = conn
            .exec_first(
                "SELECT key_record FROM encryption_key WHERE id=? AND created=?",
                (id, &ts),
            )
            .with_context(|| format!("MySQL load query failed for id={id} created={created}"))?;
        Self::return_conn(conn);
        if let Some((json_str,)) = row {
            log::debug!("mysql load hit: id={id} created={created}");
            let ekr = EnvelopeKeyRecord::from_json_fast(&json_str).with_context(|| {
                format!("MySQL load: failed to parse key_record JSON for id={id}")
            })?;
            Ok(Some(ekr))
        } else {
            log::debug!("mysql load miss: id={id} created={created}");
            Ok(None)
        }
    }

    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("mysql load_latest: id={id}");
        let mut conn = self.conn()?;
        let row: Option<(String,)> = conn
            .exec_first(
                "SELECT key_record FROM encryption_key WHERE id=? ORDER BY created DESC LIMIT 1",
                (id,),
            )
            .with_context(|| format!("MySQL load_latest query failed for id={id}"))?;
        Self::return_conn(conn);
        if let Some((json_str,)) = row {
            log::debug!("mysql load_latest hit: id={id}");
            let ekr = EnvelopeKeyRecord::from_json_fast(&json_str).with_context(|| {
                format!("MySQL load_latest: failed to parse key_record JSON for id={id}")
            })?;
            Ok(Some(ekr))
        } else {
            log::debug!("mysql load_latest miss: id={id}");
            Ok(None)
        }
    }

    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        log::debug!("mysql store: id={id} created={created}");
        let rec = ekr.to_json_fast();
        let mut conn = self.conn()?;
        let ts = epoch_to_utc_datetime(created);
        conn.exec_drop(
            "INSERT IGNORE INTO encryption_key(id, created, key_record) VALUES(?, ?, CAST(? AS JSON))",
            (id, &ts, rec),
        ).with_context(|| format!("MySQL store insert failed for id={id} created={created}"))?;
        let stored = conn.affected_rows() > 0;
        Self::return_conn(conn);
        log::debug!("mysql store: id={id} created={created} stored={stored}");
        Ok(stored)
    }

    // ── Async methods (sqlx — truly async, no thread spawn) ──

    async fn load_async(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("mysql load_async: id={id} created={created}");
        let ts = epoch_to_utc_datetime(created);
        let row: Option<sqlx::mysql::MySqlRow> = sqlx::query(
            "SELECT CAST(key_record AS CHAR) AS key_record FROM encryption_key WHERE id=? AND created=?",
        )
        .bind(id)
        .bind(&ts)
        .fetch_optional(&self.async_pool)
        .await
        .with_context(|| format!("MySQL load_async query failed for id={id} created={created}"))?;

        if let Some(row) = row {
            let json_str: String = row
                .try_get("key_record")
                .context("MySQL load_async: failed to get key_record column")?;
            log::debug!("mysql load_async hit: id={id} created={created}");
            let ekr = EnvelopeKeyRecord::from_json_fast(&json_str).with_context(|| {
                format!("MySQL load_async: failed to parse key_record JSON for id={id}")
            })?;
            Ok(Some(ekr))
        } else {
            log::debug!("mysql load_async miss: id={id} created={created}");
            Ok(None)
        }
    }

    async fn load_latest_async(
        &self,
        id: &str,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("mysql load_latest_async: id={id}");
        let row: Option<sqlx::mysql::MySqlRow> = sqlx::query(
            "SELECT CAST(key_record AS CHAR) AS key_record FROM encryption_key WHERE id=? ORDER BY created DESC LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&self.async_pool)
        .await
        .with_context(|| format!("MySQL load_latest_async query failed for id={id}"))?;

        if let Some(row) = row {
            let json_str: String = row
                .try_get("key_record")
                .context("MySQL load_latest_async: failed to get key_record column")?;
            log::debug!("mysql load_latest_async hit: id={id}");
            let ekr = EnvelopeKeyRecord::from_json_fast(&json_str).with_context(|| {
                format!("MySQL load_latest_async: failed to parse key_record JSON for id={id}")
            })?;
            Ok(Some(ekr))
        } else {
            log::debug!("mysql load_latest_async miss: id={id}");
            Ok(None)
        }
    }

    async fn store_async(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        log::debug!("mysql store_async: id={id} created={created}");
        let rec = ekr.to_json_fast();
        let ts = epoch_to_utc_datetime(created);
        let result = sqlx::query(
            "INSERT IGNORE INTO encryption_key(id, created, key_record) VALUES(?, ?, CAST(? AS JSON))",
        )
        .bind(id)
        .bind(&ts)
        .bind(rec)
        .execute(&self.async_pool)
        .await
        .with_context(|| format!("MySQL store_async insert failed for id={id} created={created}"))?;

        let stored = result.rows_affected() > 0;
        log::debug!("mysql store_async: id={id} created={created} stored={stored}");
        Ok(stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_zero() {
        assert_eq!(epoch_to_utc_datetime(0), "1970-01-01 00:00:00");
    }

    #[test]
    fn epoch_known_date() {
        assert_eq!(epoch_to_utc_datetime(1_705_325_400), "2024-01-15 13:30:00");
    }

    #[test]
    fn epoch_recent() {
        assert_eq!(epoch_to_utc_datetime(1_773_320_280), "2026-03-12 12:58:00");
    }

    #[test]
    fn epoch_leap_year() {
        assert_eq!(epoch_to_utc_datetime(1_709_208_000), "2024-02-29 12:00:00");
    }

    #[test]
    fn epoch_end_of_day() {
        assert_eq!(epoch_to_utc_datetime(1_704_067_199), "2023-12-31 23:59:59");
    }

    #[test]
    fn epoch_y2k() {
        assert_eq!(epoch_to_utc_datetime(946_684_800), "2000-01-01 00:00:00");
    }
}
