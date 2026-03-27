use std::sync::Arc;

use async_trait::async_trait;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlSslMode};
use sqlx::{MySqlPool, Row};

use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use anyhow::Context;

/// Convert Unix epoch seconds to a "YYYY-MM-DD HH:MM:SS" UTC datetime string.
///
/// This matches the Go go-sql-driver/mysql behavior: `time.Unix(epoch, 0)` is
/// formatted in UTC (the driver's default `Loc=time.UTC`) and sent as a plain
/// datetime string without timezone info. MySQL then interprets this string in
/// the session's `@@time_zone`.
fn epoch_to_utc_datetime(epoch: i64) -> String {
    use std::fmt::Write;
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

fn parse_connect_options(url: &str) -> anyhow::Result<MySqlConnectOptions> {
    let opts: MySqlConnectOptions = url
        .parse()
        .with_context(|| format!("invalid MySQL URL: {url}"))?;

    // Apply TLS from MYSQL_TLS_MODE env var (matches Go go-sql-driver tls param)
    let opts = if let Ok(tls_mode) = std::env::var("MYSQL_TLS_MODE") {
        match tls_mode.as_str() {
            "skip-verify" => opts.ssl_mode(MySqlSslMode::Required), // encrypted, no cert check
            "false" => opts.ssl_mode(MySqlSslMode::Disabled),
            _ => opts.ssl_mode(MySqlSslMode::VerifyCa), // "true", "preferred" → verify
        }
    } else {
        opts
    };

    Ok(opts)
}

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct MySqlMetastore {
    pool: MySqlPool,
    /// Private runtime for sync callers (Python, Java, etc.)
    rt: Arc<tokio::runtime::Runtime>,
}

impl MySqlMetastore {
    /// Sync constructor — creates a private tokio runtime for the connection pool.
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let rt = tokio::runtime::Runtime::new()?;
        let pool = rt.block_on(Self::create_pool(url))?;
        Ok(Self {
            pool,
            rt: Arc::new(rt),
        })
    }

    /// Async constructor — creates the pool on the caller's runtime.
    pub async fn connect_async(url: &str) -> anyhow::Result<Self> {
        let pool = Self::create_pool(url).await?;
        let rt = tokio::runtime::Runtime::new()?;
        Ok(Self {
            pool,
            rt: Arc::new(rt),
        })
    }

    async fn create_pool(url: &str) -> anyhow::Result<MySqlPool> {
        let opts = parse_connect_options(url)?;
        let max_pool = std::env::var("ASHERAH_POOL_SIZE")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(10);

        let pool = MySqlPoolOptions::new()
            .min_connections(1)
            .max_connections(max_pool.max(1))
            .connect_with(opts)
            .await
            .context("MySQL connection pool creation failed")?;

        // Aurora replica read consistency
        if let Ok(consistency) = std::env::var("REPLICA_READ_CONSISTENCY") {
            match consistency.as_str() {
                "eventual" | "global" | "session" => {
                    sqlx::query(&format!(
                        "SET aurora_replica_read_consistency = '{consistency}'"
                    ))
                    .execute(&pool)
                    .await
                    .context("Failed to set aurora_replica_read_consistency")?;
                }
                _ => {
                    anyhow::bail!(
                        "invalid REPLICA_READ_CONSISTENCY value: '{}' (expected eventual, global, or session)",
                        consistency
                    );
                }
            }
        }

        Ok(pool)
    }

    fn block_on_maybe<F: std::future::Future>(&self, f: F) -> F::Output {
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| self.rt.block_on(f))
        } else {
            self.rt.block_on(f)
        }
    }

    // ── Async query implementations ──

    async fn load_impl(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("mysql load: id={id} created={created}");
        let ts = epoch_to_utc_datetime(created);
        let row: Option<sqlx::mysql::MySqlRow> =
            sqlx::query("SELECT key_record FROM encryption_key WHERE id=? AND created=?")
                .bind(id)
                .bind(&ts)
                .fetch_optional(&self.pool)
                .await
                .with_context(|| {
                    format!("MySQL load query failed for id={id} created={created}")
                })?;

        if let Some(row) = row {
            let json_str: String = row
                .try_get("key_record")
                .context("MySQL load: failed to get key_record column")?;
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

    async fn load_latest_impl(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("mysql load_latest: id={id}");
        let row: Option<sqlx::mysql::MySqlRow> = sqlx::query(
            "SELECT key_record FROM encryption_key WHERE id=? ORDER BY created DESC LIMIT 1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .with_context(|| format!("MySQL load_latest query failed for id={id}"))?;

        if let Some(row) = row {
            let json_str: String = row
                .try_get("key_record")
                .context("MySQL load_latest: failed to get key_record column")?;
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

    async fn store_impl(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        log::debug!("mysql store: id={id} created={created}");
        let rec = ekr.to_json_fast();
        let ts = epoch_to_utc_datetime(created);
        let result = sqlx::query(
            "INSERT IGNORE INTO encryption_key(id, created, key_record) VALUES(?, ?, CAST(? AS JSON))",
        )
        .bind(id)
        .bind(&ts)
        .bind(rec)
        .execute(&self.pool)
        .await
        .with_context(|| format!("MySQL store insert failed for id={id} created={created}"))?;

        let stored = result.rows_affected() > 0;
        log::debug!("mysql store: id={id} created={created} stored={stored}");
        Ok(stored)
    }
}

#[async_trait]
impl Metastore for MySqlMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        self.block_on_maybe(self.load_impl(id, created))
    }

    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        self.block_on_maybe(self.load_latest_impl(id))
    }

    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        self.block_on_maybe(self.store_impl(id, created, ekr))
    }

    async fn load_async(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        self.load_impl(id, created).await
    }

    async fn load_latest_async(
        &self,
        id: &str,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        self.load_latest_impl(id).await
    }

    async fn store_async(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        self.store_impl(id, created, ekr).await
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
