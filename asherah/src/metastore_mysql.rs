use async_trait::async_trait;

use crate::pool_mysql::{self, ManagedPool, PoolConfig};
use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use anyhow::Context;
use mysql::prelude::Queryable;
use std::fmt::Write;
use std::sync::Arc;

/// Convert Unix epoch seconds to a "YYYY-MM-DD HH:MM:SS" UTC datetime string.
///
/// This matches the Go go-sql-driver/mysql behavior: `time.Unix(epoch, 0)` is
/// formatted in UTC (the driver's default `Loc=time.UTC`) and sent as a plain
/// datetime string without timezone info. MySQL then interprets this string in
/// the session's `@@time_zone`.
///
/// Using `FROM_UNIXTIME(epoch)` is technically more correct (timezone-safe),
/// but it produces different results than Go when `@@time_zone` isn't UTC,
/// breaking cross-language interoperability.
fn epoch_to_utc_datetime(epoch: i64) -> String {
    // Seconds within the day
    let day_secs = epoch.rem_euclid(86400);
    let hour = day_secs / 3600;
    let min = (day_secs % 3600) / 60;
    let sec = day_secs % 60;

    // Days since Unix epoch (1970-01-01)
    let z = epoch.div_euclid(86400) + 719_468;
    // Howard Hinnant's civil_from_days algorithm
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

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct MySqlMetastore {
    pool: Arc<ManagedPool>,
}

impl MySqlMetastore {
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let opts = pool_mysql::build_opts(url)?;

        let mut config = PoolConfig::default();
        if let Some(max_open) = std::env::var("ASHERAH_POOL_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
        {
            config.max_open = max_open;
        }

        let pool = ManagedPool::new(opts, config);

        // Fail-fast: validate connectivity at setup time
        pool.validate()?;

        Ok(Self { pool })
    }

    fn conn(&self) -> anyhow::Result<pool_mysql::ManagedConn> {
        self.pool.get_conn()
    }
}

#[async_trait]
impl Metastore for MySqlMetastore {
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
        drop(conn);
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
        drop(conn);
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
        drop(conn);
        log::debug!("mysql store: id={id} created={created} stored={stored}");
        Ok(stored)
    }

    // Async methods use spawn_blocking (reuses thread pool) instead of
    // std::thread::spawn (creates new OS thread per call). The mysql crate
    // doesn't call block_on internally, so spawn_blocking is safe here.
    async fn load_async(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let this = self.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || this.load(&id, created))
            .await
            .map_err(|e| anyhow::anyhow!("mysql load_async join error: {e}"))?
    }

    async fn load_latest_async(
        &self,
        id: &str,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let this = self.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || this.load_latest(&id))
            .await
            .map_err(|e| anyhow::anyhow!("mysql load_latest_async join error: {e}"))?
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
            .map_err(|e| anyhow::anyhow!("mysql store_async join error: {e}"))?
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
        // 2024-01-15 13:30:00 UTC = 1705325400
        assert_eq!(epoch_to_utc_datetime(1_705_325_400), "2024-01-15 13:30:00");
    }

    #[test]
    fn epoch_recent() {
        // 2026-03-12 12:58:00 UTC = 1773320280
        assert_eq!(epoch_to_utc_datetime(1_773_320_280), "2026-03-12 12:58:00");
    }

    #[test]
    fn epoch_leap_year() {
        // 2024-02-29 12:00:00 UTC = 1709208000
        assert_eq!(epoch_to_utc_datetime(1_709_208_000), "2024-02-29 12:00:00");
    }

    #[test]
    fn epoch_end_of_day() {
        // 2023-12-31 23:59:59 UTC = 1704067199
        assert_eq!(epoch_to_utc_datetime(1_704_067_199), "2023-12-31 23:59:59");
    }

    #[test]
    fn epoch_y2k() {
        // 2000-01-01 00:00:00 UTC = 946684800
        assert_eq!(epoch_to_utc_datetime(946_684_800), "2000-01-01 00:00:00");
    }
}
