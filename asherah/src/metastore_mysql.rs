use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use anyhow::Context;
use mysql::prelude::Queryable;
use mysql::{Opts, OptsBuilder, Pool, PooledConn, SslOpts};

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct MySqlMetastore {
    pool: Pool,
}

impl MySqlMetastore {
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let opts: Opts = url.try_into()?;
        let mut builder = OptsBuilder::from_opts(opts);

        // Apply TLS configuration from MYSQL_TLS_MODE env var.
        // Values match Go go-sql-driver/mysql `tls` parameter:
        //   "skip-verify" → TLS required, skip certificate verification
        //   "true"        → TLS required with certificate verification
        //   "false"       → TLS disabled (explicit)
        //   "preferred"   → TLS required with verification (best-effort mapping)
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
                // "true", "preferred", or any other value → require TLS with verification
                _ => {
                    builder = builder.ssl_opts(Some(SslOpts::default()));
                }
            }
        }

        // Aurora MySQL write forwarding: set replica read consistency on each connection
        if let Ok(consistency) = std::env::var("REPLICA_READ_CONSISTENCY") {
            match consistency.as_str() {
                "eventual" | "global" | "session" => {
                    builder = builder.init(vec![format!(
                        "SET aurora_replica_read_consistency = '{consistency}'"
                    )]);
                }
                _ => {
                    anyhow::bail!(
                        "invalid REPLICA_READ_CONSISTENCY value: '{}' (expected eventual, global, or session)",
                        consistency
                    );
                }
            }
        }

        let pool = Pool::new(builder)?;
        Ok(Self { pool })
    }

    fn conn(&self) -> anyhow::Result<PooledConn> {
        self.pool.get_conn().map_err(|e| {
            log::error!("MySQL connection pool error: {e:#}");
            anyhow::anyhow!("MySQL connection failed: {e}")
        })
    }
}

impl Metastore for MySqlMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("mysql load: id={id} created={created}");
        let mut conn = self.conn()?;
        let row: Option<(String,)> = conn.exec_first(
            "SELECT JSON_EXTRACT(key_record, '$') FROM encryption_key WHERE id=? AND created=FROM_UNIXTIME(?)",
            (id, created),
        ).context(format!("MySQL load query failed for id={id} created={created}"))?;
        if let Some((json_str,)) = row {
            log::debug!("mysql load hit: id={id} created={created}");
            let ekr = serde_json::from_str(&json_str).context(format!(
                "MySQL load: failed to parse key_record JSON for id={id}"
            ))?;
            Ok(Some(ekr))
        } else {
            log::debug!("mysql load miss: id={id} created={created}");
            Ok(None)
        }
    }

    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("mysql load_latest: id={id}");
        let mut conn = self.conn()?;
        let row: Option<(String,)> = conn.exec_first(
            "SELECT JSON_EXTRACT(key_record, '$') FROM encryption_key WHERE id=? ORDER BY created DESC LIMIT 1",
            (id,),
        ).context(format!("MySQL load_latest query failed for id={id}"))?;
        if let Some((json_str,)) = row {
            log::debug!("mysql load_latest hit: id={id}");
            let ekr = serde_json::from_str(&json_str).context(format!(
                "MySQL load_latest: failed to parse key_record JSON for id={id}"
            ))?;
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
        let rec = serde_json::to_string(ekr).context(format!(
            "MySQL store: failed to serialize key_record for id={id}"
        ))?;
        let mut conn = self.conn()?;
        conn.exec_drop(
            "INSERT IGNORE INTO encryption_key(id, created, key_record) VALUES(?, FROM_UNIXTIME(?), CAST(? AS JSON))",
            (id, created, rec),
        ).context(format!("MySQL store insert failed for id={id} created={created}"))?;
        let stored = conn.affected_rows() > 0;
        log::debug!("mysql store: id={id} created={created} stored={stored}");
        Ok(stored)
    }
}
