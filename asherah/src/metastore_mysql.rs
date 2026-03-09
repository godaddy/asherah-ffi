use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use mysql::prelude::Queryable;
use mysql::{Opts, OptsBuilder, Pool, PooledConn};

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct MySqlMetastore {
    pool: Pool,
}

impl MySqlMetastore {
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let opts: Opts = url.try_into()?;
        let mut builder = OptsBuilder::from_opts(opts);

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
        let mut conn = pool.get_conn()?;
        conn.query_drop(
            r#"CREATE TABLE IF NOT EXISTS encryption_key (
                id VARCHAR(255) NOT NULL,
                created TIMESTAMP NOT NULL,
                key_record JSON NOT NULL,
                PRIMARY KEY(id, created)
            ) ENGINE=InnoDB"#,
        )?;
        Ok(Self { pool })
    }

    fn conn(&self) -> anyhow::Result<PooledConn> {
        Ok(self.pool.get_conn()?)
    }
}

impl Metastore for MySqlMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let mut conn = self.conn()?;
        let row: Option<(String,)> = conn.exec_first(
            "SELECT JSON_EXTRACT(key_record, '$') FROM encryption_key WHERE id=? AND created=FROM_UNIXTIME(?)",
            (id, created),
        )?;
        if let Some((json_str,)) = row {
            Ok(Some(serde_json::from_str(&json_str)?))
        } else {
            Ok(None)
        }
    }

    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let mut conn = self.conn()?;
        let row: Option<(String,)> = conn.exec_first(
            "SELECT JSON_EXTRACT(key_record, '$') FROM encryption_key WHERE id=? ORDER BY created DESC LIMIT 1",
            (id,),
        )?;
        if let Some((json_str,)) = row {
            Ok(Some(serde_json::from_str(&json_str)?))
        } else {
            Ok(None)
        }
    }

    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        let rec = serde_json::to_string(ekr)?;
        let mut conn = self.conn()?;
        conn.exec_drop(
            "INSERT IGNORE INTO encryption_key(id, created, key_record) VALUES(?, FROM_UNIXTIME(?), CAST(? AS JSON))",
            (id, created, rec),
        )?;
        Ok(conn.affected_rows() > 0)
    }
}
