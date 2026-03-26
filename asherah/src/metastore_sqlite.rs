use async_trait::async_trait;

use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use anyhow::Context;
#[cfg(feature = "sqlite")]
use parking_lot::Mutex;
#[cfg(feature = "sqlite")]
use rusqlite::{params, Connection};

#[cfg(feature = "sqlite")]
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct SqliteMetastore {
    conn: std::sync::Arc<Mutex<Connection>>,
}

#[cfg(feature = "sqlite")]
impl SqliteMetastore {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"CREATE TABLE IF NOT EXISTS encryption_key (
                    id TEXT NOT NULL,
                    created TIMESTAMP NOT NULL,
                    key_record TEXT NOT NULL,
                    PRIMARY KEY (id, created)
                );
            "#,
        )?;
        Ok(Self {
            conn: std::sync::Arc::new(Mutex::new(conn)),
        })
    }
}

#[cfg(feature = "sqlite")]
#[async_trait]
impl Metastore for SqliteMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("sqlite load: id={id} created={created}");
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT key_record FROM encryption_key WHERE id=?1 AND created = datetime(?2, 'unixepoch')")
            .with_context(|| format!("SQLite load prepare failed for id={id}"))?;
        let mut rows = stmt
            .query(params![id, created])
            .with_context(|| format!("SQLite load query failed for id={id} created={created}"))?;
        if let Some(row) = rows.next()? {
            let txt: String = row.get(0)?;
            let ekr: EnvelopeKeyRecord = serde_json::from_str(&txt).with_context(|| {
                format!("SQLite load: failed to parse key_record JSON for id={id}")
            })?;
            log::debug!("sqlite load hit: id={id} created={created}");
            Ok(Some(ekr))
        } else {
            log::debug!("sqlite load miss: id={id} created={created}");
            Ok(None)
        }
    }
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("sqlite load_latest: id={id}");
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT key_record FROM encryption_key WHERE id=?1 ORDER BY created DESC LIMIT 1",
            )
            .with_context(|| format!("SQLite load_latest prepare failed for id={id}"))?;
        let mut rows = stmt
            .query(params![id])
            .with_context(|| format!("SQLite load_latest query failed for id={id}"))?;
        if let Some(row) = rows.next()? {
            let txt: String = row.get(0)?;
            let ekr: EnvelopeKeyRecord = serde_json::from_str(&txt).with_context(|| {
                format!("SQLite load_latest: failed to parse key_record JSON for id={id}")
            })?;
            log::debug!("sqlite load_latest hit: id={id}");
            Ok(Some(ekr))
        } else {
            log::debug!("sqlite load_latest miss: id={id}");
            Ok(None)
        }
    }
    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        log::debug!("sqlite store: id={id} created={created}");
        let rec = serde_json::to_string(ekr)
            .with_context(|| format!("SQLite store: failed to serialize key_record for id={id}"))?;
        let conn = self.conn.lock();
        let res = conn.execute(
            "INSERT OR IGNORE INTO encryption_key(id, created, key_record) VALUES (?1, datetime(?2, 'unixepoch'), ?3)",
            params![id, created, rec],
        ).with_context(|| format!("SQLite store insert failed for id={id} created={created}"))?;
        let stored = res > 0;
        log::debug!("sqlite store: id={id} created={created} stored={stored}");
        Ok(stored)
    }
    fn region_suffix(&self) -> Option<String> {
        None
    }
}
