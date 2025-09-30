use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
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
impl Metastore for SqliteMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT key_record FROM encryption_key WHERE id=?1 AND created = datetime(?2, 'unixepoch')")?;
        let mut rows = stmt.query(params![id, created])?;
        if let Some(row) = rows.next()? {
            let txt: String = row.get(0)?;
            let ekr: EnvelopeKeyRecord = serde_json::from_str(&txt)?;
            if std::env::var("ASHERAH_INTEROP_DEBUG").is_ok() {
                log::debug!("sqlite load hit id={} created={}", id, created);
            }
            Ok(Some(ekr))
        } else {
            if std::env::var("ASHERAH_INTEROP_DEBUG").is_ok() {
                log::debug!("sqlite load miss id={} created={}", id, created);
            }
            Ok(None)
        }
    }
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT key_record FROM encryption_key WHERE id=?1 ORDER BY created DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            let txt: String = row.get(0)?;
            let ekr: EnvelopeKeyRecord = serde_json::from_str(&txt)?;
            Ok(Some(ekr))
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
        let conn = self.conn.lock();
        let res = conn.execute(
            "INSERT OR IGNORE INTO encryption_key(id, created, key_record) VALUES (?1, datetime(?2, 'unixepoch'), ?3)",
            params![id, created, rec],
        )?;
        if std::env::var("ASHERAH_INTEROP_DEBUG").is_ok() {
            log::debug!("sqlite store id={} created={} res={}", id, created, res);
        }
        Ok(res > 0)
    }
    fn region_suffix(&self) -> Option<String> {
        None
    }
}
