use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use postgres::{Client, NoTls};

#[derive(Clone)]
pub struct PostgresMetastore {
    url: String,
}

impl PostgresMetastore {
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let mut cli = Client::connect(url, NoTls)?;
        cli.batch_execute(
            r#"CREATE TABLE IF NOT EXISTS encryption_key (
                id TEXT NOT NULL,
                created TIMESTAMP NOT NULL,
                key_record JSONB NOT NULL,
                PRIMARY KEY(id, created)
            );"#,
        )?;
        Ok(Self {
            url: url.to_string(),
        })
    }

    fn client(&self) -> anyhow::Result<Client> {
        Ok(Client::connect(&self.url, NoTls)?)
    }
}

impl Metastore for PostgresMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let mut c = self.client()?;
        let rows = c.query(
            "SELECT key_record::text FROM encryption_key WHERE id=$1 AND created=to_timestamp($2)",
            &[&id, &created],
        )?;
        if let Some(row) = rows.into_iter().next() {
            let txt: String = row.get(0);
            let ekr: EnvelopeKeyRecord = serde_json::from_str(&txt)?;
            Ok(Some(ekr))
        } else {
            Ok(None)
        }
    }
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let mut c = self.client()?;
        let rows = c.query(
            "SELECT key_record::text FROM encryption_key WHERE id=$1 ORDER BY created DESC LIMIT 1",
            &[&id],
        )?;
        if let Some(row) = rows.into_iter().next() {
            let txt: String = row.get(0);
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
        let mut c = self.client()?;
        let v = serde_json::to_string(ekr)?;
        let res = c.execute(
            "INSERT INTO encryption_key(id, created, key_record) VALUES ($1, to_timestamp($2), $3::jsonb) ON CONFLICT DO NOTHING",
            &[&id, &created, &v],
        )?;
        Ok(res > 0)
    }
}
