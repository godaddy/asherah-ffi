use std::sync::Arc;

use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use futures_util::TryStreamExt;
use tiberius::{Client, Config};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;
use url::Url;

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct MssqlMetastore {
    config: Config,
    rt: Arc<tokio::runtime::Runtime>,
}

impl MssqlMetastore {
    pub fn connect(conn: &str) -> anyhow::Result<Self> {
        let config = config_from_str(conn)?;
        let rt = tokio::runtime::Runtime::new()?;
        let store = Self {
            config,
            rt: Arc::new(rt),
        };
        store.ensure_schema()?;
        Ok(store)
    }

    fn ensure_schema(&self) -> anyhow::Result<()> {
        let sql = r#"
IF OBJECT_ID('encryption_key', 'U') IS NULL
BEGIN
    CREATE TABLE encryption_key (
        id NVARCHAR(512) NOT NULL,
        created DATETIME2(3) NOT NULL,
        key_record NVARCHAR(MAX) NOT NULL,
        CONSTRAINT PK_encryption_key PRIMARY KEY (id, created)
    );
END
"#;
        let cfg = self.config.clone();
        self.rt.block_on(async move {
            let mut client = connect(&cfg).await?;
            client.execute(sql, &[]).await?;
            Ok(())
        })
    }
}

impl Metastore for MssqlMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let sql = "SELECT key_record FROM encryption_key WHERE id = @P1 AND created = DATEADD(SECOND, @P2, '1970-01-01')";
        let cfg = self.config.clone();
        let result: Result<Option<EnvelopeKeyRecord>, anyhow::Error> =
            self.rt.block_on(async move {
                let mut client = connect(&cfg).await?;
                let mut stream = client.query(sql, &[&id, &created]).await?;
                while let Some(item) = stream.try_next().await? {
                    if let tiberius::QueryItem::Row(row) = item {
                        let txt: &str = row
                            .get::<&str, _>(0)
                            .ok_or_else(|| anyhow::anyhow!("missing key_record"))?;
                        let ekr: EnvelopeKeyRecord = serde_json::from_str(txt)?;
                        return Ok(Some(ekr));
                    }
                }
                Ok(None)
            });
        match result {
            Ok(value) => Ok(value),
            Err(_) => Ok(None),
        }
    }

    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let sql =
            "SELECT TOP 1 key_record FROM encryption_key WHERE id = @P1 ORDER BY created DESC";
        let cfg = self.config.clone();
        let result: Result<Option<EnvelopeKeyRecord>, anyhow::Error> =
            self.rt.block_on(async move {
                let mut client = connect(&cfg).await?;
                let mut stream = client.query(sql, &[&id]).await?;
                while let Some(item) = stream.try_next().await? {
                    if let tiberius::QueryItem::Row(row) = item {
                        let txt: &str = row
                            .get::<&str, _>(0)
                            .ok_or_else(|| anyhow::anyhow!("missing key_record"))?;
                        let ekr: EnvelopeKeyRecord = serde_json::from_str(txt)?;
                        return Ok(Some(ekr));
                    }
                }
                Ok(None)
            });
        match result {
            Ok(value) => Ok(value),
            Err(_) => Ok(None),
        }
    }

    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        let sql = r#"
IF NOT EXISTS (SELECT 1 FROM encryption_key WHERE id = @P1 AND created = DATEADD(SECOND, @P2, '1970-01-01'))
BEGIN
    INSERT INTO encryption_key (id, created, key_record)
    VALUES (@P1, DATEADD(SECOND, @P2, '1970-01-01'), @P3);
END
"#;
        let payload = match serde_json::to_string(ekr) {
            Ok(value) => value,
            Err(_) => return Ok(false),
        };
        let cfg = self.config.clone();
        let result: Result<bool, anyhow::Error> = self.rt.block_on(async move {
            let mut client = connect(&cfg).await?;
            let rows = client.execute(sql, &[&id, &created, &payload]).await?;
            let affected: u64 = rows.rows_affected().iter().copied().sum();
            Ok(affected > 0)
        });
        match result {
            Ok(value) => Ok(value),
            Err(_) => Ok(false),
        }
    }
}

async fn connect(config: &Config) -> anyhow::Result<Client<tokio_util::compat::Compat<TcpStream>>> {
    let addr = config.get_addr();
    let tcp = TcpStream::connect(addr).await?;
    tcp.set_nodelay(true)?;
    let client = Client::connect(config.clone(), tcp.compat_write()).await?;
    Ok(client)
}

fn config_from_str(conn: &str) -> anyhow::Result<Config> {
    if looks_like_url(conn) {
        let ado = mssql_url_to_ado(conn)?;
        return Ok(Config::from_ado_string(&ado)?);
    }
    Ok(Config::from_ado_string(conn)?)
}

fn looks_like_url(conn: &str) -> bool {
    let lower = conn.trim().to_lowercase();
    lower.starts_with("sqlserver://") || lower.starts_with("mssql://")
}

fn mssql_url_to_ado(conn: &str) -> anyhow::Result<String> {
    let url = Url::parse(conn)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing host"))?;
    let mut server = format!("tcp:{}", host);
    if let Some(port) = url.port() {
        server = format!("{server},{port}");
    }
    let mut parts = vec![format!("Server={server}")];
    if !url.username().is_empty() {
        parts.push(format!("User ID={}", url.username()));
    }
    if let Some(password) = url.password() {
        parts.push(format!("Password={password}"));
    }
    let db = url.path().trim_start_matches('/');
    if !db.is_empty() {
        parts.push(format!("Database={db}"));
    }
    for (key, value) in url.query_pairs() {
        let lower = key.to_lowercase();
        let key_norm = match lower.as_str() {
            "encrypt" => "Encrypt",
            "trustservercertificate" => "TrustServerCertificate",
            "applicationintent" => "ApplicationIntent",
            "integratedsecurity" => "Integrated Security",
            other => other,
        };
        parts.push(format!("{key_norm}={value}"));
    }
    Ok(parts.join(";"))
}

#[cfg(test)]
mod tests {
    use super::mssql_url_to_ado;

    #[test]
    fn mssql_url_to_ado_basic() {
        let ado = mssql_url_to_ado("sqlserver://user:pass@localhost:1433/db?encrypt=true").unwrap();
        assert!(ado.contains("Server=tcp:localhost,1433"));
        assert!(ado.contains("User ID=user"));
        assert!(ado.contains("Password=pass"));
        assert!(ado.contains("Database=db"));
        assert!(ado.contains("Encrypt=true"));
    }
}
