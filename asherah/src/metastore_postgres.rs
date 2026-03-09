use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use postgres::Client;

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct PostgresMetastore {
    url: String,
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
        let mut cli = connect_client(url)?;
        cli.batch_execute(
            r#"CREATE TABLE IF NOT EXISTS encryption_key (
                id TEXT NOT NULL,
                created TIMESTAMP NOT NULL,
                key_record JSONB NOT NULL,
                PRIMARY KEY(id, created)
            );"#,
        )?;

        // Aurora PostgreSQL write forwarding: set consistency mode on initial connection
        Self::apply_replica_read_consistency(&mut cli)?;

        Ok(Self {
            url: url.to_string(),
        })
    }

    fn client(&self) -> anyhow::Result<Client> {
        let mut cli = connect_client(&self.url)?;
        Self::apply_replica_read_consistency(&mut cli)?;
        Ok(cli)
    }

    fn apply_replica_read_consistency(cli: &mut Client) -> anyhow::Result<()> {
        if let Ok(consistency) = std::env::var("REPLICA_READ_CONSISTENCY") {
            match consistency.as_str() {
                "eventual" | "global" | "session" => {
                    cli.batch_execute(&format!(
                        "SET apg_write_forward.consistency_mode = '{consistency}'"
                    ))?;
                }
                _ => {
                    anyhow::bail!(
                        "invalid REPLICA_READ_CONSISTENCY value: '{}' (expected eventual, global, or session)",
                        consistency
                    );
                }
            }
        }
        Ok(())
    }
}

impl Metastore for PostgresMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let mut c = self.client()?;
        let created_f = created as f64;
        let rows = c.query(
            "SELECT key_record::text FROM encryption_key WHERE id=$1 AND created=to_timestamp($2)",
            &[&id, &created_f],
        )?;
        match rows.into_iter().next() {
            Some(row) => {
                let txt: String = row.get(0);
                let ekr: EnvelopeKeyRecord = serde_json::from_str(&txt)?;
                Ok(Some(ekr))
            }
            None => Ok(None),
        }
    }
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let mut c = self.client()?;
        let rows = c.query(
            "SELECT key_record::text FROM encryption_key WHERE id=$1 ORDER BY created DESC LIMIT 1",
            &[&id],
        )?;
        match rows.into_iter().next() {
            Some(row) => {
                let txt: String = row.get(0);
                let ekr: EnvelopeKeyRecord = serde_json::from_str(&txt)?;
                Ok(Some(ekr))
            }
            None => Ok(None),
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
        let created_f = created as f64;
        let v_json: serde_json::Value = serde_json::from_str(&v)?;
        let res = c.execute(
            "INSERT INTO encryption_key(id, created, key_record) VALUES ($1, to_timestamp($2), $3) ON CONFLICT DO NOTHING",
            &[&id, &created_f, &v_json],
        )?;
        Ok(res > 0)
    }
}
