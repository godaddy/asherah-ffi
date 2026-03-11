use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use anyhow::Context;
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
        // Validate REPLICA_READ_CONSISTENCY early (before any connection)
        if let Ok(consistency) = std::env::var("REPLICA_READ_CONSISTENCY") {
            match consistency.as_str() {
                "eventual" | "global" | "session" => {}
                _ => {
                    anyhow::bail!(
                        "invalid REPLICA_READ_CONSISTENCY value: '{}' (expected eventual, global, or session)",
                        consistency
                    );
                }
            }
        }

        Ok(Self {
            url: url.to_string(),
        })
    }

    fn client(&self) -> anyhow::Result<Client> {
        let mut cli = connect_client(&self.url).map_err(|e| {
            log::error!("Postgres connection failed: {e:#}");
            e
        })?;
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
        log::debug!("postgres load: id={id} created={created}");
        let mut c = self.client()?;
        let created_f = created as f64;
        let rows = c.query(
            "SELECT key_record::text FROM encryption_key WHERE id=$1 AND created=to_timestamp($2)",
            &[&id, &created_f],
        ).context(format!("Postgres load query failed for id={id} created={created}"))?;
        match rows.into_iter().next() {
            Some(row) => {
                let txt: String = row.get(0);
                log::debug!("postgres load hit: id={id} created={created}");
                let ekr = serde_json::from_str(&txt).context(format!(
                    "Postgres load: failed to parse key_record JSON for id={id}"
                ))?;
                Ok(Some(ekr))
            }
            None => {
                log::debug!("postgres load miss: id={id} created={created}");
                Ok(None)
            }
        }
    }
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("postgres load_latest: id={id}");
        let mut c = self.client()?;
        let rows = c.query(
            "SELECT key_record::text FROM encryption_key WHERE id=$1 ORDER BY created DESC LIMIT 1",
            &[&id],
        ).context(format!("Postgres load_latest query failed for id={id}"))?;
        match rows.into_iter().next() {
            Some(row) => {
                let txt: String = row.get(0);
                log::debug!("postgres load_latest hit: id={id}");
                let ekr = serde_json::from_str(&txt).context(format!(
                    "Postgres load_latest: failed to parse key_record JSON for id={id}"
                ))?;
                Ok(Some(ekr))
            }
            None => {
                log::debug!("postgres load_latest miss: id={id}");
                Ok(None)
            }
        }
    }
    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        log::debug!("postgres store: id={id} created={created}");
        let mut c = self.client()?;
        let v = serde_json::to_string(ekr).context(format!(
            "Postgres store: failed to serialize key_record for id={id}"
        ))?;
        let created_f = created as f64;
        let v_json: serde_json::Value = serde_json::from_str(&v).context(format!(
            "Postgres store: failed to re-parse key_record JSON for id={id}"
        ))?;
        let res = c.execute(
            "INSERT INTO encryption_key(id, created, key_record) VALUES ($1, to_timestamp($2), $3) ON CONFLICT DO NOTHING",
            &[&id, &created_f, &v_json],
        ).context(format!("Postgres store insert failed for id={id} created={created}"))?;
        let stored = res > 0;
        log::debug!("postgres store: id={id} created={created} stored={stored}");
        Ok(stored)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // URL format tests
    #[test]
    fn parse_sslmode_url_require() {
        assert_eq!(
            parse_sslmode("postgres://host/db?sslmode=require").as_deref(),
            Some("require")
        );
    }

    #[test]
    fn parse_sslmode_url_verify_full() {
        assert_eq!(
            parse_sslmode("postgres://host/db?sslmode=verify-full").as_deref(),
            Some("verify-full")
        );
    }

    #[test]
    fn parse_sslmode_url_verify_ca() {
        assert_eq!(
            parse_sslmode("postgres://host/db?sslmode=verify-ca").as_deref(),
            Some("verify-ca")
        );
    }

    #[test]
    fn parse_sslmode_url_disable() {
        assert_eq!(
            parse_sslmode("postgres://host/db?sslmode=disable").as_deref(),
            Some("disable")
        );
    }

    #[test]
    fn parse_sslmode_url_absent() {
        assert_eq!(parse_sslmode("postgres://host/db"), None);
    }

    #[test]
    fn parse_sslmode_url_other_params() {
        assert_eq!(
            parse_sslmode(
                "postgres://host/db?connect_timeout=10&sslmode=require&application_name=test"
            )
            .as_deref(),
            Some("require")
        );
    }

    #[test]
    fn parse_sslmode_url_no_query() {
        assert_eq!(parse_sslmode("postgres://user:pass@host:5432/db"), None);
    }

    // Key-value format tests
    #[test]
    fn parse_sslmode_kv_require() {
        assert_eq!(
            parse_sslmode("host=localhost sslmode=require dbname=test").as_deref(),
            Some("require")
        );
    }

    #[test]
    fn parse_sslmode_kv_absent() {
        assert_eq!(parse_sslmode("host=localhost dbname=test"), None);
    }

    #[test]
    fn parse_sslmode_kv_disable() {
        assert_eq!(
            parse_sslmode("host=localhost sslmode=disable").as_deref(),
            Some("disable")
        );
    }

    #[test]
    fn parse_sslmode_empty_string() {
        assert_eq!(parse_sslmode(""), None);
    }
}
