use async_trait::async_trait;

use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use anyhow::Context;
use postgres::Client;
use std::mem::ManuallyDrop;
use std::sync::{Arc, Mutex};

/// Default max open connections — 0 means unlimited, matching Go's `database/sql`.
const DEFAULT_MAX_OPEN: usize = 0;

/// Default max idle connections, matching Go's database/sql MaxIdleConns default.
const DEFAULT_MAX_IDLE: usize = 2;

/// Replica read consistency modes accepted by Aurora's `apg_write_forward.consistency_mode`.
///
/// Restricting the wire-level setting to a closed enum keeps user input out
/// of the `SET` statement entirely — the SQL strings are compile-time
/// constants picked by `as_set_statement` (T7 in
/// `docs/review-2026-05-05-findings.md`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaConsistency {
    Eventual,
    Global,
    Session,
}

impl ReplicaConsistency {
    /// Parse the case-sensitive wire value (`eventual`, `global`, `session`).
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "eventual" => Ok(Self::Eventual),
            "global" => Ok(Self::Global),
            "session" => Ok(Self::Session),
            other => anyhow::bail!(
                "invalid REPLICA_READ_CONSISTENCY value: '{other}' \
                 (expected eventual, global, or session)"
            ),
        }
    }

    /// Returns the static `SET` statement for this mode. The value is a
    /// `&'static str` literal, never a runtime-formatted string.
    fn as_set_statement(self) -> &'static str {
        match self {
            Self::Eventual => "SET apg_write_forward.consistency_mode = 'eventual'",
            Self::Global => "SET apg_write_forward.consistency_mode = 'global'",
            Self::Session => "SET apg_write_forward.consistency_mode = 'session'",
        }
    }
}

struct PoolInner {
    conns: Vec<Client>,
    checked_out: usize,
}

struct PgPool {
    url: String,
    replica_consistency: Option<ReplicaConsistency>,
    inner: Mutex<PoolInner>,
    /// Notified when a connection is returned to the pool. Replaces
    /// the previous `std::thread::sleep` exponential backoff so a
    /// waiting thread wakes immediately on availability instead of
    /// sleeping out the full backoff. T-finding "std::thread::sleep
    /// up to 320ms on blocking pool worker; consider Condvar" in
    /// `docs/review-2026-05-05-findings.md`.
    return_cv: std::sync::Condvar,
    max_idle: usize,
    max_open: usize,
}

/// A connection checked out from the pool. Returns to the pool on drop.
///
/// The inner `Client` is held in `ManuallyDrop` rather than `Option`
/// so `Deref`/`DerefMut` can return `&Client`/`&mut Client` without an
/// `expect()` that would violate the no-panic policy. The type
/// invariant — `client` is initialized for the whole lifetime of
/// `PgPooledClient` and is taken out exactly once in `Drop::drop` — is
/// upheld because the only way to remove the `ManuallyDrop` value is
/// through `Drop`, which by definition runs at most once and after
/// which the value is no longer accessible to safe code.
struct PgPooledClient {
    pool: Arc<PgPool>,
    client: ManuallyDrop<Client>,
}

impl Drop for PgPooledClient {
    fn drop(&mut self) {
        // SAFETY: `client` is initialized for the lifetime of `self`
        // and `Drop::drop` runs at most once. The value is not
        // accessed via `Deref`/`DerefMut` after this point because
        // safe code can't observe a dropped value.
        let client = unsafe { ManuallyDrop::take(&mut self.client) };
        {
            let mut inner = self.pool.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.checked_out -= 1;
            if !client.is_closed() && inner.conns.len() < self.pool.max_idle {
                inner.conns.push(client);
            }
            // Drop `inner` (and therefore the lock) before notifying so
            // the woken waiter doesn't immediately block trying to
            // acquire the lock we still hold.
        }
        // Wake one waiter (if any) so it can retake the released slot
        // immediately rather than sleeping out the rest of its
        // backoff window.
        self.pool.return_cv.notify_one();
        // Otherwise `client` drops here — closing the postgres
        // connection cleanly.
    }
}

impl std::ops::Deref for PgPooledClient {
    type Target = Client;
    fn deref(&self) -> &Client {
        &self.client
    }
}

impl std::ops::DerefMut for PgPooledClient {
    fn deref_mut(&mut self) -> &mut Client {
        &mut self.client
    }
}

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct PostgresMetastore {
    pool: Arc<PgPool>,
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
    /// Connect with explicit config — no env var reads.
    pub fn connect_with(
        url: &str,
        max_open: Option<usize>,
        max_idle: Option<usize>,
        replica_consistency: Option<String>,
    ) -> anyhow::Result<Self> {
        let replica_consistency = replica_consistency
            .as_deref()
            .map(ReplicaConsistency::parse)
            .transpose()?;
        let max_open = max_open.unwrap_or(DEFAULT_MAX_OPEN);
        let max_idle = max_idle.unwrap_or(DEFAULT_MAX_IDLE);
        let max_idle = if max_open > 0 {
            max_idle.min(max_open)
        } else {
            max_idle
        };

        Ok(Self {
            pool: Arc::new(PgPool {
                url: url.to_string(),
                replica_consistency,
                inner: Mutex::new(PoolInner {
                    conns: Vec::with_capacity(max_idle),
                    checked_out: 0,
                }),
                return_cv: std::sync::Condvar::new(),
                max_idle,
                max_open,
            }),
        })
    }

    /// Connect using env vars for pool config (legacy entry point).
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let replica_consistency = std::env::var("REPLICA_READ_CONSISTENCY").ok();

        fn env_usize(key: &str) -> Option<usize> {
            std::env::var(key).ok().and_then(|v| v.parse().ok())
        }
        let max_open =
            env_usize("ASHERAH_POOL_MAX_OPEN").or_else(|| env_usize("ASHERAH_POOL_SIZE"));
        let max_idle = env_usize("ASHERAH_POOL_MAX_IDLE");

        Self::connect_with(url, max_open, max_idle, replica_consistency)
    }

    fn client(&self) -> anyhow::Result<PgPooledClient> {
        // Total time we'll wait for a checked-out connection to come
        // back before giving up. Matches the prior backoff-sum
        // (~640ms across 10 retries) but spent on a Condvar wait
        // instead of a polling sleep so a return wakes us immediately.
        let total_wait = std::time::Duration::from_millis(640);
        let deadline = std::time::Instant::now() + total_wait;

        loop {
            let mut inner = self.pool.inner.lock().unwrap_or_else(|e| e.into_inner());

            // Try to reuse an idle connection from the pool.
            while let Some(client) = inner.conns.pop() {
                if !client.is_closed() {
                    inner.checked_out += 1;
                    return Ok(PgPooledClient {
                        pool: Arc::clone(&self.pool),
                        client: ManuallyDrop::new(client),
                    });
                }
            }

            // No idle connection available — check if we can open a new one.
            // max_open == 0 means unlimited (matching Go's database/sql).
            let total = inner.checked_out + inner.conns.len();
            if self.pool.max_open > 0 && total >= self.pool.max_open {
                let now = std::time::Instant::now();
                if now >= deadline {
                    drop(inner);
                    anyhow::bail!(
                        "Postgres connection pool exhausted after {:?} wait (max_open={})",
                        total_wait,
                        self.pool.max_open
                    );
                }
                // Wait on the Condvar — released when a `PgPooledClient`
                // is dropped and returns its connection.
                let remaining = deadline - now;
                let (returned_inner, _timeout) = self
                    .pool
                    .return_cv
                    .wait_timeout(inner, remaining)
                    .unwrap_or_else(|e| {
                        // Mutex was poisoned; recover the guard. The
                        // wait_timeout API returns the inner Result via
                        // PoisonError so we have to peel both layers.
                        let inner = e.into_inner();
                        (inner.0, inner.1)
                    });
                drop(returned_inner);
                continue;
            }
            inner.checked_out += 1;
            // Re-acquire is implicit on the next loop iteration's `lock()`.
            drop(inner);
            // Continue past the lock-scoped block to construction.
            break;
        }
        // ── connection-creation path (lock-free) ────────────────────

        // `checked_out += 1` was committed inside the loop above; if
        // anything between here and `pooled` being constructed
        // (which takes ownership of the increment via
        // `PgPooledClient::Drop`) returns Err, the increment leaks
        // and the pool deadlocks once `total >= max_open`. A small
        // guard struct decrements on Drop unless we explicitly
        // commit. T-finding "checked_out increment outside
        // failure-decrement lock" in
        // `docs/review-2026-05-05-findings.md`.
        struct CheckoutGuard<'pool> {
            pool: &'pool Arc<PgPool>,
            committed: bool,
        }
        impl Drop for CheckoutGuard<'_> {
            fn drop(&mut self) {
                if !self.committed {
                    let mut inner = self.pool.inner.lock().unwrap_or_else(|e| e.into_inner());
                    inner.checked_out = inner.checked_out.saturating_sub(1);
                    // Wake a waiting acquirer so it can either retake
                    // the slot or hit the deadline cleanly.
                    self.pool.return_cv.notify_one();
                }
            }
        }
        let mut guard = CheckoutGuard {
            pool: &self.pool,
            committed: false,
        };

        // Create a new connection (outside the lock)
        let client = connect_client(&self.pool.url).map_err(|e| {
            log::error!("Postgres connection failed: {e:#}");
            e
        })?;

        // Apply replica read consistency on new connections
        let mut pooled = PgPooledClient {
            pool: Arc::clone(&self.pool),
            client: ManuallyDrop::new(client),
        };
        if let Some(consistency) = self.pool.replica_consistency {
            if let Err(e) = pooled.batch_execute(consistency.as_set_statement()) {
                // pooled will be dropped, which decrements checked_out;
                // the guard is also still un-committed so it will
                // double-decrement — flip committed=true to suppress.
                guard.committed = true;
                return Err(e.into());
            }
        }

        // Ownership transfers to PgPooledClient::Drop now.
        guard.committed = true;
        Ok(pooled)
    }
}

#[async_trait]
impl Metastore for PostgresMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        log::debug!("postgres load: id={id} created={created}");
        let mut c = self.client()?;
        // f64 has 53-bit mantissa, more than enough for any plausible
        // epoch value (current epochs are ~1.7e9; the safe ceiling is
        // ~9e15). Bind as f64 to match Postgres' single-arg
        // `to_timestamp(double precision)` directly. T-finding
        // "created as f64 loses precision for large epochs" in
        // docs/review-2026-05-05-findings.md is documented here as a
        // known precision floor; switching to BIGINT-backed encoding
        // requires schema changes.
        let created_f = created as f64;
        let row = c
            .query_opt(
                "SELECT key_record::text FROM encryption_key \
             WHERE id=$1 AND created=to_timestamp($2)",
                &[&id, &created_f],
            )
            .with_context(|| format!("Postgres load query failed for id={id} created={created}"))?;
        match row {
            Some(row) => {
                let txt: String = row.get(0);
                log::debug!("postgres load hit: id={id} created={created}");
                let ekr = EnvelopeKeyRecord::from_json_fast(&txt).with_context(|| {
                    format!("Postgres load: failed to parse key_record JSON for id={id}")
                })?;
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
        let row = c.query_opt(
            "SELECT key_record::text FROM encryption_key WHERE id=$1 ORDER BY created DESC LIMIT 1",
            &[&id],
        ).with_context(|| format!("Postgres load_latest query failed for id={id}"))?;
        match row {
            Some(row) => {
                let txt: String = row.get(0);
                log::debug!("postgres load_latest hit: id={id}");
                let ekr = EnvelopeKeyRecord::from_json_fast(&txt).with_context(|| {
                    format!("Postgres load_latest: failed to parse key_record JSON for id={id}")
                })?;
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
        let v = ekr.to_json_fast();
        let created_f = created as f64;
        // The double-parse path (`v` → `serde_json::Value` → wire JSONB)
        // could be replaced with `$3::jsonb` casting bound text, but the
        // postgres-rs driver's prepared-statement type-inference rejects
        // a `String` bound at the JSONB position even with the explicit
        // cast in some setups. Keep the parse-and-bind path until it can
        // be replaced with `tokio_postgres::types::ToSql` for `&str`
        // (T-finding "to_json_fast() then serde_json::from_str" in
        // docs/review-2026-05-05-findings.md is left as a follow-up).
        let v_json: serde_json::Value = serde_json::from_str(&v).with_context(|| {
            format!("Postgres store: failed to re-parse key_record JSON for id={id}")
        })?;
        let res = c
            .execute(
                "INSERT INTO encryption_key(id, created, key_record) \
             VALUES ($1, to_timestamp($2), $3) ON CONFLICT DO NOTHING",
                &[&id, &created_f, &v_json],
            )
            .with_context(|| {
                format!("Postgres store insert failed for id={id} created={created}")
            })?;
        let stored = res > 0;
        log::debug!("postgres store: id={id} created={created} stored={stored}");
        if !stored {
            // Surface duplicate-id conflicts at info level so rotation
            // collisions are observable in metrics/logs (T-finding
            // "Postgres store does not log the id on conflict-no-op" in
            // docs/review-2026-05-05-findings.md).
            log::info!(
                "postgres store: duplicate id={id} created={created} (ON CONFLICT DO NOTHING)"
            );
        }
        Ok(stored)
    }

    // The sync postgres crate does blocking I/O with internal block_on for
    // connection management. spawn_blocking is safe here because blocking pool
    // threads don't have the runtime "entered" (only Handle is available).
    async fn load_async(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let this = self.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || this.load(&id, created))
            .await
            .map_err(|e| anyhow::anyhow!("postgres load_async join error: {e}"))?
    }

    async fn load_latest_async(
        &self,
        id: &str,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let this = self.clone();
        let id = id.to_string();
        tokio::task::spawn_blocking(move || this.load_latest(&id))
            .await
            .map_err(|e| anyhow::anyhow!("postgres load_latest_async join error: {e}"))?
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
            .map_err(|e| anyhow::anyhow!("postgres store_async join error: {e}"))?
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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

    // ────────────── ReplicaConsistency (T7) ──────────────

    #[test]
    fn replica_consistency_parse_known_values() {
        assert_eq!(
            ReplicaConsistency::parse("eventual").unwrap(),
            ReplicaConsistency::Eventual
        );
        assert_eq!(
            ReplicaConsistency::parse("global").unwrap(),
            ReplicaConsistency::Global
        );
        assert_eq!(
            ReplicaConsistency::parse("session").unwrap(),
            ReplicaConsistency::Session
        );
    }

    #[test]
    fn replica_consistency_parse_rejects_unknown_and_injection() {
        // Reject unknown legitimate-looking values.
        assert!(ReplicaConsistency::parse("strong").is_err());
        assert!(ReplicaConsistency::parse("EVENTUAL").is_err()); // case-sensitive
                                                                 // Reject SQL injection payloads — these would have been interpolated
                                                                 // into the SET statement by the previous format!() implementation.
        assert!(ReplicaConsistency::parse("eventual'; DROP TABLE keys;--").is_err());
        assert!(ReplicaConsistency::parse("' OR '1'='1").is_err());
        assert!(ReplicaConsistency::parse("").is_err());
    }

    #[test]
    fn replica_consistency_set_statement_is_static() {
        // The wire SQL must be a fixed string per variant — no interpolation,
        // no user data ever reaches the SET statement.
        assert_eq!(
            ReplicaConsistency::Eventual.as_set_statement(),
            "SET apg_write_forward.consistency_mode = 'eventual'"
        );
        assert_eq!(
            ReplicaConsistency::Global.as_set_statement(),
            "SET apg_write_forward.consistency_mode = 'global'"
        );
        assert_eq!(
            ReplicaConsistency::Session.as_set_statement(),
            "SET apg_write_forward.consistency_mode = 'session'"
        );
    }

    #[test]
    fn connect_with_rejects_invalid_consistency_value() {
        let result = PostgresMetastore::connect_with(
            "postgres://localhost/db",
            None,
            None,
            Some("eventual'; DROP TABLE keys;--".to_string()),
        );
        let err = match result {
            Ok(_) => panic!("invalid consistency must error"),
            Err(e) => e,
        };
        let msg = format!("{err:#}");
        assert!(msg.contains("REPLICA_READ_CONSISTENCY"), "{msg}");
    }
}
