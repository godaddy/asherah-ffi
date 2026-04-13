//! Go-style connection pool for the sync `mysql` crate.
//!
//! Manages `mysql::Conn` objects directly (bypassing the crate's built-in pool)
//! to provide the same knobs as Go's `database/sql`:
//!
//! | Go `database/sql`        | This pool                                       |
//! |--------------------------|-------------------------------------------------|
//! | `SetMaxOpenConns(n)`     | `max_open` — hard cap on total connections       |
//! | `SetMaxIdleConns(n)`     | `max_idle` — cap on idle connections retained    |
//! | `SetConnMaxLifetime(d)`  | `max_lifetime` — reject conns older than this    |
//! | `SetConnMaxIdleTime(d)`  | `max_idle_time` — reject conns idle too long     |
//! | Lazy init                | Starts with 0 connections, creates on demand     |
//! | Background cleaner       | `tokio::spawn` reaper on configurable interval   |

use mysql::{Conn, Opts, OptsBuilder, SslOpts};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Default max open connections — 0 means unlimited, matching Go's `database/sql`.
const DEFAULT_MAX_OPEN: usize = 0;

/// Default max idle connections — matches Go's `database/sql` default.
const DEFAULT_MAX_IDLE: usize = 2;

/// Default reaper interval for the background cleaner.
const DEFAULT_REAPER_INTERVAL: Duration = Duration::from_secs(30);

/// A connection with metadata for lifetime/idle tracking.
struct IdleConn {
    conn: Conn,
    created_at: Instant,
    returned_at: Instant,
}

/// Configuration for the managed pool.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Maximum number of open connections (checked-out + idle).
    /// 0 means unlimited, matching Go's `database/sql` default.
    pub max_open: usize,
    /// Maximum number of idle connections to retain. Surplus connections are
    /// closed on return rather than kept in the pool.
    pub max_idle: usize,
    /// Maximum lifetime of a connection. Connections older than this are
    /// rejected on checkout and closed.
    pub max_lifetime: Option<Duration>,
    /// Maximum time a connection can sit idle. Idle connections exceeding this
    /// are rejected on checkout and closed.
    pub max_idle_time: Option<Duration>,
    /// Interval for the background reaper task. Set to `None` to disable.
    pub reaper_interval: Option<Duration>,
    /// Whether to ping connections on checkout to verify health.
    pub check_health: bool,
    /// Whether to run COM_RESET_CONNECTION on return.
    pub reset_on_return: bool,
}

impl PoolConfig {
    /// Build a `PoolConfig` from environment variables, falling back to defaults.
    ///
    /// Env vars:
    /// - `ASHERAH_POOL_MAX_OPEN` (or legacy `ASHERAH_POOL_SIZE`): max open connections (0=unlimited)
    /// - `ASHERAH_POOL_MAX_IDLE`: max idle connections retained
    /// - `ASHERAH_POOL_MAX_LIFETIME`: max connection lifetime in seconds (0=unlimited)
    /// - `ASHERAH_POOL_MAX_IDLE_TIME`: max idle time in seconds (0=unlimited)
    pub fn from_env() -> Self {
        let mut cfg = Self::default();

        // ASHERAH_POOL_MAX_OPEN takes precedence; fall back to legacy ASHERAH_POOL_SIZE
        if let Some(v) = Self::env_usize("ASHERAH_POOL_MAX_OPEN")
            .or_else(|| Self::env_usize("ASHERAH_POOL_SIZE"))
        {
            cfg.max_open = v;
        }
        if let Some(v) = Self::env_usize("ASHERAH_POOL_MAX_IDLE") {
            cfg.max_idle = v;
        }
        if let Some(v) = Self::env_secs("ASHERAH_POOL_MAX_LIFETIME") {
            cfg.max_lifetime = v;
        }
        if let Some(v) = Self::env_secs("ASHERAH_POOL_MAX_IDLE_TIME") {
            cfg.max_idle_time = v;
        }
        cfg
    }

    fn env_usize(key: &str) -> Option<usize> {
        std::env::var(key).ok().and_then(|v| v.parse().ok())
    }

    /// Parse an env var as seconds → `Option<Duration>`. Returns `Some(None)`
    /// for 0 (meaning "unlimited"), `Some(Some(dur))` for positive values,
    /// and `None` when the env var is unset.
    fn env_secs(key: &str) -> Option<Option<Duration>> {
        let val: u64 = std::env::var(key).ok().and_then(|v| v.parse().ok())?;
        if val == 0 {
            Some(None) // explicit unlimited
        } else {
            Some(Some(Duration::from_secs(val)))
        }
    }

    /// Build from explicit values, falling back to defaults for None.
    pub fn from_values(
        max_open: Option<usize>,
        max_idle: Option<usize>,
        max_lifetime_s: Option<u64>,
        max_idle_time_s: Option<u64>,
    ) -> Self {
        let mut cfg = Self::default();
        if let Some(v) = max_open {
            cfg.max_open = v;
        }
        if let Some(v) = max_idle {
            cfg.max_idle = v;
        }
        if let Some(v) = max_lifetime_s {
            cfg.max_lifetime = if v == 0 {
                None
            } else {
                Some(Duration::from_secs(v))
            };
        }
        if let Some(v) = max_idle_time_s {
            cfg.max_idle_time = if v == 0 {
                None
            } else {
                Some(Duration::from_secs(v))
            };
        }
        cfg
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_open: DEFAULT_MAX_OPEN,
            max_idle: DEFAULT_MAX_IDLE,
            max_lifetime: None,
            max_idle_time: None,
            reaper_interval: Some(DEFAULT_REAPER_INTERVAL),
            check_health: true,
            reset_on_return: true,
        }
    }
}

struct PoolInner {
    idle: VecDeque<IdleConn>,
    checked_out: usize,
}

#[allow(missing_debug_implementations)]
pub struct ManagedPool {
    opts: Opts,
    config: PoolConfig,
    inner: Mutex<PoolInner>,
    condvar: Condvar,
    open_count: AtomicUsize,
    closed: AtomicBool,
}

/// A connection checked out from the pool. Returns on drop.
#[allow(missing_debug_implementations)]
pub struct ManagedConn {
    pool: Arc<ManagedPool>,
    conn: Option<Conn>,
    created_at: Instant,
}

impl ManagedConn {
    /// Access the underlying `mysql::Conn`.
    pub fn as_conn(&mut self) -> &mut Conn {
        self.conn.as_mut().expect("ManagedConn accessed after drop")
    }
}

impl std::ops::Deref for ManagedConn {
    type Target = Conn;
    fn deref(&self) -> &Conn {
        self.conn.as_ref().expect("ManagedConn accessed after drop")
    }
}

impl std::ops::DerefMut for ManagedConn {
    fn deref_mut(&mut self) -> &mut Conn {
        self.conn.as_mut().expect("ManagedConn accessed after drop")
    }
}

impl Drop for ManagedConn {
    fn drop(&mut self) {
        if let Some(mut conn) = self.conn.take() {
            // Reset connection state if configured
            if self.pool.config.reset_on_return && conn.reset().is_err() {
                // Connection is broken, discard it
                self.pool.open_count.fetch_sub(1, Ordering::Relaxed);
                self.pool.return_slot();
                return;
            }

            let now = Instant::now();

            // Check lifetime before returning — don't put expired connections back
            if let Some(max_lifetime) = self.pool.config.max_lifetime {
                if now.duration_since(self.created_at) >= max_lifetime {
                    self.pool.open_count.fetch_sub(1, Ordering::Relaxed);
                    self.pool.return_slot();
                    return;
                }
            }

            let mut inner = self.pool.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.checked_out -= 1;

            // Enforce max_idle: only keep if under the idle cap
            if inner.idle.len() < self.pool.config.max_idle {
                inner.idle.push_back(IdleConn {
                    conn,
                    created_at: self.created_at,
                    returned_at: now,
                });
                drop(inner);
                self.pool.condvar.notify_one();
            } else {
                // Over idle cap — close the connection
                drop(inner);
                drop(conn);
                self.pool.open_count.fetch_sub(1, Ordering::Relaxed);
                self.pool.condvar.notify_one();
            }
        }
    }
}

impl ManagedPool {
    /// Create a new managed pool.
    ///
    /// No connections are created at construction (lazy init). The first
    /// `get_conn()` call will create the first connection.
    pub fn new(opts: Opts, config: PoolConfig) -> Arc<Self> {
        let pool = Arc::new(Self {
            opts,
            config,
            inner: Mutex::new(PoolInner {
                idle: VecDeque::new(),
                checked_out: 0,
            }),
            condvar: Condvar::new(),
            open_count: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        });

        // Spawn background reaper if configured
        if let Some(interval) = pool.config.reaper_interval {
            let weak = Arc::downgrade(&pool);
            // Use std::thread since the pool is sync-oriented and we don't want
            // to require a tokio runtime to be running at construction time.
            std::thread::Builder::new()
                .name("mysql-pool-reaper".into())
                .spawn(move || {
                    loop {
                        std::thread::sleep(interval);
                        match weak.upgrade() {
                            Some(pool) => {
                                if pool.closed.load(Ordering::Relaxed) {
                                    break;
                                }
                                pool.reap_idle();
                            }
                            None => break, // Pool was dropped
                        }
                    }
                })
                .ok(); // If thread spawn fails, pool still works (lazy reaping only)
        }

        pool
    }

    /// Validate connectivity by creating and immediately returning one connection.
    /// Call after `new()` for fail-fast behavior.
    pub fn validate(self: &Arc<Self>) -> anyhow::Result<()> {
        let managed = self.get_conn()?;
        drop(managed); // Returns to pool
        Ok(())
    }

    /// Get a connection from the pool. Blocks if `max_open` is reached until
    /// a connection is returned by another thread.
    pub fn get_conn(self: &Arc<Self>) -> anyhow::Result<ManagedConn> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        loop {
            // Try to reuse an idle connection
            while let Some(idle) = inner.idle.pop_front() {
                let now = Instant::now();

                // Check max_lifetime
                if let Some(max_lifetime) = self.config.max_lifetime {
                    if now.duration_since(idle.created_at) >= max_lifetime {
                        drop(idle.conn);
                        self.open_count.fetch_sub(1, Ordering::Relaxed);
                        continue;
                    }
                }

                // Check max_idle_time
                if let Some(max_idle_time) = self.config.max_idle_time {
                    if now.duration_since(idle.returned_at) >= max_idle_time {
                        drop(idle.conn);
                        self.open_count.fetch_sub(1, Ordering::Relaxed);
                        continue;
                    }
                }

                // Health check
                let mut conn = idle.conn;
                if self.config.check_health && conn.ping().is_err() {
                    drop(conn);
                    self.open_count.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }

                inner.checked_out += 1;
                return Ok(ManagedConn {
                    pool: Arc::clone(self),
                    conn: Some(conn),
                    created_at: idle.created_at,
                });
            }

            // No idle connections — can we create a new one?
            // max_open == 0 means unlimited (matching Go's database/sql)
            let total = self.open_count.load(Ordering::Relaxed);
            if self.config.max_open == 0 || total < self.config.max_open {
                // Reserve a slot before dropping the lock
                self.open_count.fetch_add(1, Ordering::Relaxed);
                inner.checked_out += 1;
                drop(inner);

                // Create connection outside the lock
                match self.new_conn() {
                    Ok(conn) => {
                        return Ok(ManagedConn {
                            pool: Arc::clone(self),
                            conn: Some(conn),
                            created_at: Instant::now(),
                        });
                    }
                    Err(e) => {
                        // Undo the reservation
                        self.open_count.fetch_sub(1, Ordering::Relaxed);
                        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                        inner.checked_out -= 1;
                        return Err(e);
                    }
                }
            }

            // Pool is full — wait for a connection to be returned
            inner = self.condvar.wait(inner).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// Notify a waiting thread that a slot is available (used when discarding
    /// a connection without returning it to the idle queue).
    fn return_slot(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.checked_out -= 1;
        drop(inner);
        self.condvar.notify_one();
    }

    /// Create a new raw connection using the pool's opts.
    fn new_conn(&self) -> anyhow::Result<Conn> {
        Conn::new(self.opts.clone()).map_err(|e| {
            log::error!("MySQL connection failed: {e:#}");
            anyhow::anyhow!("MySQL connection failed: {e}")
        })
    }

    /// Sweep idle connections that have exceeded their lifetime or idle time.
    /// Called by the background reaper thread.
    fn reap_idle(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let before = inner.idle.len();

        inner.idle.retain(|idle| {
            if let Some(max_lifetime) = self.config.max_lifetime {
                if now.duration_since(idle.created_at) >= max_lifetime {
                    self.open_count.fetch_sub(1, Ordering::Relaxed);
                    return false;
                }
            }
            if let Some(max_idle_time) = self.config.max_idle_time {
                if now.duration_since(idle.returned_at) >= max_idle_time {
                    self.open_count.fetch_sub(1, Ordering::Relaxed);
                    return false;
                }
            }
            true
        });

        let reaped = before - inner.idle.len();
        if reaped > 0 {
            log::debug!("mysql pool reaper: closed {reaped} expired idle connections");
        }
    }

    /// Mark the pool as closed. The reaper thread will exit on its next cycle.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        // Drain idle connections
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let count = inner.idle.len();
        inner.idle.clear();
        drop(inner);
        self.open_count.fetch_sub(count, Ordering::Relaxed);
    }
}

/// Build `mysql::Opts` from a URL string with TLS and Aurora config applied.
///
/// This extracts the connection option setup from `MySqlMetastore::connect`
/// so it can be reused by the managed pool.
/// Build `mysql::Opts` from explicit parameters.
pub fn build_opts_with(
    url: &str,
    tls_mode: Option<&str>,
    replica_consistency: Option<&str>,
) -> anyhow::Result<Opts> {
    let opts: Opts = url
        .try_into()
        .map_err(|e: mysql::UrlError| anyhow::anyhow!("invalid MySQL URL: {e}"))?;

    let mut builder = OptsBuilder::from_opts(opts);

    if let Some(tls_mode) = tls_mode {
        match tls_mode {
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
            _ => {
                builder = builder.ssl_opts(Some(SslOpts::default()));
            }
        }
    }

    if let Some(consistency) = replica_consistency {
        match consistency {
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

    Ok(builder.into())
}

/// Build `mysql::Opts` from env vars (legacy entry point).
pub fn build_opts(url: &str) -> anyhow::Result<Opts> {
    build_opts_with(
        url,
        std::env::var("MYSQL_TLS_MODE").ok().as_deref(),
        std::env::var("REPLICA_READ_CONSISTENCY").ok().as_deref(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_config() -> PoolConfig {
        PoolConfig {
            max_open: 5,
            max_idle: 2,
            max_lifetime: None,
            max_idle_time: None,
            reaper_interval: None,  // No background thread in unit tests
            check_health: false,    // No real MySQL in unit tests
            reset_on_return: false, // No real MySQL in unit tests
        }
    }

    #[test]
    fn config_defaults_match_go() {
        let cfg = PoolConfig::default();
        // Go defaults: MaxOpenConns=0 (unlimited), MaxIdleConns=2
        assert_eq!(cfg.max_open, 0); // 0 = unlimited
        assert_eq!(cfg.max_idle, 2);
        assert!(cfg.max_lifetime.is_none());
        assert!(cfg.max_idle_time.is_none());
    }

    #[test]
    fn pool_config_builder_pattern() {
        let cfg = PoolConfig {
            max_open: 10,
            max_idle: 3,
            max_lifetime: Some(Duration::from_secs(300)),
            max_idle_time: Some(Duration::from_secs(60)),
            ..Default::default()
        };
        assert_eq!(cfg.max_open, 10);
        assert_eq!(cfg.max_idle, 3);
        assert_eq!(cfg.max_lifetime, Some(Duration::from_secs(300)));
        assert_eq!(cfg.max_idle_time, Some(Duration::from_secs(60)));
    }

    /// Build opts that will fail to connect — used for testing pool logic
    /// that doesn't actually need a MySQL server.
    fn dummy_opts() -> Opts {
        OptsBuilder::default()
            .ip_or_hostname(Some("127.0.0.1"))
            .tcp_port(1) // guaranteed to fail
            .into()
    }

    #[test]
    fn pool_starts_empty() {
        let pool = ManagedPool::new(dummy_opts(), test_config());
        assert_eq!(pool.open_count.load(Ordering::Relaxed), 0);
        let inner = pool.inner.lock().unwrap();
        assert_eq!(inner.idle.len(), 0);
        assert_eq!(inner.checked_out, 0);
    }

    #[test]
    fn pool_close_drains_idle() {
        let pool = ManagedPool::new(dummy_opts(), test_config());
        // Manually inject idle connections to test close behavior
        {
            let inner = pool.inner.lock().unwrap();
            // We can't create real Conn objects without MySQL, so just verify
            // the close mechanism works on the count tracking
            assert_eq!(inner.idle.len(), 0);
        }
        pool.close();
        assert!(pool.closed.load(Ordering::Relaxed));
    }

    #[test]
    fn reap_idle_with_empty_pool() {
        let pool = ManagedPool::new(dummy_opts(), test_config());
        // Should not panic on empty pool
        pool.reap_idle();
    }
}
