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
use std::mem::ManuallyDrop;
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
    /// Mutex/condvar pair owned by the reaper thread. The reaper sleeps on
    /// `reaper_cv.wait_timeout(reaper_lock.lock()…, interval)` so `close()`
    /// can wake it promptly via `notify_all` instead of waiting up to a full
    /// reaper interval (T10 in `docs/review-2026-05-05-findings.md`).
    reaper_lock: Mutex<()>,
    reaper_cv: Condvar,
    /// Join handle for the reaper thread, taken by `close()` so it can
    /// guarantee the thread has exited before the pool is dropped.
    reaper_handle: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// A connection checked out from the pool. Returns on drop.
///
/// The inner `Conn` is held in `ManuallyDrop` rather than `Option` so
/// `Deref`/`DerefMut` can hand out `&Conn`/`&mut Conn` without an
/// `expect()` panic that would violate the no-panic policy. The type
/// invariant — `conn` is initialized for the entire lifetime of
/// `ManagedConn` and is moved out exactly once, in `Drop::drop` — is
/// upheld because the only path that takes the value is `Drop`, which
/// runs at most once and after which safe code cannot observe the
/// value.
#[allow(missing_debug_implementations)]
pub struct ManagedConn {
    pool: Arc<ManagedPool>,
    conn: ManuallyDrop<Conn>,
    created_at: Instant,
}

impl ManagedConn {
    /// Access the underlying `mysql::Conn`.
    pub fn as_conn(&mut self) -> &mut Conn {
        &mut self.conn
    }
}

impl std::ops::Deref for ManagedConn {
    type Target = Conn;
    fn deref(&self) -> &Conn {
        &self.conn
    }
}

impl std::ops::DerefMut for ManagedConn {
    fn deref_mut(&mut self) -> &mut Conn {
        &mut self.conn
    }
}

impl Drop for ManagedConn {
    fn drop(&mut self) {
        // SAFETY: `conn` is initialized for the lifetime of `self` and
        // `Drop::drop` runs at most once. Safe code cannot observe
        // `self` after this point, so the `ManuallyDrop` is never
        // dereferenced post-take.
        let mut conn = unsafe { ManuallyDrop::take(&mut self.conn) };
        // If the pool was closed while this connection was checked out,
        // discard it instead of pushing it back into a closed pool's idle
        // list — that would leak the connection and skew open_count
        // accounting (T10 in `docs/review-2026-05-05-findings.md`).
        if self.pool.closed.load(Ordering::Relaxed) {
            drop(conn);
            self.pool.open_count.fetch_sub(1, Ordering::Relaxed);
            self.pool.return_slot();
            return;
        }

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
            reaper_lock: Mutex::new(()),
            reaper_cv: Condvar::new(),
            reaper_handle: Mutex::new(None),
        });

        // Spawn background reaper if configured
        if let Some(interval) = pool.config.reaper_interval {
            let weak = Arc::downgrade(&pool);
            // Use std::thread since the pool is sync-oriented and we don't want
            // to require a tokio runtime to be running at construction time.
            let spawn_result = std::thread::Builder::new()
                .name("mysql-pool-reaper".into())
                .spawn(move || {
                    loop {
                        let pool = match weak.upgrade() {
                            Some(p) => p,
                            None => break, // Pool dropped
                        };
                        // Acquire `reaper_lock` BEFORE checking `closed`. close()
                        // sets `closed = true` while holding `reaper_lock` and
                        // then notifies on `reaper_cv`, so this ordering means we
                        // either (a) see closed=true here and break, or (b) enter
                        // wait_timeout and the notify wakes us. Without holding
                        // the lock around the closed check, a notify between the
                        // check and the wait would be lost and we'd sleep the
                        // full interval.
                        let guard = pool.reaper_lock.lock().unwrap_or_else(|e| e.into_inner());
                        if pool.closed.load(Ordering::Relaxed) {
                            break;
                        }
                        let (_g, _to) = pool
                            .reaper_cv
                            .wait_timeout(guard, interval)
                            .unwrap_or_else(|e| e.into_inner());
                        if pool.closed.load(Ordering::Relaxed) {
                            break;
                        }
                        pool.reap_idle();
                    }
                });
            if let Ok(handle) = spawn_result {
                let mut slot = pool.reaper_handle.lock().unwrap_or_else(|e| e.into_inner());
                *slot = Some(handle);
            }
            // If thread spawn fails, the pool still works (lazy reaping only).
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
            if self.closed.load(Ordering::Relaxed) {
                anyhow::bail!("MySQL pool is closed");
            }
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
                    conn: ManuallyDrop::new(conn),
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
                            conn: ManuallyDrop::new(conn),
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

    /// Mark the pool as closed, drain idle connections, wake the reaper, and
    /// wait for the reaper thread to exit before returning.
    ///
    /// Future calls to `get_conn()` reject with "pool is closed". Any
    /// connections still checked out at close time are discarded — not
    /// returned to the idle list — when their `ManagedConn` drops, keeping
    /// `open_count` accurate.
    pub fn close(&self) {
        // Set `closed` while holding `reaper_lock` so the reaper either
        // observes `closed=true` before entering `wait_timeout` (and
        // breaks immediately) or is parked inside `wait_timeout` and
        // gets woken by the subsequent `notify_all`. Without this lock
        // ordering, a notify between the reaper's check and its wait
        // would be lost and the reaper would sleep the full interval.
        {
            let guard = self.reaper_lock.lock().unwrap_or_else(|e| e.into_inner());
            self.closed.store(true, Ordering::Relaxed);
            self.reaper_cv.notify_all();
            drop(guard);
        }
        // Wake any get_conn() callers waiting for capacity so they observe
        // the closed flag and return promptly.
        self.condvar.notify_all();
        // Drain idle connections.
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let count = inner.idle.len();
        inner.idle.clear();
        drop(inner);
        self.open_count.fetch_sub(count, Ordering::Relaxed);

        if let Some(handle) = self
            .reaper_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            // Best-effort join. A panicked reaper is logged but does not
            // propagate — close() must not panic on dirty shutdown.
            if let Err(payload) = handle.join() {
                log::warn!("mysql-pool-reaper join failed: {payload:?}");
            }
        }
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

    #[test]
    fn get_conn_after_close_rejects() {
        let pool = ManagedPool::new(dummy_opts(), test_config());
        pool.close();
        let err = pool
            .get_conn()
            .err()
            .expect("get_conn after close must error");
        assert!(format!("{err:#}").contains("closed"));
    }

    #[test]
    fn close_joins_reaper_thread_promptly() {
        let cfg = PoolConfig {
            // 60-second sleep — the test would time out if close() waited
            // for the next reaper cycle instead of waking it.
            reaper_interval: Some(Duration::from_secs(60)),
            ..test_config()
        };
        let pool = ManagedPool::new(dummy_opts(), cfg);
        let start = Instant::now();
        pool.close();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "close() should wake the reaper instead of waiting a full \
             interval — took {elapsed:?}"
        );
        // Reaper handle must have been taken (joined or absent).
        let slot = pool.reaper_handle.lock().unwrap();
        assert!(slot.is_none(), "close() should have taken the join handle");
    }
}
