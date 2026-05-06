use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::thread::{Builder as ThreadBuilder, JoinHandle};
use std::time::Duration;

/// Cumulative encrypt/decrypt timing counters exposed for ad-hoc
/// observability. The recording side increments `total_ns` before
/// `count` with `Release` ordering, so readers should:
///
/// ```ignore
/// use std::sync::atomic::Ordering;
/// let count = ENCRYPT_TIMER.count.load(Ordering::Acquire);
/// let total_ns = ENCRYPT_TIMER.total_ns.load(Ordering::Acquire);
/// let avg_ns = if count > 0 { total_ns / count } else { 0 };
/// ```
///
/// With this pattern the reader's `total_ns` always covers at least
/// every operation included in `count`, biasing any per-call average
/// toward overcounting (false-alarm latency) rather than
/// undercounting (silently masking a regression).
#[derive(Debug)]
pub struct Timers {
    pub count: AtomicU64,
    pub total_ns: AtomicU64,
}
impl Timers {
    pub const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
        }
    }
}

impl Default for Timers {
    fn default() -> Self {
        Self::new()
    }
}

pub static ENCRYPT_TIMER: Timers = Timers::new();
pub static DECRYPT_TIMER: Timers = Timers::new();
static ENABLED: AtomicBool = AtomicBool::new(false);

pub trait MetricsSink: Send + Sync + 'static {
    fn encrypt(&self, _dur: Duration) {}
    fn decrypt(&self, _dur: Duration) {}
    fn store(&self, _dur: Duration) {}
    fn load(&self, _dur: Duration) {}
    fn cache_hit(&self, _name: &str) {}
    fn cache_miss(&self, _name: &str) {}
    fn cache_stale(&self, _name: &str) {}
}

struct NoopSink;
impl MetricsSink for NoopSink {}

static SINK: Lazy<RwLock<Box<dyn MetricsSink>>> = Lazy::new(|| RwLock::new(Box::new(NoopSink)));

pub fn set_sink<T: MetricsSink>(sink: T) {
    // `parking_lot::RwLock` doesn't poison on panic so we don't have
    // to thread the recovery branch the way `std::sync::RwLock`
    // required. Switched from std for consistency with `logging.rs`,
    // which already used `parking_lot::RwLock`. T-finding
    // "Inconsistent std::sync::RwLock vs parking_lot::RwLock" in
    // `docs/review-2026-05-05-findings.md`.
    let old_sink = {
        let mut guard = SINK.write();
        std::mem::replace(&mut *guard, Box::new(sink))
    };
    drop(old_sink);
}

pub fn clear_sink() {
    let old_sink = {
        let mut guard = SINK.write();
        std::mem::replace(&mut *guard, Box::new(NoopSink))
    };
    drop(old_sink);
}

pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

#[inline(always)]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}
fn with_sink<R>(f: impl FnOnce(&dyn MetricsSink) -> R) -> R {
    let guard = SINK.read();
    f(&**guard)
}

#[inline(always)]
pub fn record_encrypt(start: std::time::Instant) {
    if !is_enabled() {
        return;
    }
    let d = start.elapsed();
    // Increment `total_ns` BEFORE `count` so any reader using
    // `Acquire` on `count` followed by `Acquire` on `total_ns` sees
    // a `total_ns` that includes at least every operation `count`
    // observed. A reader's average will therefore err on the high
    // side (false-alarm latency report) rather than the low side
    // (silently masking a regression). T-finding "Relaxed ordering
    // on count and total_ns allows reader to undercount average" in
    // `docs/review-2026-05-05-findings.md`.
    ENCRYPT_TIMER
        .total_ns
        .fetch_add(d.as_nanos() as u64, Ordering::Release);
    ENCRYPT_TIMER.count.fetch_add(1, Ordering::Release);
    with_sink(|sink| sink.encrypt(d));
}
#[inline(always)]
pub fn record_decrypt(start: std::time::Instant) {
    if !is_enabled() {
        return;
    }
    let d = start.elapsed();
    // Same total_ns-before-count ordering as record_encrypt.
    DECRYPT_TIMER
        .total_ns
        .fetch_add(d.as_nanos() as u64, Ordering::Release);
    DECRYPT_TIMER.count.fetch_add(1, Ordering::Release);
    with_sink(|sink| sink.decrypt(d));
}

#[inline(always)]
pub fn record_store(start: std::time::Instant) {
    if !is_enabled() {
        return;
    }
    let d = start.elapsed();
    with_sink(|sink| sink.store(d));
}
#[inline(always)]
pub fn record_load(start: std::time::Instant) {
    if !is_enabled() {
        return;
    }
    let d = start.elapsed();
    with_sink(|sink| sink.load(d));
}
#[inline(always)]
pub fn record_cache_hit(name: &str) {
    if !is_enabled() {
        return;
    }
    with_sink(|sink| sink.cache_hit(name));
}
#[inline(always)]
pub fn record_cache_miss(name: &str) {
    if !is_enabled() {
        return;
    }
    with_sink(|sink| sink.cache_miss(name));
}
#[inline(always)]
pub fn record_cache_stale(name: &str) {
    if !is_enabled() {
        return;
    }
    with_sink(|sink| sink.cache_stale(name));
}

// ─── async dispatch wrapper ──────────────────────────────────────────────
//
// `AsyncMetricsSink` mirrors `AsyncLogSink` (see `logging.rs`) — it wraps a
// synchronous metrics sink with a bounded SPSC channel + dedicated worker
// thread so that a slow user-supplied callback never holds up an encrypt.

/// Cumulative count of metrics events dropped because the async dispatcher's
/// channel was full, across the lifetime of the process.
static METRICS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Number of metrics events the async dispatcher has dropped due to channel
/// back-pressure since the process started. Cumulative across all installed
/// metrics hooks; never resets.
pub fn metrics_dropped_count() -> u64 {
    METRICS_DROPPED.load(Ordering::Relaxed)
}

/// Configuration for [`AsyncMetricsSink`].
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub struct AsyncMetricsConfig {
    /// Maximum events buffered. When the channel is full additional events
    /// are dropped (counted in [`metrics_dropped_count`]). Default: `4096`.
    pub queue_capacity: usize,
}

impl Default for AsyncMetricsConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 4096,
        }
    }
}

#[allow(missing_debug_implementations)]
enum OwnedMetricsEvent {
    Encrypt(Duration),
    Decrypt(Duration),
    Store(Duration),
    Load(Duration),
    CacheHit(String),
    CacheMiss(String),
    CacheStale(String),
}

/// Wrap a synchronous `MetricsSink` in an async dispatcher. The encrypt/
/// decrypt hot path performs only an enum construction + non-blocking
/// channel send; the user's callback runs on a dedicated worker thread.
#[allow(missing_debug_implementations)]
pub struct AsyncMetricsSink {
    sender: Option<SyncSender<OwnedMetricsEvent>>,
    worker: Option<JoinHandle<()>>,
}

impl AsyncMetricsSink {
    /// Construct an async dispatcher wrapping `inner`.
    ///
    /// Returns `Err(io::Error)` when the OS rejects the worker thread
    /// spawn (EAGAIN under thread quota, seccomp policy, etc.). The
    /// previous `expect()` aborted the host process, which is
    /// unacceptable in cdylib-loaded FFI contexts.
    pub fn new<S: MetricsSink>(inner: S, config: AsyncMetricsConfig) -> std::io::Result<Self> {
        let (sender, receiver) = sync_channel::<OwnedMetricsEvent>(config.queue_capacity);
        let worker = ThreadBuilder::new()
            .name("asherah-metrics-dispatch".into())
            .spawn(move || {
                while let Ok(event) = receiver.recv() {
                    match event {
                        OwnedMetricsEvent::Encrypt(d) => inner.encrypt(d),
                        OwnedMetricsEvent::Decrypt(d) => inner.decrypt(d),
                        OwnedMetricsEvent::Store(d) => inner.store(d),
                        OwnedMetricsEvent::Load(d) => inner.load(d),
                        OwnedMetricsEvent::CacheHit(name) => inner.cache_hit(&name),
                        OwnedMetricsEvent::CacheMiss(name) => inner.cache_miss(&name),
                        OwnedMetricsEvent::CacheStale(name) => inner.cache_stale(&name),
                    }
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
        })
    }

    fn try_send(&self, event: OwnedMetricsEvent) {
        let Some(sender) = self.sender.as_ref() else {
            METRICS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                METRICS_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Drop for AsyncMetricsSink {
    fn drop(&mut self) {
        // Drop the sender so the worker's `recv()` returns Err and
        // the loop exits cleanly. Then join the worker so a panic
        // inside the user's `MetricsSink` callback surfaces here
        // (logged) rather than silently disappearing into a detached
        // thread. T-finding "Worker JoinHandle never joined in Drop;
        // worker panics lost" in
        // `docs/review-2026-05-05-findings.md`.
        drop(self.sender.take());
        if let Some(worker) = self.worker.take() {
            if let Err(panic_payload) = worker.join() {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| panic_payload.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("(non-string panic payload)");
                log::error!("AsyncMetricsSink dispatcher worker panicked: {msg}");
            }
        }
    }
}

impl MetricsSink for AsyncMetricsSink {
    fn encrypt(&self, dur: Duration) {
        self.try_send(OwnedMetricsEvent::Encrypt(dur));
    }
    fn decrypt(&self, dur: Duration) {
        self.try_send(OwnedMetricsEvent::Decrypt(dur));
    }
    fn store(&self, dur: Duration) {
        self.try_send(OwnedMetricsEvent::Store(dur));
    }
    fn load(&self, dur: Duration) {
        self.try_send(OwnedMetricsEvent::Load(dur));
    }
    fn cache_hit(&self, name: &str) {
        self.try_send(OwnedMetricsEvent::CacheHit(name.to_string()));
    }
    fn cache_miss(&self, name: &str) {
        self.try_send(OwnedMetricsEvent::CacheMiss(name.to_string()));
    }
    fn cache_stale(&self, name: &str) {
        self.try_send(OwnedMetricsEvent::CacheStale(name.to_string()));
    }
}
