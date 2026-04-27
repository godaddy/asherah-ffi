use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::RwLock;
use std::thread::{Builder as ThreadBuilder, JoinHandle};
use std::time::Duration;

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
    if let Ok(mut guard) = SINK.write() {
        *guard = Box::new(sink);
    }
}

pub fn clear_sink() {
    if let Ok(mut guard) = SINK.write() {
        *guard = Box::new(NoopSink);
    }
}

pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

#[inline(always)]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}
fn with_sink<R>(f: impl FnOnce(&dyn MetricsSink) -> R) -> R {
    match SINK.read() {
        Ok(guard) => f(&**guard),
        Err(_) => f(&NoopSink),
    }
}

#[inline(always)]
pub fn record_encrypt(start: std::time::Instant) {
    if !is_enabled() {
        return;
    }
    ENCRYPT_TIMER.count.fetch_add(1, Ordering::Relaxed);
    let d = start.elapsed();
    ENCRYPT_TIMER
        .total_ns
        .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
    with_sink(|sink| sink.encrypt(d));
}
#[inline(always)]
pub fn record_decrypt(start: std::time::Instant) {
    if !is_enabled() {
        return;
    }
    DECRYPT_TIMER.count.fetch_add(1, Ordering::Relaxed);
    let d = start.elapsed();
    DECRYPT_TIMER
        .total_ns
        .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
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
    sender: SyncSender<OwnedMetricsEvent>,
    _worker: JoinHandle<()>,
}

impl AsyncMetricsSink {
    /// Construct an async dispatcher wrapping `inner`.
    pub fn new<S: MetricsSink>(inner: S, config: AsyncMetricsConfig) -> Self {
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
            })
            .expect("spawn asherah-metrics-dispatch worker");
        Self {
            sender,
            _worker: worker,
        }
    }

    fn try_send(&self, event: OwnedMetricsEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                METRICS_DROPPED.fetch_add(1, Ordering::Relaxed);
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
