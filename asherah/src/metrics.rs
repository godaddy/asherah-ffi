use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

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

pub trait MetricsSink: Send + Sync + 'static {
    fn encrypt(&self, _dur: std::time::Duration) {}
    fn decrypt(&self, _dur: std::time::Duration) {}
    fn store(&self, _dur: std::time::Duration) {}
    fn load(&self, _dur: std::time::Duration) {}
    fn cache_hit(&self, _name: &str) {}
    fn cache_miss(&self, _name: &str) {}
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
fn with_sink<R>(f: impl FnOnce(&dyn MetricsSink) -> R) -> R {
    match SINK.read() {
        Ok(guard) => f(&**guard),
        Err(_) => f(&NoopSink),
    }
}

pub fn record_encrypt(start: std::time::Instant) {
    ENCRYPT_TIMER.count.fetch_add(1, Ordering::Relaxed);
    let d = start.elapsed();
    ENCRYPT_TIMER
        .total_ns
        .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
    with_sink(|sink| sink.encrypt(d));
}
pub fn record_decrypt(start: std::time::Instant) {
    DECRYPT_TIMER.count.fetch_add(1, Ordering::Relaxed);
    let d = start.elapsed();
    DECRYPT_TIMER
        .total_ns
        .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
    with_sink(|sink| sink.decrypt(d));
}

pub fn record_store(start: std::time::Instant) {
    let d = start.elapsed();
    with_sink(|sink| sink.store(d));
}
pub fn record_load(start: std::time::Instant) {
    let d = start.elapsed();
    with_sink(|sink| sink.load(d));
}
pub fn record_cache_hit(name: &str) {
    with_sink(|sink| sink.cache_hit(name));
}
pub fn record_cache_miss(name: &str) {
    with_sink(|sink| sink.cache_miss(name));
}
