use once_cell::sync::OnceCell;
use std::sync::atomic::{AtomicU64, Ordering};

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

static SINK: OnceCell<Box<dyn MetricsSink>> = OnceCell::new();

pub fn set_sink<T: MetricsSink>(sink: T) {
    let _set_result = SINK.set(Box::new(sink));
}
fn sink() -> &'static dyn MetricsSink {
    SINK.get().map(|b| &**b).unwrap_or(&NoopSink)
}

pub fn record_encrypt(start: std::time::Instant) {
    ENCRYPT_TIMER.count.fetch_add(1, Ordering::Relaxed);
    let d = start.elapsed();
    ENCRYPT_TIMER
        .total_ns
        .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
    sink().encrypt(d);
}
pub fn record_decrypt(start: std::time::Instant) {
    DECRYPT_TIMER.count.fetch_add(1, Ordering::Relaxed);
    let d = start.elapsed();
    DECRYPT_TIMER
        .total_ns
        .fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
    sink().decrypt(d);
}

pub fn record_store(start: std::time::Instant) {
    sink().store(start.elapsed());
}
pub fn record_load(start: std::time::Instant) {
    sink().load(start.elapsed());
}
pub fn record_cache_hit(name: &str) {
    sink().cache_hit(name);
}
pub fn record_cache_miss(name: &str) {
    sink().cache_miss(name);
}
