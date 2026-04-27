//! Tests for `AsyncLogSink` and `AsyncMetricsSink` — the wrappers that
//! decouple the encrypt/decrypt hot path from a slow user-supplied hook
//! callback.

use asherah::logging::{self, AsyncLogConfig, AsyncLogSink, LogSink};
use asherah::metrics::{self, AsyncMetricsConfig, AsyncMetricsSink, MetricsSink};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Tests in this file install global hooks via `logging::set_sink` /
// `metrics::set_sink`. To prevent parallel test runs from racing on those
// globals, every test takes this lock first.
static SERIAL: once_cell::sync::Lazy<Mutex<()>> = once_cell::sync::Lazy::new(|| Mutex::new(()));

const TEST_TARGET: &str = "asherah_async_hook_dispatch_test";

#[derive(Default)]
struct CountingLogSink {
    count: AtomicU64,
}

impl LogSink for CountingLogSink {
    fn log(&self, record: &log::Record<'_>) {
        // Other tests in the workspace can fire records while we hold the
        // serial lock (e.g., the encrypt/decrypt path itself logs from
        // background threads). Only count records emitted by THIS test.
        if record.target() == TEST_TARGET {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct SharedLogSink(Arc<CountingLogSink>);

impl LogSink for SharedLogSink {
    fn log(&self, record: &log::Record<'_>) {
        self.0.log(record);
    }
}

#[test]
fn async_log_sink_delivers_events_off_thread() {
    let _guard = SERIAL.lock().expect("serial lock");
    logging::ensure_logger().expect("ensure_logger");
    let inner = Arc::new(CountingLogSink::default());
    let sink = AsyncLogSink::new(SharedLogSink(Arc::clone(&inner)), AsyncLogConfig::default());
    logging::set_sink("async-test", Some(Arc::new(sink)));

    // `warn!` (not `info!`) because the default `AsyncLogConfig` filters
    // anything below Warn at the producer thread.
    for _ in 0..200 {
        log::warn!(target: TEST_TARGET, "hello");
    }

    // Worker drains asynchronously — wait briefly for delivery.
    let deadline = Instant::now() + Duration::from_secs(2);
    while inner.count.load(Ordering::Relaxed) < 200 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }

    logging::set_sink("async-test", None);
    assert_eq!(inner.count.load(Ordering::Relaxed), 200);
}

#[test]
fn async_log_sink_min_level_filter_drops_below_threshold() {
    let _guard = SERIAL.lock().expect("serial lock");
    logging::ensure_logger().expect("ensure_logger");
    let inner = Arc::new(CountingLogSink::default());
    let sink = AsyncLogSink::new(
        SharedLogSink(Arc::clone(&inner)),
        AsyncLogConfig {
            queue_capacity: 4096,
            min_level: log::LevelFilter::Warn,
        },
    );
    logging::set_sink("async-filter-test", Some(Arc::new(sink)));

    for _ in 0..50 {
        log::trace!(target: TEST_TARGET, "trace");
        log::debug!(target: TEST_TARGET, "debug");
        log::info!(target: TEST_TARGET, "info");
        log::warn!(target: TEST_TARGET, "warn");
        log::error!(target: TEST_TARGET, "error");
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while inner.count.load(Ordering::Relaxed) < 100 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    // 50 warn + 50 error = 100 delivered. trace/debug/info filtered.
    assert_eq!(inner.count.load(Ordering::Relaxed), 100);

    logging::set_sink("async-filter-test", None);
}

struct BlockingLogSink {
    delay: Duration,
    delivered: Arc<AtomicU64>,
}

impl LogSink for BlockingLogSink {
    fn log(&self, _record: &log::Record<'_>) {
        std::thread::sleep(self.delay);
        self.delivered.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn async_log_sink_drops_when_queue_overflows() {
    let _guard = SERIAL.lock().expect("serial lock");
    logging::ensure_logger().expect("ensure_logger");
    let baseline = logging::log_dropped_count();
    let delivered = Arc::new(AtomicU64::new(0));

    // Tiny queue + slow consumer so we can observe drops deterministically.
    let sink = AsyncLogSink::new(
        BlockingLogSink {
            delay: Duration::from_millis(50),
            delivered: Arc::clone(&delivered),
        },
        AsyncLogConfig {
            queue_capacity: 4,
            min_level: log::LevelFilter::Trace,
        },
    );
    logging::set_sink("async-overflow-test", Some(Arc::new(sink)));

    // Push way more than the queue can hold while the consumer is sleeping.
    for _ in 0..200 {
        log::info!(target: TEST_TARGET, "fill");
    }

    // Give the worker a moment to start processing; drops should already
    // have accumulated by the time we check.
    std::thread::sleep(Duration::from_millis(20));
    let dropped = logging::log_dropped_count() - baseline;
    assert!(
        dropped > 0,
        "expected drops to accumulate, got {dropped} (delivered so far: {})",
        delivered.load(Ordering::Relaxed)
    );

    logging::set_sink("async-overflow-test", None);
}

// ────────────────────────── metrics ──────────────────────────

#[derive(Default)]
struct CountingMetricsSink {
    encrypts: AtomicU64,
    decrypts: AtomicU64,
}

impl CountingMetricsSink {
    fn shared(self: Arc<Self>) -> SharedMetricsSink {
        SharedMetricsSink(self)
    }
}

struct SharedMetricsSink(Arc<CountingMetricsSink>);

impl MetricsSink for SharedMetricsSink {
    fn encrypt(&self, _dur: Duration) {
        self.0.encrypts.fetch_add(1, Ordering::Relaxed);
    }
    fn decrypt(&self, _dur: Duration) {
        self.0.decrypts.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn async_metrics_sink_delivers_events_off_thread() {
    let inner = Arc::new(CountingMetricsSink::default());
    let async_sink =
        AsyncMetricsSink::new(Arc::clone(&inner).shared(), AsyncMetricsConfig::default());

    for _ in 0..500 {
        async_sink.encrypt(Duration::from_nanos(100));
    }
    for _ in 0..300 {
        async_sink.decrypt(Duration::from_nanos(200));
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while inner.encrypts.load(Ordering::Relaxed) < 500
        && inner.decrypts.load(Ordering::Relaxed) < 300
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(inner.encrypts.load(Ordering::Relaxed), 500);
    assert_eq!(inner.decrypts.load(Ordering::Relaxed), 300);
}

struct BlockingMetricsSink {
    delay: Duration,
}

impl MetricsSink for BlockingMetricsSink {
    fn encrypt(&self, _dur: Duration) {
        std::thread::sleep(self.delay);
    }
    fn decrypt(&self, _dur: Duration) {
        std::thread::sleep(self.delay);
    }
}

#[test]
fn async_metrics_sink_drops_when_queue_overflows() {
    let baseline = metrics::metrics_dropped_count();
    let async_sink = AsyncMetricsSink::new(
        BlockingMetricsSink {
            delay: Duration::from_millis(50),
        },
        AsyncMetricsConfig { queue_capacity: 4 },
    );

    for _ in 0..200 {
        async_sink.encrypt(Duration::from_nanos(1));
    }

    std::thread::sleep(Duration::from_millis(20));
    let dropped = metrics::metrics_dropped_count() - baseline;
    assert!(dropped > 0, "expected drops, got {dropped}");
}
