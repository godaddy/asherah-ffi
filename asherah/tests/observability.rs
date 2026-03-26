use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asherah::logging::{ensure_logger, set_sink as set_log_sink, LogSink};
use asherah::metrics;
use asherah::metrics::MetricsSink;

/// Metrics use process-global state (single SINK, single ENABLED flag, static
/// timers).  Tests that swap the sink or toggle `set_enabled` must not run
/// concurrently with each other.  We use a plain `Mutex` to serialize them.
static METRICS_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct TestMetricsSink {
    events: Mutex<Vec<MetricsEventRecord>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MetricsEventRecord {
    Timed {
        kind: &'static str,
        duration: Duration,
    },
    Named {
        kind: &'static str,
        name: String,
    },
}

impl MetricsEventRecord {
    fn kind(&self) -> &'static str {
        match self {
            MetricsEventRecord::Timed { kind, .. } | MetricsEventRecord::Named { kind, .. } => kind,
        }
    }
}

impl TestMetricsSink {
    fn push(&self, record: MetricsEventRecord) {
        if let Ok(mut guard) = self.events.lock() {
            guard.push(record);
        }
    }
}

#[derive(Clone)]
struct SharedMetricsSink(Arc<TestMetricsSink>);

impl MetricsSink for SharedMetricsSink {
    fn encrypt(&self, duration: Duration) {
        self.0.push(MetricsEventRecord::Timed {
            kind: "encrypt",
            duration,
        });
    }

    fn decrypt(&self, duration: Duration) {
        self.0.push(MetricsEventRecord::Timed {
            kind: "decrypt",
            duration,
        });
    }

    fn store(&self, duration: Duration) {
        self.0.push(MetricsEventRecord::Timed {
            kind: "store",
            duration,
        });
    }

    fn load(&self, duration: Duration) {
        self.0.push(MetricsEventRecord::Timed {
            kind: "load",
            duration,
        });
    }

    fn cache_hit(&self, name: &str) {
        self.0.push(MetricsEventRecord::Named {
            kind: "cache_hit",
            name: name.to_string(),
        });
    }

    fn cache_miss(&self, name: &str) {
        self.0.push(MetricsEventRecord::Named {
            kind: "cache_miss",
            name: name.to_string(),
        });
    }
}

#[test]
fn metrics_sink_receives_events() {
    let _guard = METRICS_LOCK.lock().expect("metrics lock");

    let sink = Arc::new(TestMetricsSink::default());
    metrics::set_enabled(true);
    metrics::set_sink(SharedMetricsSink(Arc::clone(&sink)));

    // Use a start time in the past to guarantee non-zero duration
    let start = Instant::now() - Duration::from_micros(1);
    metrics::record_encrypt(start);
    metrics::record_cache_hit("factory");
    metrics::clear_sink();

    let events = sink
        .events
        .lock()
        .expect("metrics sink lock should succeed")
        .clone();
    assert!(
        events.iter().any(|event| matches!(
            event,
            MetricsEventRecord::Timed { kind, duration }
                if *kind == "encrypt" && duration.as_nanos() > 0
        )),
        "expected encrypt timing event, got {events:?}"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            MetricsEventRecord::Named { kind, name }
                if *kind == "cache_hit" && name == "factory"
        )),
        "expected cache_hit event, got {events:?}"
    );
}

#[derive(Default)]
struct TestLogSink {
    events: Mutex<Vec<(log::Level, String, String)>>,
}

impl LogSink for TestLogSink {
    fn log(&self, record: &log::Record<'_>) {
        if let Ok(mut guard) = self.events.lock() {
            guard.push((
                record.level(),
                record.args().to_string(),
                record.target().to_string(),
            ));
        }
    }
}

#[test]
fn log_sink_receives_events() {
    ensure_logger().expect("logger should initialize");
    let sink = Arc::new(TestLogSink::default());

    set_log_sink("observability_test", Some(sink.clone()));
    log::info!(target: "observability::test", "hook triggered");
    set_log_sink("observability_test", None);

    let events = sink
        .events
        .lock()
        .expect("log sink lock should succeed")
        .clone();
    assert!(
        events.iter().any(|(level, message, target)| {
            *level == log::Level::Info
                && message == "hook triggered"
                && target == "observability::test"
        }),
        "expected info log event, got {events:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 1: metrics_disabled_does_not_call_sink
// ---------------------------------------------------------------------------
#[test]
fn metrics_disabled_does_not_call_sink() {
    let _guard = METRICS_LOCK.lock().expect("metrics lock");

    metrics::set_enabled(false);
    let sink = Arc::new(TestMetricsSink::default());
    metrics::set_sink(SharedMetricsSink(Arc::clone(&sink)));

    let start = Instant::now();
    metrics::record_encrypt(start);

    let count = sink.events.lock().expect("lock should succeed").len();
    assert_eq!(count, 0, "sink should receive 0 events when disabled");

    // Restore global state.
    metrics::clear_sink();
    metrics::set_enabled(false); // default is disabled
}

// ---------------------------------------------------------------------------
// Test 2: metrics_all_event_types_received
// ---------------------------------------------------------------------------
#[test]
fn metrics_all_event_types_received() {
    let _guard = METRICS_LOCK.lock().expect("metrics lock");

    let sink = Arc::new(TestMetricsSink::default());
    metrics::set_enabled(true);
    metrics::set_sink(SharedMetricsSink(Arc::clone(&sink)));

    let start = Instant::now();
    metrics::record_encrypt(start);
    metrics::record_decrypt(start);
    metrics::record_store(start);
    metrics::record_load(start);
    metrics::record_cache_hit("ik");
    metrics::record_cache_miss("sk");

    metrics::clear_sink();

    let events = sink.events.lock().expect("lock should succeed").clone();

    let has = |kind_val: &str| events.iter().any(|e| e.kind() == kind_val);

    assert!(has("encrypt"), "missing encrypt event, got {events:?}");
    assert!(has("decrypt"), "missing decrypt event, got {events:?}");
    assert!(has("store"), "missing store event, got {events:?}");
    assert!(has("load"), "missing load event, got {events:?}");
    assert!(has("cache_hit"), "missing cache_hit event, got {events:?}");
    assert!(
        has("cache_miss"),
        "missing cache_miss event, got {events:?}"
    );
    assert_eq!(events.len(), 6, "expected exactly 6 events, got {events:?}");
}

// ---------------------------------------------------------------------------
// Test 3: metrics_clear_sink_stops_events
// ---------------------------------------------------------------------------
#[test]
fn metrics_clear_sink_stops_events() {
    let _guard = METRICS_LOCK.lock().expect("metrics lock");

    let sink = Arc::new(TestMetricsSink::default());
    metrics::set_enabled(true);
    metrics::set_sink(SharedMetricsSink(Arc::clone(&sink)));

    let start = Instant::now();
    metrics::record_encrypt(start);

    let count_before = sink.events.lock().expect("lock should succeed").len();
    assert!(
        count_before > 0,
        "should have at least one event before clear"
    );

    metrics::clear_sink();

    // Record another event after clearing -- original sink should NOT receive it.
    metrics::record_encrypt(Instant::now());

    let count_after = sink.events.lock().expect("lock should succeed").len();
    assert_eq!(
        count_before, count_after,
        "original sink should not receive events after clear_sink"
    );
}

// ---------------------------------------------------------------------------
// Test 4: metrics_encrypt_timer_accumulates
// ---------------------------------------------------------------------------
#[test]
fn metrics_encrypt_timer_accumulates() {
    let _guard = METRICS_LOCK.lock().expect("metrics lock");

    metrics::set_enabled(true);
    metrics::clear_sink();
    let before = metrics::ENCRYPT_TIMER.count.load(Ordering::Relaxed);

    for _ in 0..5 {
        metrics::record_encrypt(Instant::now());
    }

    let after = metrics::ENCRYPT_TIMER.count.load(Ordering::Relaxed);
    assert_eq!(
        after - before,
        5,
        "ENCRYPT_TIMER.count should increase by 5, was {before} -> {after}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: log_multiple_subscribers
// ---------------------------------------------------------------------------
#[test]
fn log_multiple_subscribers() {
    ensure_logger().expect("logger should initialize");

    let sink1 = Arc::new(TestLogSink::default());
    let sink2 = Arc::new(TestLogSink::default());

    set_log_sink("sub1", Some(sink1.clone()));
    set_log_sink("sub2", Some(sink2.clone()));

    log::info!(target: "observability::multi", "msg_both");

    let count1 = sink1
        .events
        .lock()
        .expect("lock")
        .iter()
        .filter(|(_, m, _)| m == "msg_both")
        .count();
    let count2 = sink2
        .events
        .lock()
        .expect("lock")
        .iter()
        .filter(|(_, m, _)| m == "msg_both")
        .count();
    assert_eq!(count1, 1, "sub1 should have received msg_both");
    assert_eq!(count2, 1, "sub2 should have received msg_both");

    // Remove sub1, log another message.
    set_log_sink("sub1", None);
    log::info!(target: "observability::multi", "msg_only_sub2");

    let count1_after = sink1
        .events
        .lock()
        .expect("lock")
        .iter()
        .filter(|(_, m, _)| m == "msg_only_sub2")
        .count();
    let count2_after = sink2
        .events
        .lock()
        .expect("lock")
        .iter()
        .filter(|(_, m, _)| m == "msg_only_sub2")
        .count();
    assert_eq!(count1_after, 0, "sub1 should NOT receive msg_only_sub2");
    assert_eq!(count2_after, 1, "sub2 should receive msg_only_sub2");

    // Cleanup.
    set_log_sink("sub2", None);
}

// ---------------------------------------------------------------------------
// Test 6: log_different_levels
// ---------------------------------------------------------------------------
#[test]
fn log_different_levels() {
    ensure_logger().expect("logger should initialize");

    let sink = Arc::new(TestLogSink::default());
    set_log_sink("level_test", Some(sink.clone()));

    log::trace!(target: "observability::levels", "trace_msg");
    log::debug!(target: "observability::levels", "debug_msg");
    log::info!(target: "observability::levels", "info_msg");
    log::warn!(target: "observability::levels", "warn_msg");
    log::error!(target: "observability::levels", "error_msg");

    set_log_sink("level_test", None);

    let events = sink.events.lock().expect("lock").clone();

    let has_level =
        |lvl: log::Level, msg: &str| events.iter().any(|(l, m, _)| *l == lvl && m == msg);

    assert!(has_level(log::Level::Trace, "trace_msg"), "missing trace");
    assert!(has_level(log::Level::Debug, "debug_msg"), "missing debug");
    assert!(has_level(log::Level::Info, "info_msg"), "missing info");
    assert!(has_level(log::Level::Warn, "warn_msg"), "missing warn");
    assert!(has_level(log::Level::Error, "error_msg"), "missing error");
    assert_eq!(
        events
            .iter()
            .filter(|(_, _, t)| t == "observability::levels")
            .count(),
        5,
        "expected exactly 5 log events at observability::levels target"
    );
}

// ---------------------------------------------------------------------------
// Helper: build a minimal in-process session factory for integration tests
// ---------------------------------------------------------------------------
fn make_test_factory() -> asherah::SessionFactory<
    asherah::aead::AES256GCM,
    asherah::kms::StaticKMS<asherah::aead::AES256GCM>,
    asherah::metastore::InMemoryMetastore,
> {
    let crypto = Arc::new(asherah::aead::AES256GCM::new());
    let master_key = vec![0xAB_u8; 32];
    let kms = Arc::new(
        asherah::kms::StaticKMS::new(crypto.clone(), master_key)
            .expect("static kms creation should succeed"),
    );
    let metastore = Arc::new(asherah::metastore::InMemoryMetastore::new());
    let cfg = asherah::Config::new("obs_test_svc", "obs_test_prod");
    asherah::api::new_session_factory(cfg, metastore, kms, crypto).with_metrics(true)
}

// ---------------------------------------------------------------------------
// Test 7: metrics_sink_receives_decrypt_event
// ---------------------------------------------------------------------------
#[test]
fn metrics_sink_receives_decrypt_event() {
    let _guard = METRICS_LOCK.lock().expect("metrics lock");

    let sink = Arc::new(TestMetricsSink::default());
    metrics::set_enabled(true);
    metrics::set_sink(SharedMetricsSink(Arc::clone(&sink)));

    let factory = make_test_factory();
    let session = factory.get_session("partition_decrypt_test");

    let plaintext = b"hello observability";
    let drr = session.encrypt(plaintext).expect("encrypt should succeed");
    let decrypted = session.decrypt(drr).expect("decrypt should succeed");
    assert_eq!(decrypted, plaintext);

    metrics::clear_sink();

    let events = sink.events.lock().expect("lock").clone();

    let has_kind = |kind_val: &str| events.iter().any(|e| e.kind() == kind_val);

    assert!(
        has_kind("encrypt"),
        "expected encrypt event from session, got {events:?}"
    );
    assert!(
        has_kind("decrypt"),
        "expected decrypt event from session, got {events:?}"
    );
}

// ---------------------------------------------------------------------------
// Test 8: metrics_sink_receives_cache_events
// ---------------------------------------------------------------------------
#[test]
fn metrics_sink_receives_cache_events() {
    let _guard = METRICS_LOCK.lock().expect("metrics lock");

    let sink = Arc::new(TestMetricsSink::default());
    metrics::set_enabled(true);
    metrics::set_sink(SharedMetricsSink(Arc::clone(&sink)));

    // Default policy has cache_system_keys and cache_intermediate_keys enabled.
    let factory = make_test_factory();
    let session = factory.get_session("partition_cache_test");

    // First encrypt populates the cache (should see cache_miss).
    let drr1 = session.encrypt(b"first").expect("encrypt 1 should succeed");

    // Second encrypt should hit the IK cache (should see cache_hit).
    let _drr2 = session
        .encrypt(b"second")
        .expect("encrypt 2 should succeed");

    // Decrypt uses a meta-based cache lookup.
    let _pt = session.decrypt(drr1).expect("decrypt should succeed");

    metrics::clear_sink();

    let events = sink.events.lock().expect("lock").clone();

    let has_kind = |kind_val: &str| events.iter().any(|e| e.kind() == kind_val);

    assert!(
        has_kind("cache_hit"),
        "expected cache_hit event from caching layer, got {events:?}"
    );
    assert!(
        has_kind("cache_miss"),
        "expected cache_miss event from caching layer, got {events:?}"
    );
}
