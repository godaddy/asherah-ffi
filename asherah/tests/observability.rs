use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asherah::logging::{ensure_logger, set_sink as set_log_sink, LogSink};
use asherah::metrics;
use asherah::metrics::MetricsSink;

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
    let sink = Arc::new(TestMetricsSink::default());
    metrics::set_sink(SharedMetricsSink(Arc::clone(&sink)));

    let start = Instant::now();
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

    let sink_for_log: Arc<dyn LogSink> = sink.clone();
    set_log_sink("observability_test", Some(sink_for_log));
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
