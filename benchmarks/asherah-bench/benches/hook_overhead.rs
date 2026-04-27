//! Microbenchmark: confirm the metrics + log hook plumbing imposes zero
//! overhead on the encrypt/decrypt hot path when no hook is installed,
//! including on factories that have `with_metrics(true)` set (which all FFI
//! bindings now do so an installed hook fires automatically).
//!
//! Four scenarios per operation, expected ordering of latency:
//!   metrics_off  ≈  metrics_on_no_hook  <  metrics_on_hooked
//!
//! `metrics_off` is the legacy default (direct asherah crate users).
//! `metrics_on_no_hook` is what every FFI factory now looks like at idle.
//! `metrics_on_hooked` is what FFI looks like once a binding registers a
//! metrics hook — this should be the only path that pays Instant::now()
//! plus the sink dispatch.
//!
//! If `metrics_on_no_hook` matches `metrics_off` we have proven the
//! "global gate short-circuits" optimization works.

use asherah::logging::LogSink;
use asherah::{builders, logging, metrics};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;

#[cfg(target_os = "macos")]
fn pin_to_performance_cores() {
    extern "C" {
        fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    }
    unsafe {
        pthread_set_qos_class_self_np(0x21, 0);
    }
}

#[cfg(not(target_os = "macos"))]
fn pin_to_performance_cores() {}

struct CountingSink {
    count: std::sync::atomic::AtomicU64,
}

impl metrics::MetricsSink for CountingSink {
    fn encrypt(&self, _dur: std::time::Duration) {
        self.count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn decrypt(&self, _dur: std::time::Duration) {
        self.count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

fn install_counting_sink() {
    let sink = CountingSink {
        count: std::sync::atomic::AtomicU64::new(0),
    };
    metrics::set_sink(sink);
    metrics::set_enabled(true);
}

fn uninstall_sink() {
    metrics::clear_sink();
    metrics::set_enabled(false);
}

fn build_factory(metrics_enabled: bool) -> impl std::ops::Deref<Target = ()> + 'static {
    // Returning `factory` by value here would require naming the concrete
    // generic — instead we leak it for the bench's lifetime via Box::leak.
    // (Each scenario builds its own factory so they don't share state.)
    let factory = builders::factory_from_env().expect("factory");
    let factory = factory.with_metrics(metrics_enabled);
    Box::leak(Box::new(factory));
    // Trampoline return — the call sites build their own factories below.
    // This signature is only used to keep the file compiling without unused
    // warnings; the actual factory plumbing lives in each bench fn.
    Box::leak(Box::new(()))
}

fn bench_encrypt(c: &mut Criterion) {
    pin_to_performance_cores();
    let mut group = c.benchmark_group("hook_overhead_encrypt");
    let payload = vec![0_u8; 64];

    // Scenario B: metrics_enabled = true on factory, but no hook installed
    // (FIRST to rule out warmup ordering artifacts)
    {
        uninstall_sink();
        let factory = builders::factory_from_env().expect("factory_b");
        let factory = factory.with_metrics(true);
        let session = factory.get_session("hook-bench-b");
        for _ in 0..1000 {
            let _ = session.encrypt(black_box(&payload)).expect("warmup");
        }
        group.bench_function(BenchmarkId::new("metrics_on_no_hook", 64), |b| {
            b.iter(|| black_box(session.encrypt(black_box(&payload)).expect("encrypt")))
        });
        session.close().ok();
        factory.close().ok();
    }

    // Scenario A: metrics_enabled = false (legacy default)
    {
        uninstall_sink();
        let factory = builders::factory_from_env().expect("factory_a");
        let factory = factory.with_metrics(false);
        let session = factory.get_session("hook-bench-a");
        // warmup
        for _ in 0..1000 {
            let _ = session.encrypt(black_box(&payload)).expect("warmup");
        }
        group.bench_function(BenchmarkId::new("metrics_off", 64), |b| {
            b.iter(|| black_box(session.encrypt(black_box(&payload)).expect("encrypt")))
        });
        session.close().ok();
        factory.close().ok();
    }

    // Scenario C: metrics_enabled = true, hook installed
    {
        install_counting_sink();
        let factory = builders::factory_from_env().expect("factory_c");
        let factory = factory.with_metrics(true);
        let session = factory.get_session("hook-bench-c");
        for _ in 0..1000 {
            let _ = session.encrypt(black_box(&payload)).expect("warmup");
        }
        group.bench_function(BenchmarkId::new("metrics_on_hooked", 64), |b| {
            b.iter(|| black_box(session.encrypt(black_box(&payload)).expect("encrypt")))
        });
        session.close().ok();
        factory.close().ok();
        uninstall_sink();
    }

    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    pin_to_performance_cores();
    let mut group = c.benchmark_group("hook_overhead_decrypt");
    let payload = vec![0_u8; 64];

    // Pre-build a ciphertext for each scenario.
    fn one_run(
        c: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
        label: &'static str,
        metrics_enabled: bool,
        with_hook: bool,
        payload: &[u8],
    ) {
        if with_hook {
            install_counting_sink();
        } else {
            uninstall_sink();
        }
        let factory = builders::factory_from_env().expect("factory");
        let factory = factory.with_metrics(metrics_enabled);
        let session = factory.get_session(&format!("hook-bench-decrypt-{label}"));
        let drr = session.encrypt(payload).expect("setup encrypt");
        // warmup
        for _ in 0..1000 {
            let _ = session
                .decrypt(black_box(drr.clone()))
                .expect("warmup decrypt");
        }
        c.bench_function(BenchmarkId::new(label, 64), |b| {
            b.iter(|| black_box(session.decrypt(black_box(drr.clone())).expect("decrypt")))
        });
        session.close().ok();
        factory.close().ok();
        if with_hook {
            uninstall_sink();
        }
    }

    one_run(&mut group, "metrics_off", false, false, &payload);
    one_run(&mut group, "metrics_on_no_hook", true, false, &payload);
    one_run(&mut group, "metrics_on_hooked", true, true, &payload);

    group.finish();
}

// Suppress unused-fn warning from the helper that exists only to document
// the scenario shape — keep the implementation clean if a future test
// wants to reuse it.
#[allow(dead_code)]
fn _docs_only() {
    let _ = build_factory;
}

struct DiscardLogSink;
impl LogSink for DiscardLogSink {
    fn log(&self, _record: &log::Record<'_>) {}
}

fn install_log_sink() {
    logging::ensure_logger().expect("ensure_logger");
    logging::set_sink("bench", Some(Arc::new(DiscardLogSink)));
}
fn clear_log_sink() {
    logging::set_sink("bench", None);
}

fn bench_logging(c: &mut Criterion) {
    pin_to_performance_cores();
    let mut group = c.benchmark_group("hook_overhead_logging");
    let payload = vec![0_u8; 64];

    // L0: log subscriber NEVER installed (cold logger). ensure_logger
    // hasn't been called by the bench — log macros short-circuit at
    // STATIC_MAX_LEVEL / max_level() = Off (default).
    {
        clear_log_sink();
        metrics::set_enabled(false);
        let factory = builders::factory_from_env().expect("factory_l0");
        let factory = factory.with_metrics(false);
        let session = factory.get_session("hook-bench-l0");
        for _ in 0..1000 {
            let _ = session.encrypt(black_box(&payload)).expect("warmup");
        }
        group.bench_function(BenchmarkId::new("log_never_installed", 64), |b| {
            b.iter(|| black_box(session.encrypt(black_box(&payload)).expect("encrypt")))
        });
        session.close().ok();
        factory.close().ok();
    }

    // L1: log subscriber was installed, then cleared. With the fix in
    // logging::set_sink, max_level is lowered back to Off when subscribers
    // go to 0 — so this scenario should match L0. Without the fix it would
    // pay full log-macro cost for every encrypt.
    {
        install_log_sink();
        clear_log_sink();
        metrics::set_enabled(false);
        let factory = builders::factory_from_env().expect("factory_l1");
        let factory = factory.with_metrics(false);
        let session = factory.get_session("hook-bench-l1");
        for _ in 0..1000 {
            let _ = session.encrypt(black_box(&payload)).expect("warmup");
        }
        group.bench_function(BenchmarkId::new("log_installed_then_cleared", 64), |b| {
            b.iter(|| black_box(session.encrypt(black_box(&payload)).expect("encrypt")))
        });
        session.close().ok();
        factory.close().ok();
    }

    // L2: log subscriber currently installed (discards every record).
    // This pays the full log macro path on every record — measures the
    // ceiling cost when a hook is actively listening.
    {
        install_log_sink();
        metrics::set_enabled(false);
        let factory = builders::factory_from_env().expect("factory_l2");
        let factory = factory.with_metrics(false);
        let session = factory.get_session("hook-bench-l2");
        for _ in 0..1000 {
            let _ = session.encrypt(black_box(&payload)).expect("warmup");
        }
        group.bench_function(BenchmarkId::new("log_active", 64), |b| {
            b.iter(|| black_box(session.encrypt(black_box(&payload)).expect("encrypt")))
        });
        session.close().ok();
        factory.close().ok();
        clear_log_sink();
    }

    group.finish();
}

criterion_group!(benches, bench_encrypt, bench_decrypt, bench_logging);
criterion_main!(benches);
