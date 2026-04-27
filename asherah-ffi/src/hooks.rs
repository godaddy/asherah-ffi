//! C ABI for log and metrics observability hooks.
//!
//! All language bindings that go through this C ABI (.NET, Java, Ruby, Go)
//! use these entry points to install callbacks that fire on log events and
//! metrics events. The contract is identical across bindings; only the
//! callback marshalling on the binding side differs (delegate, functional
//! interface, Proc, func).
//!
//! ## Threading
//!
//! Callbacks may fire from any thread — including Rust tokio worker threads
//! and database driver threads. Bindings must not assume single-thread
//! affinity. The callback function pointer and `user_data` are read under a
//! short lock; the actual invocation runs without holding the lock so a
//! slow callback does not block other threads.
//!
//! ## Panic safety
//!
//! Bindings MUST catch their own language-level exceptions inside the
//! callback before returning across the FFI boundary. Throwing a foreign
//! exception across an `extern "C"` boundary is undefined behavior;
//! since Rust 1.81 it aborts the process.
//!
//! On the Rust side, `catch_unwind` wraps the marshalling code (CString
//! conversions, function-pointer reinterpret) so that a Rust-side panic
//! in those steps is contained — but it cannot catch a C-side panic from
//! the foreign callback itself, because that panic aborts before
//! returning to the Rust caller.
//!
//! ## Strings
//!
//! All `*const c_char` arguments are NUL-terminated UTF-8 and are valid
//! ONLY for the duration of the callback. Bindings must copy the bytes if
//! they need to retain them.

use std::os::raw::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use asherah::logging::{self, AsyncLogConfig, AsyncLogSink, LogSink};
use asherah::metrics::{self, AsyncMetricsConfig, AsyncMetricsSink, MetricsSink};

// ─── Log hook ─────────────────────────────────────────────────────────────

/// Log severity, matching the `log` crate's levels.
pub const ASHERAH_LOG_TRACE: i32 = 0;
pub const ASHERAH_LOG_DEBUG: i32 = 1;
pub const ASHERAH_LOG_INFO: i32 = 2;
pub const ASHERAH_LOG_WARN: i32 = 3;
pub const ASHERAH_LOG_ERROR: i32 = 4;
/// Filter sentinel: drop every record. Useful when a binding's standard
/// log-level enum has values higher than Error (e.g. Microsoft.Extensions.
/// Logging.LogLevel.Critical/None) and the caller wants those to translate
/// to "deliver nothing" rather than "deliver everything (the unknown-value
/// fallback)". Only meaningful as a `min_level` argument to `_with_config`/
/// `_sync`; never appears in a delivered LogEvent.
pub const ASHERAH_LOG_OFF: i32 = 5;

/// Log callback signature. Strings are NUL-terminated UTF-8 valid for the
/// callback's lifetime only.
pub type AsherahLogCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    level: i32,
    target: *const c_char,
    message: *const c_char,
);

// Function pointers and *mut c_void are not Send/Sync by default. We store
// them as `usize` (which is) and reinterpret on call. This is safe because
// the binding side guarantees the callback and user_data remain valid until
// `asherah_clear_log_hook` returns or another `asherah_set_log_hook` call
// replaces them.
struct LogHookRegistration {
    callback: usize,  // AsherahLogCallback as usize
    user_data: usize, // *mut c_void as usize
}

static LOG_HOOK: Mutex<Option<LogHookRegistration>> = Mutex::new(None);

struct CallbackLogSink;

impl LogSink for CallbackLogSink {
    fn log(&self, record: &log::Record<'_>) {
        let registration = match LOG_HOOK.lock().as_ref() {
            Some(r) => LogHookRegistration {
                callback: r.callback,
                user_data: r.user_data,
            },
            None => return,
        };

        let level: i32 = match record.level() {
            log::Level::Error => ASHERAH_LOG_ERROR,
            log::Level::Warn => ASHERAH_LOG_WARN,
            log::Level::Info => ASHERAH_LOG_INFO,
            log::Level::Debug => ASHERAH_LOG_DEBUG,
            log::Level::Trace => ASHERAH_LOG_TRACE,
        };

        // Build NUL-terminated copies for the callback. Errors here are
        // swallowed because there is nothing actionable for the caller.
        let target = match std::ffi::CString::new(record.target()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let message = match std::ffi::CString::new(format!("{}", record.args())) {
            Ok(s) => s,
            Err(_) => return,
        };

        // Reinterpret the function pointer and user_data, invoke under
        // catch_unwind so a foreign panic cannot unwind into Rust.
        drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || {
                let cb: AsherahLogCallback = unsafe { std::mem::transmute(registration.callback) };
                unsafe {
                    cb(
                        registration.user_data as *mut c_void,
                        level,
                        target.as_ptr(),
                        message.as_ptr(),
                    );
                }
            },
        )));
    }
}

// Default queue size for the async dispatcher. Sized to absorb a few
// thousand encrypts worth of records on a hot path before the queue starts
// dropping. Override per-hook via `asherah_set_log_hook_with_config`.
const DEFAULT_LOG_QUEUE_CAPACITY: usize = 4096;
// Default min level — Warn and above. Trace/Debug/Info are dropped at the
// producer thread so they never reach the queue. Callers who want the
// verbose records pass `ASHERAH_LOG_TRACE` (or any other level constant)
// to `_with_config` / `_sync` explicitly.
const DEFAULT_LOG_MIN_LEVEL: i32 = ASHERAH_LOG_WARN;

// Synchronous variant of `CallbackLogSink` that applies a per-hook level
// filter. Async mode does the filter inside `AsyncLogSink::log` to avoid
// even materialising the record; sync mode does it here so the user's
// callback only sees records at or above their configured threshold.
struct SyncFilteredLogSink {
    min_level: log::LevelFilter,
}

impl LogSink for SyncFilteredLogSink {
    fn log(&self, record: &log::Record<'_>) {
        if record.level() > self.min_level {
            return;
        }
        CallbackLogSink.log(record);
    }
}

fn map_log_level(value: i32) -> log::LevelFilter {
    // Anything outside the documented range is treated as "deliver everything"
    // (the caller likely passed 0 / -1 / a sentinel value, and over-delivering
    // is preferable to silently dropping). `ASHERAH_LOG_OFF` is the explicit
    // "deliver nothing" sentinel.
    match value {
        ASHERAH_LOG_DEBUG => log::LevelFilter::Debug,
        ASHERAH_LOG_INFO => log::LevelFilter::Info,
        ASHERAH_LOG_WARN => log::LevelFilter::Warn,
        ASHERAH_LOG_ERROR => log::LevelFilter::Error,
        ASHERAH_LOG_OFF => log::LevelFilter::Off,
        _ => log::LevelFilter::Trace,
    }
}

fn install_log_hook_with_config(
    cb: AsherahLogCallback,
    user_data: *mut c_void,
    queue_capacity: usize,
    min_level: i32,
) {
    let _ = logging::ensure_logger();
    *LOG_HOOK.lock() = Some(LogHookRegistration {
        callback: cb as usize,
        user_data: user_data as usize,
    });
    let inner = CallbackLogSink;
    let async_sink = AsyncLogSink::new(
        inner,
        AsyncLogConfig {
            queue_capacity: if queue_capacity == 0 {
                DEFAULT_LOG_QUEUE_CAPACITY
            } else {
                queue_capacity
            },
            min_level: map_log_level(min_level),
        },
    );
    logging::set_sink("asherah-ffi-log", Some(Arc::new(async_sink)));
}

/// Register a callback that receives every log event. Replaces any
/// previously registered hook.
///
/// Pass a non-null `callback`. `user_data` is opaque and passed back
/// unchanged on every invocation; it may be NULL.
///
/// Returns 0 on success, -1 if `callback` is NULL.
///
/// # Default level filter
/// Only `Warn` and `Error` records are delivered by default. Verbose
/// `Trace`/`Debug`/`Info` records are dropped at the producer thread —
/// they never reach the queue and never invoke the callback. Use
/// [`asherah_set_log_hook_with_config`] with `ASHERAH_LOG_TRACE` (or any
/// other level constant) to widen the filter.
///
/// # Async dispatch
/// The callback is **not** invoked on the encrypt/decrypt thread. Records
/// are pushed to a bounded MPSC channel (default capacity 4096) and a
/// dedicated worker thread invokes the callback. If the queue is full,
/// records are dropped — see [`asherah_log_dropped_count`]. To override the
/// queue size or filter by level, use [`asherah_set_log_hook_with_config`].
///
/// # Safety
/// `callback` must remain a valid function pointer until cleared or
/// replaced. `user_data` must remain valid for the same duration. Strings
/// passed to the callback are valid only for the duration of the callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_set_log_hook(
    callback: Option<AsherahLogCallback>,
    user_data: *mut c_void,
) -> c_int {
    let cb = match callback {
        Some(c) => c,
        None => return -1,
    };
    install_log_hook_with_config(
        cb,
        user_data,
        DEFAULT_LOG_QUEUE_CAPACITY,
        DEFAULT_LOG_MIN_LEVEL,
    );
    0
}

/// Configurable variant of [`asherah_set_log_hook`].
///
/// - `queue_capacity`: max events buffered. `0` = use default (4096).
///   When the queue is full, records are dropped and counted in
///   [`asherah_log_dropped_count`].
/// - `min_level`: only records at this severity or higher are delivered.
///   Use `ASHERAH_LOG_TRACE` to deliver everything (default), or e.g.
///   `ASHERAH_LOG_WARN` to skip trace/debug/info entirely. Values outside
///   the documented range are treated as `ASHERAH_LOG_TRACE`.
///
/// # Safety
/// Same lifetime requirements as [`asherah_set_log_hook`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_set_log_hook_with_config(
    callback: Option<AsherahLogCallback>,
    user_data: *mut c_void,
    queue_capacity: usize,
    min_level: i32,
) -> c_int {
    let cb = match callback {
        Some(c) => c,
        None => return -1,
    };
    install_log_hook_with_config(cb, user_data, queue_capacity, min_level);
    0
}

/// Synchronous variant of [`asherah_set_log_hook`].
///
/// The callback is invoked **on the encrypt/decrypt thread, before the
/// operation continues**. There is no queue, no worker thread, no drop
/// counter. This is the right choice when:
///
/// - You're diagnosing a problem and want the callback to fire before any
///   subsequent panic/crash so the message is observable.
/// - You're correlating log records to in-progress operations and need
///   thread-local context (trace IDs, request scopes) to be intact.
/// - Your handler is verifiably non-blocking and you'd rather not pay the
///   try_send cost.
///
/// Trade-off: a slow callback **directly extends encrypt/decrypt latency**.
/// Use `asherah_set_log_hook` (or `_with_config`) for the async-by-default
/// behaviour that protects the hot path from a misbehaving handler.
///
/// `min_level` filters the same way as in `_with_config`.
///
/// # Safety
/// Same lifetime requirements as [`asherah_set_log_hook`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_set_log_hook_sync(
    callback: Option<AsherahLogCallback>,
    user_data: *mut c_void,
    min_level: i32,
) -> c_int {
    let cb = match callback {
        Some(c) => c,
        None => return -1,
    };
    let _ = logging::ensure_logger();
    *LOG_HOOK.lock() = Some(LogHookRegistration {
        callback: cb as usize,
        user_data: user_data as usize,
    });
    let sink = SyncFilteredLogSink {
        min_level: map_log_level(min_level),
    };
    logging::set_sink("asherah-ffi-log", Some(Arc::new(sink)));
    0
}

/// Cumulative count of log records dropped because the async dispatcher's
/// queue was full, since the process started. Cumulative across all hook
/// installations; never resets.
#[unsafe(no_mangle)]
pub extern "C" fn asherah_log_dropped_count() -> u64 {
    logging::log_dropped_count()
}

/// Remove the registered log callback. Subsequent log events will not be
/// dispatched. Always returns 0.
#[unsafe(no_mangle)]
pub extern "C" fn asherah_clear_log_hook() -> c_int {
    *LOG_HOOK.lock() = None;
    logging::set_sink("asherah-ffi-log", None);
    0
}

// ─── Metrics hook ─────────────────────────────────────────────────────────

/// Metric event kind. Cache events use the `name` parameter; timing events
/// use `duration_ns`.
pub const ASHERAH_METRIC_ENCRYPT: i32 = 0;
pub const ASHERAH_METRIC_DECRYPT: i32 = 1;
pub const ASHERAH_METRIC_STORE: i32 = 2;
pub const ASHERAH_METRIC_LOAD: i32 = 3;
pub const ASHERAH_METRIC_CACHE_HIT: i32 = 4;
pub const ASHERAH_METRIC_CACHE_MISS: i32 = 5;
pub const ASHERAH_METRIC_CACHE_STALE: i32 = 6;

/// Metrics callback signature.
///
/// - `event_type`: one of `ASHERAH_METRIC_*`.
/// - `duration_ns`: nanoseconds for timing events; 0 for cache events.
/// - `name`: NUL-terminated UTF-8 for cache events (cache name); NULL for
///   timing events.
pub type AsherahMetricsCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    event_type: i32,
    duration_ns: u64,
    name: *const c_char,
);

struct MetricsHookRegistration {
    callback: usize,
    user_data: usize,
}

// Use AtomicUsize pair guarded by a mutex for the registration; reads are
// frequent (per encrypt/decrypt) so we prefer copy-out under lock.
static METRICS_HOOK: Mutex<Option<MetricsHookRegistration>> = Mutex::new(None);
// Cheap fast-path probe so the metrics path can short-circuit without
// taking the mutex in the steady-state where no hook is set.
static METRICS_HOOK_INSTALLED: AtomicUsize = AtomicUsize::new(0);

struct CallbackMetricsSink;

impl CallbackMetricsSink {
    fn invoke(event_type: i32, duration_ns: u64, name: Option<&str>) {
        if METRICS_HOOK_INSTALLED.load(Ordering::Acquire) == 0 {
            return;
        }
        let registration = match METRICS_HOOK.lock().as_ref() {
            Some(r) => MetricsHookRegistration {
                callback: r.callback,
                user_data: r.user_data,
            },
            None => return,
        };
        let name_cstr = name.and_then(|n| std::ffi::CString::new(n).ok());
        let name_ptr = name_cstr
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null());
        drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || {
                let cb: AsherahMetricsCallback =
                    unsafe { std::mem::transmute(registration.callback) };
                unsafe {
                    cb(
                        registration.user_data as *mut c_void,
                        event_type,
                        duration_ns,
                        name_ptr,
                    );
                }
            },
        )));
    }
}

impl MetricsSink for CallbackMetricsSink {
    fn encrypt(&self, dur: Duration) {
        Self::invoke(ASHERAH_METRIC_ENCRYPT, dur.as_nanos() as u64, None);
    }
    fn decrypt(&self, dur: Duration) {
        Self::invoke(ASHERAH_METRIC_DECRYPT, dur.as_nanos() as u64, None);
    }
    fn store(&self, dur: Duration) {
        Self::invoke(ASHERAH_METRIC_STORE, dur.as_nanos() as u64, None);
    }
    fn load(&self, dur: Duration) {
        Self::invoke(ASHERAH_METRIC_LOAD, dur.as_nanos() as u64, None);
    }
    fn cache_hit(&self, name: &str) {
        Self::invoke(ASHERAH_METRIC_CACHE_HIT, 0, Some(name));
    }
    fn cache_miss(&self, name: &str) {
        Self::invoke(ASHERAH_METRIC_CACHE_MISS, 0, Some(name));
    }
    fn cache_stale(&self, name: &str) {
        Self::invoke(ASHERAH_METRIC_CACHE_STALE, 0, Some(name));
    }
}

const DEFAULT_METRICS_QUEUE_CAPACITY: usize = 4096;

fn install_metrics_hook_with_config(
    cb: AsherahMetricsCallback,
    user_data: *mut c_void,
    queue_capacity: usize,
) {
    *METRICS_HOOK.lock() = Some(MetricsHookRegistration {
        callback: cb as usize,
        user_data: user_data as usize,
    });
    METRICS_HOOK_INSTALLED.store(1, Ordering::Release);
    let async_sink = AsyncMetricsSink::new(
        CallbackMetricsSink,
        AsyncMetricsConfig {
            queue_capacity: if queue_capacity == 0 {
                DEFAULT_METRICS_QUEUE_CAPACITY
            } else {
                queue_capacity
            },
        },
    );
    metrics::set_sink(async_sink);
    metrics::set_enabled(true);
}

/// Register a callback that receives every metric event. Replaces any
/// previously registered hook. Also enables metrics collection (which is
/// off by default for performance).
///
/// Pass a non-null `callback`. `user_data` is opaque and passed back
/// unchanged. Returns 0 on success, -1 if `callback` is NULL.
///
/// # Async dispatch
/// The callback is **not** invoked on the encrypt/decrypt thread. Events
/// are pushed to a bounded MPSC channel (default capacity 4096) drained by
/// a dedicated worker thread. Overflow events are dropped — see
/// [`asherah_metrics_dropped_count`]. Override the queue size with
/// [`asherah_set_metrics_hook_with_config`].
///
/// # Safety
/// Same lifetime requirements as `asherah_set_log_hook`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_set_metrics_hook(
    callback: Option<AsherahMetricsCallback>,
    user_data: *mut c_void,
) -> c_int {
    let cb = match callback {
        Some(c) => c,
        None => return -1,
    };
    install_metrics_hook_with_config(cb, user_data, DEFAULT_METRICS_QUEUE_CAPACITY);
    0
}

/// Configurable variant of [`asherah_set_metrics_hook`].
///
/// - `queue_capacity`: max events buffered. `0` = use default (4096).
///
/// # Safety
/// Same lifetime requirements as [`asherah_set_metrics_hook`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_set_metrics_hook_with_config(
    callback: Option<AsherahMetricsCallback>,
    user_data: *mut c_void,
    queue_capacity: usize,
) -> c_int {
    let cb = match callback {
        Some(c) => c,
        None => return -1,
    };
    install_metrics_hook_with_config(cb, user_data, queue_capacity);
    0
}

/// Synchronous variant of [`asherah_set_metrics_hook`].
///
/// The callback fires **on the encrypt/decrypt thread**, before the
/// operation returns. No queue, no worker thread, no drop counter.
/// See [`asherah_set_log_hook_sync`] for the trade-off discussion — same
/// idea on the metrics side.
///
/// # Safety
/// Same lifetime requirements as [`asherah_set_metrics_hook`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_set_metrics_hook_sync(
    callback: Option<AsherahMetricsCallback>,
    user_data: *mut c_void,
) -> c_int {
    let cb = match callback {
        Some(c) => c,
        None => return -1,
    };
    *METRICS_HOOK.lock() = Some(MetricsHookRegistration {
        callback: cb as usize,
        user_data: user_data as usize,
    });
    METRICS_HOOK_INSTALLED.store(1, Ordering::Release);
    metrics::set_sink(CallbackMetricsSink);
    metrics::set_enabled(true);
    0
}

/// Cumulative count of metrics events dropped due to async-dispatch
/// queue back-pressure since the process started. Never resets.
#[unsafe(no_mangle)]
pub extern "C" fn asherah_metrics_dropped_count() -> u64 {
    metrics::metrics_dropped_count()
}

/// Remove the registered metrics callback and disable metrics collection.
/// Always returns 0.
#[unsafe(no_mangle)]
pub extern "C" fn asherah_clear_metrics_hook() -> c_int {
    METRICS_HOOK_INSTALLED.store(0, Ordering::Release);
    *METRICS_HOOK.lock() = None;
    metrics::clear_sink();
    metrics::set_enabled(false);
    0
}

// Tests live in `asherah-ffi/tests/hooks.rs` as an integration test
// binary so they get process-level isolation from the lib's other unit
// tests (which call into the metrics path and would race against an
// installed metrics hook).
