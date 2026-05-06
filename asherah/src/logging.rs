use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::{Arc, Once};
use std::thread::{Builder as ThreadBuilder, JoinHandle};

static SUBSCRIBERS: once_cell::sync::Lazy<RwLock<HashMap<&'static str, Arc<dyn LogSink>>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));
static LOGGER: MultiplexLogger = MultiplexLogger;
static LOGGER_ONCE: Once = Once::new();
// True only when our `MultiplexLogger` is the global `log` logger. If some
// other logger was already installed (env_logger, fern, etc.) we leave
// `log::max_level` alone so we don't silence the host application's logs.
static LOGGER_INSTALLED: AtomicBool = AtomicBool::new(false);

struct MultiplexLogger;

impl log::Log for MultiplexLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        log::max_level() >= metadata.level()
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let subscribers = SUBSCRIBERS.read();
        for sink in subscribers.values() {
            sink.log(record);
        }
    }

    fn flush(&self) {}
}

pub trait LogSink: Send + Sync + 'static {
    fn log(&self, record: &log::Record<'_>);
    /// Most-permissive level the sink wants to receive. The
    /// multiplex logger uses the *max* of every registered sink's
    /// level to set `log::max_level`, so a sink that only wants
    /// `Warn` doesn't pay materialization cost for trace/debug/info
    /// records (the producer-side `log!` macro short-circuits before
    /// formatting). Default `Trace` preserves the previous "give me
    /// everything" semantics for sinks that don't override.
    /// T-finding "log::max_level = Trace whenever any subscriber
    /// registers; defeats subscribers wanting Warn" in
    /// `docs/review-2026-05-05-findings.md`.
    fn min_level(&self) -> log::LevelFilter {
        log::LevelFilter::Trace
    }
}

/// Install our multiplex logger as the global `log` logger if nothing else
/// has claimed that slot yet. The actual level filter stays at `Off` until
/// the first subscriber registers via [`set_sink`] — that way log macros in
/// the encrypt/decrypt hot path short-circuit at the macro level when no hook
/// is installed, instead of running through `MultiplexLogger::log` for an
/// empty subscriber map.
///
/// This function cannot fail observably — `log::set_logger` returns `Err`
/// only if a different logger is already installed, in which case we
/// leave it alone (this is the documented "live and let live" behavior).
/// The signature returns `Result<(), SetLoggerError>` purely for source
/// compatibility with previous releases; new code should treat it as
/// infallible.
pub fn ensure_logger() -> Result<(), log::SetLoggerError> {
    LOGGER_ONCE.call_once(|| {
        if log::set_logger(&LOGGER).is_ok() {
            LOGGER_INSTALLED.store(true, Ordering::Release);
            log::set_max_level(log::LevelFilter::Off);
        }
    });
    Ok(())
}

pub fn set_sink(name: &'static str, sink: Option<Arc<dyn LogSink>>) {
    let mut guard = SUBSCRIBERS.write();
    match sink {
        Some(s) => {
            guard.insert(name, s);
        }
        None => {
            guard.remove(name);
        }
    }
    // Compute the effective max level: the max of every registered
    // sink's `min_level()` (defaults to `Trace` for unimplemented
    // hooks). Empty map → `Off` so log macros short-circuit when no
    // subscriber is listening.
    let new_level = guard
        .values()
        .map(|s| s.min_level())
        .max()
        .unwrap_or(log::LevelFilter::Off);
    drop(guard);

    // Only manage the global level filter if we actually own the logger.
    // If a different logger was registered before us we leave it alone.
    if !LOGGER_INSTALLED.load(Ordering::Acquire) {
        return;
    }
    log::set_max_level(new_level);
}

// ─── async dispatch wrapper ──────────────────────────────────────────────
//
// `AsyncLogSink` wraps any synchronous `LogSink` with a bounded SPSC channel
// and a single dedicated worker thread. The intent: keep the encrypt/decrypt
// hot path independent of how slow a user-supplied callback is. Push side is
// a level filter + materialize-to-owned + `try_send`. The worker thread pops
// off the channel and invokes the inner sink.
//
// Back-pressure policy: drop on overflow, increment a global counter. We
// prefer dropping log records to either (a) blocking the encrypt thread or
// (b) growing memory unbounded. The drop counter is exposed via
// `log_dropped_count()` so callers can monitor.
//
// The worker is owned by the `AsyncLogSink`. Dropping the sink closes the
// sender, which causes the worker's `recv()` loop to terminate naturally.

/// Cumulative count of log records dropped because the async dispatcher's
/// channel was full, across the lifetime of the process. Each call to
/// [`AsyncLogSink::new`] shares this same counter — drops from any
/// dispatcher are added together.
static LOG_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Number of log records the async dispatcher has dropped due to channel
/// back-pressure since the process started. Cumulative across all installed
/// log hooks; never resets. Useful as a smoke test for "is my queue too
/// small for my log volume?"
pub fn log_dropped_count() -> u64 {
    LOG_DROPPED.load(Ordering::Relaxed)
}

/// Configuration for [`AsyncLogSink`].
#[derive(Debug, Clone)]
#[allow(missing_copy_implementations)]
pub struct AsyncLogConfig {
    /// Maximum events buffered. When the channel is full additional events
    /// are dropped (counted in [`log_dropped_count`]). Default: `4096`.
    pub queue_capacity: usize,
    /// Filter applied on the producer thread before materializing the
    /// record. Records whose level is more verbose than this filter are
    /// discarded before any allocation or queue push. Default:
    /// [`log::LevelFilter::Warn`] — Trace/Debug/Info are dropped. Pass
    /// [`log::LevelFilter::Trace`] to deliver everything.
    pub min_level: log::LevelFilter,
}

impl Default for AsyncLogConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 4096,
            // Warn-and-above by default. Trace/Debug/Info are dropped at the
            // producer thread before any allocation. Callers who want the
            // verbose records pass an explicit `min_level` (typically Trace).
            min_level: log::LevelFilter::Warn,
        }
    }
}

#[allow(missing_debug_implementations)]
struct OwnedLogEvent {
    level: log::Level,
    target: String,
    message: String,
}

/// Wrap a synchronous `LogSink` in an async dispatcher. The encrypt/decrypt
/// hot path performs only a level check, an `O(message length)` materialize,
/// and a single non-blocking channel send; the user's callback runs on a
/// dedicated worker thread.
#[allow(missing_debug_implementations)]
pub struct AsyncLogSink {
    sender: Option<SyncSender<OwnedLogEvent>>,
    min_level: log::LevelFilter,
    // Held in `Option` so `Drop::drop` can `take()` and `join()` the
    // worker explicitly — surfacing any panic from the user's
    // `LogSink` callback into the operator log instead of silently
    // disappearing into a detached thread. T-finding "Worker
    // JoinHandle never joined in Drop; worker panics lost" in
    // `docs/review-2026-05-05-findings.md`.
    worker: Option<JoinHandle<()>>,
}

impl AsyncLogSink {
    /// Construct an async dispatcher wrapping `inner`.
    ///
    /// Returns `Err(io::Error)` when the OS rejects the worker thread
    /// spawn (EAGAIN under thread quota, seccomp policy, etc.). The
    /// previous `expect()` aborted the host process — fine for a binary
    /// but unacceptable in cdylib-loaded FFI contexts where the host
    /// runtime can't recover. T-finding ".expect(\"spawn worker\")
    /// aborts cdylib-loaded process on EAGAIN" in
    /// `docs/review-2026-05-05-findings.md`.
    pub fn new<S: LogSink>(inner: S, config: AsyncLogConfig) -> std::io::Result<Self> {
        let (sender, receiver) = sync_channel::<OwnedLogEvent>(config.queue_capacity);
        let worker = ThreadBuilder::new()
            .name("asherah-log-dispatch".into())
            .spawn(move || {
                while let Ok(event) = receiver.recv() {
                    let metadata = log::Metadata::builder()
                        .level(event.level)
                        .target(event.target.as_str())
                        .build();
                    inner.log(
                        &log::Record::builder()
                            .args(format_args!("{}", event.message))
                            .metadata(metadata)
                            .build(),
                    );
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            min_level: config.min_level,
            worker: Some(worker),
        })
    }
}

impl LogSink for AsyncLogSink {
    fn min_level(&self) -> log::LevelFilter {
        self.min_level
    }
    fn log(&self, record: &log::Record<'_>) {
        // Producer-side level filter — saves the materialization cost for
        // records the user has opted out of.
        if record.level() > self.min_level {
            return;
        }
        let Some(sender) = self.sender.as_ref() else {
            LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let event = OwnedLogEvent {
            level: record.level(),
            target: record.target().to_string(),
            message: record.args().to_string(),
        };
        match sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                LOG_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Drop for AsyncLogSink {
    fn drop(&mut self) {
        // Drop the sender first so the worker's `recv()` returns Err
        // and the loop exits cleanly, then join so a panic inside the
        // user's `LogSink` callback is logged here rather than
        // disappearing into a detached thread.
        drop(self.sender.take());
        if let Some(worker) = self.worker.take() {
            if let Err(panic_payload) = worker.join() {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| panic_payload.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("(non-string panic payload)");
                // `eprintln` rather than `log::error!`: this Drop runs
                // during the very tear-down of the log-dispatch path, so
                // the `log` macros may already be wired to a sink that's
                // about to disappear. Stderr is the most reliable
                // surface to surface the panic to the operator.
                #[allow(clippy::print_stderr)]
                {
                    eprintln!("AsyncLogSink dispatcher worker panicked: {msg}");
                }
            }
        }
    }
}
