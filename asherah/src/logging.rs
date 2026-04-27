use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Once;

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
}

/// Install our multiplex logger as the global `log` logger if nothing else
/// has claimed that slot yet. The actual level filter stays at `Off` until
/// the first subscriber registers via [`set_sink`] — that way log macros in
/// the encrypt/decrypt hot path short-circuit at the macro level when no hook
/// is installed, instead of running through `MultiplexLogger::log` for an
/// empty subscriber map.
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
    let was_empty = guard.is_empty();
    match sink {
        Some(s) => {
            guard.insert(name, s);
        }
        None => {
            guard.remove(name);
        }
    }
    let is_empty_now = guard.is_empty();
    drop(guard);

    // Only manage the global level filter if we actually own the logger.
    // If a different logger was registered before us we leave it alone.
    if !LOGGER_INSTALLED.load(Ordering::Acquire) {
        return;
    }
    match (was_empty, is_empty_now) {
        (true, false) => log::set_max_level(log::LevelFilter::Trace),
        (false, true) => log::set_max_level(log::LevelFilter::Off),
        _ => {}
    }
}
