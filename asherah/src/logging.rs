use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Once;

static SUBSCRIBERS: once_cell::sync::Lazy<RwLock<HashMap<&'static str, Arc<dyn LogSink>>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));
static LOGGER: MultiplexLogger = MultiplexLogger;
static LOGGER_ONCE: Once = Once::new();

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

pub fn ensure_logger() -> Result<(), log::SetLoggerError> {
    LOGGER_ONCE.call_once(|| {
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(log::LevelFilter::Trace);
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
}
