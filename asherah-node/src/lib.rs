#![allow(unsafe_code)]
#![deny(clippy::all)]
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;

use napi::bindgen_prelude::*;
use napi::bindgen_prelude::{FunctionRef, JsValuesTupleIntoVec, Object};
use napi::sys;
use napi::{Env, Status};
// Log hook temporarily disabled for performance testing; add debug timers
use napi::threadsafe_function::{
    ThreadsafeCallContext, ThreadsafeFunction, ThreadsafeFunctionCallMode,
};
use napi_derive::napi;
use once_cell::sync::Lazy;

use asherah::logging::{ensure_logger as ensure_core_logger, set_sink as set_log_sink, LogSink};
use asherah::metrics;
use asherah::metrics::MetricsSink;

type Factory = asherah::session::PublicFactory<
    asherah::aead::AES256GCM,
    asherah::builders::DynKms,
    asherah::builders::DynMetastore,
>;
type Session = asherah::session::PublicSession<
    asherah::aead::AES256GCM,
    asherah::builders::DynKms,
    asherah::builders::DynMetastore,
>;

struct GlobalState {
    factory: Factory,
    sessions: HashMap<String, Session>,
    session_caching: bool,
}

static STATE: Lazy<Mutex<Option<GlobalState>>> = Lazy::new(|| Mutex::new(None));
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

fn is_debug() -> bool {
    DEBUG_ENABLED.load(Ordering::Relaxed)
}
fn debug_log(msg: &str) {
    if is_debug() {
        log::debug!("[asherah-node] {msg}");
    }
}

#[derive(Debug)]
#[napi(object)]
pub struct AsherahConfig {
    pub service_name: String,
    pub product_id: String,
    pub expire_after: Option<i64>,
    pub check_interval: Option<i64>,
    pub metastore: String, // "memory" | "rdbms" | "dynamodb"
    pub connection_string: Option<String>,
    pub dynamo_db_endpoint: Option<String>,
    pub dynamo_db_region: Option<String>,
    pub dynamo_db_table_name: Option<String>,
    pub session_cache_max_size: Option<u32>,
    pub session_cache_duration: Option<i64>,
    pub kms: Option<String>,                         // "aws" | "static"
    pub region_map: Option<HashMap<String, String>>, // region -> arn
    pub preferred_region: Option<String>,
    pub enable_region_suffix: Option<bool>,
    pub enable_session_caching: Option<bool>,
    pub verbose: Option<bool>,
}

fn set_env_bool(key: &str, v: Option<bool>) {
    if let Some(b) = v {
        std::env::set_var(key, if b { "1" } else { "0" });
    }
}
fn set_env_i64(key: &str, v: Option<i64>) {
    if let Some(x) = v {
        std::env::set_var(key, x.to_string());
    }
}
fn set_env_u32(key: &str, v: Option<u32>) {
    if let Some(x) = v {
        std::env::set_var(key, x.to_string());
    }
}
fn set_env_str(key: &str, v: Option<String>) {
    if let Some(s) = v {
        std::env::set_var(key, s);
    }
}

fn apply_config_env(cfg: &AsherahConfig) -> Result<()> {
    // Core service identifiers
    std::env::set_var("SERVICE_NAME", &cfg.service_name);
    std::env::set_var("PRODUCT_ID", &cfg.product_id);

    // Policy
    set_env_i64("EXPIRE_AFTER_SECS", cfg.expire_after);
    set_env_i64("REVOKE_CHECK_INTERVAL_SECS", cfg.check_interval);
    set_env_bool("SESSION_CACHE", cfg.enable_session_caching);
    set_env_u32("SESSION_CACHE_MAX_SIZE", cfg.session_cache_max_size);
    set_env_i64("SESSION_CACHE_DURATION_SECS", cfg.session_cache_duration);

    // Metastore selection
    let mut m = cfg.metastore.to_lowercase();
    if m == "sqlite" {
        if let Some(path) = &cfg.connection_string {
            std::env::set_var("SQLITE_PATH", path);
        }
        m = "rdbms".into();
    }
    if std::env::var("ASHERAH_INTEROP_DEBUG").is_ok() {
        log::debug!(
            "asherah-node metastore={} connection_string={:?} sqlite_path={:?}",
            m,
            cfg.connection_string,
            std::env::var("SQLITE_PATH").ok()
        );
    }
    std::env::set_var("Metastore", &m);
    match m.as_str() {
        "memory" => {}
        "rdbms" => {
            if let Some(cs) = &cfg.connection_string {
                if cs.starts_with("postgres://") || cs.starts_with("postgresql://") {
                    std::env::set_var("POSTGRES_URL", cs);
                } else if cs.starts_with("mysql://") {
                    std::env::set_var("MYSQL_URL", cs);
                } else if cs.starts_with("sqlite://") {
                    let trimmed = cs.trim_start_matches("sqlite://");
                    std::env::set_var("SQLITE_PATH", trimmed);
                } else {
                    std::env::set_var("SQLITE_PATH", cs);
                }
            }
        }
        "dynamodb" => {
            set_env_str("AWS_ENDPOINT_URL", cfg.dynamo_db_endpoint.clone());
            set_env_str("AWS_REGION", cfg.dynamo_db_region.clone());
            set_env_str(
                "DDB_TABLE",
                cfg.dynamo_db_table_name
                    .clone()
                    .or(Some("EncryptionKey".into())),
            );
            set_env_bool("DDB_REGION_SUFFIX", cfg.enable_region_suffix);
        }
        other => {
            return Err(Error::from_reason(format!(
                "unsupported metastore: {}",
                other
            )))
        }
    }

    // KMS selection
    let kms = cfg
        .kms
        .clone()
        .unwrap_or_else(|| "static".into())
        .to_lowercase();
    std::env::set_var("KMS", &kms);
    match kms.as_str() {
        "aws" => {
            if let Some(map) = &cfg.region_map {
                std::env::set_var(
                    "REGION_MAP",
                    serde_json::to_string(map).unwrap_or_else(|_| "{}".into()),
                );
            }
            set_env_str("PREFERRED_REGION", cfg.preferred_region.clone());
        }
        "static" => { /* expects STATIC_MASTER_KEY_HEX env externally or uses default in Rust */ }
        other => return Err(Error::from_reason(format!("unsupported kms: {}", other))),
    }

    Ok(())
}

#[napi]
pub fn setup(config: AsherahConfig) -> Result<()> {
    apply_config_env(&config)?;
    let dbg_env = std::env::var("ASHERAH_NODE_DEBUG")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "on" | "yes"));
    DEBUG_ENABLED.store(
        config.verbose.unwrap_or(false) || dbg_env.unwrap_or(false),
        Ordering::Relaxed,
    );

    let factory = asherah::builders::factory_from_env()
        .map_err(|e| Error::from_reason(format!("setup error: {e}")))?;
    let session_caching = config.enable_session_caching.unwrap_or(true);

    let mut guard = STATE.lock();
    if guard.is_some() {
        return Err(Error::from_reason(
            "asherah already configured; call shutdown() first",
        ));
    }

    *guard = Some(GlobalState {
        factory,
        sessions: HashMap::new(),
        session_caching,
    });
    Ok(())
}

#[napi]
pub async fn setup_async(config: AsherahConfig) -> Result<()> {
    // For simplicity, do the same work async (config env and create)
    setup(config)
}

#[napi]
pub fn shutdown() -> Result<()> {
    let mut guard = STATE.lock();
    if let Some(mut state) = guard.take() {
        for (_, session) in state.sessions.drain() {
            drop(session.close());
        }
        state
            .factory
            .close()
            .map_err(|e| Error::from_reason(format!("shutdown error: {e}")))?;
    }
    DEBUG_ENABLED.store(false, Ordering::Relaxed);
    Ok(())
}

#[napi]
pub async fn shutdown_async() -> Result<()> {
    shutdown()
}

fn with_session<R>(partition_id: &str, fcall: impl FnOnce(&Session) -> Result<R>) -> Result<R> {
    let mut guard = STATE.lock();
    let state = guard
        .as_mut()
        .ok_or_else(|| Error::from_reason("asherah not configured; call setup() first"))?;

    if state.session_caching {
        let session = state
            .sessions
            .entry(partition_id.to_string())
            .or_insert_with(|| state.factory.get_session(partition_id));
        return fcall(session);
    }

    let session = state.factory.get_session(partition_id);
    drop(guard);
    let result = fcall(&session);
    let close_result = session
        .close()
        .map_err(|e| Error::from_reason(format!("session close error: {e}")));
    match (result, close_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(e)) | (Err(e), Ok(())) => Err(e),
        (Err(e), Err(close_err)) => {
            debug_log(&format!("error closing session after failure: {close_err}"));
            Err(e)
        }
    }
}

#[napi]
pub fn get_setup_status() -> bool {
    STATE.lock().is_some()
}

#[napi]
pub fn setenv(env: String) -> Result<()> {
    // Accept lines of KEY=VALUE; ignore blanks
    for line in env.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = s.split_once('=') {
            std::env::set_var(k.trim(), v.trim());
        }
    }
    Ok(())
}

#[napi]
pub fn encrypt(partition_id: String, data: Buffer) -> Result<String> {
    let t0 = Instant::now();
    let drr = with_session(&partition_id, |s| {
        let t_core0 = Instant::now();
        let r = s
            .encrypt(&data)
            .map_err(|e| Error::from_reason(format!("encrypt error: {e}")));
        debug_log(&format!(
            "encrypt core {} us",
            t_core0.elapsed().as_micros()
        ));
        r
    })?;
    let t_json0 = Instant::now();
    let out =
        serde_json::to_string(&drr).map_err(|e| Error::from_reason(format!("json error: {e}")))?;
    debug_log(&format!(
        "encrypt total={} us json={} us",
        t0.elapsed().as_micros(),
        t_json0.elapsed().as_micros()
    ));
    Ok(out)
}

#[napi]
pub async fn encrypt_async(partition_id: String, data: Buffer) -> Result<String> {
    tokio::task::spawn_blocking(move || encrypt(partition_id, data))
        .await
        .map_err(|e| Error::from_reason(format!("join error: {e}")))?
}

#[napi]
pub fn decrypt(partition_id: String, data_row_record: String) -> Result<Buffer> {
    let t0 = Instant::now();
    let t_parse0 = Instant::now();
    let drr: asherah::types::DataRowRecord = serde_json::from_str(&data_row_record)
        .map_err(|e| Error::from_reason(format!("invalid DataRowRecord JSON: {e}")))?;
    debug_log(&format!(
        "decrypt json parse {} us",
        t_parse0.elapsed().as_micros()
    ));
    let pt = with_session(&partition_id, |s| {
        let t_core0 = Instant::now();
        let r = s
            .decrypt(drr)
            .map_err(|e| Error::from_reason(format!("decrypt error: {e}")));
        debug_log(&format!(
            "decrypt core {} us",
            t_core0.elapsed().as_micros()
        ));
        r
    })?;
    debug_log(&format!("decrypt total {} us", t0.elapsed().as_micros()));
    Ok(Buffer::from(pt))
}

#[napi]
pub async fn decrypt_async(partition_id: String, data_row_record: String) -> Result<Buffer> {
    tokio::task::spawn_blocking(move || decrypt(partition_id, data_row_record))
        .await
        .map_err(|e| Error::from_reason(format!("join error: {e}")))?
}

#[napi]
pub fn encrypt_string(partition_id: String, data: String) -> Result<String> {
    encrypt(partition_id, Buffer::from(data.into_bytes()))
}

#[napi]
pub async fn encrypt_string_async(partition_id: String, data: String) -> Result<String> {
    encrypt_async(partition_id, Buffer::from(data.into_bytes())).await
}

#[napi]
pub fn decrypt_string(partition_id: String, drr: String) -> Result<String> {
    let buf = decrypt(partition_id, drr)?;
    String::from_utf8(buf.to_vec()).map_err(|e| Error::from_reason(format!("utf8 error: {e}")))
}

#[napi]
pub async fn decrypt_string_async(partition_id: String, drr: String) -> Result<String> {
    let buf = decrypt_async(partition_id, drr).await?;
    String::from_utf8(buf.to_vec()).map_err(|e| Error::from_reason(format!("utf8 error: {e}")))
}

#[napi]
pub fn set_max_stack_alloc_item_size(_n: u32) {}

#[napi]
pub fn set_safety_padding_overhead(_n: u32) {}

struct JsArgList(Vec<sys::napi_value>);

impl JsValuesTupleIntoVec for JsArgList {
    fn into_vec(self, _: sys::napi_env) -> Result<Vec<sys::napi_value>> {
        Ok(self.0)
    }
}

struct MetricsEvent {
    event_type: &'static str,
    duration_ns: Option<u64>,
    name: Option<String>,
}

type MetricsCallback =
    ThreadsafeFunction<MetricsEvent, Unknown<'static>, JsArgList, Status, true, false, 0>;

struct JsMetricsSink {
    tsfn: Arc<MetricsCallback>,
}

struct MetricsHook {
    _tsfn: Arc<MetricsCallback>,
    _reference: FunctionRef<Unknown<'static>, Unknown<'static>>,
}

impl JsMetricsSink {
    fn emit(&self, event_type: &'static str, duration_ns: Option<u64>, name: Option<String>) {
        let event = MetricsEvent {
            event_type,
            duration_ns,
            name,
        };
        let _ = self
            .tsfn
            .call(Ok(event), ThreadsafeFunctionCallMode::NonBlocking);
    }
}

impl MetricsSink for JsMetricsSink {
    fn encrypt(&self, duration: std::time::Duration) {
        self.emit("encrypt", Some(duration.as_nanos() as u64), None);
    }

    fn decrypt(&self, duration: std::time::Duration) {
        self.emit("decrypt", Some(duration.as_nanos() as u64), None);
    }

    fn store(&self, duration: std::time::Duration) {
        self.emit("store", Some(duration.as_nanos() as u64), None);
    }

    fn load(&self, duration: std::time::Duration) {
        self.emit("load", Some(duration.as_nanos() as u64), None);
    }

    fn cache_hit(&self, name: &str) {
        self.emit("cache_hit", None, Some(name.to_string()));
    }

    fn cache_miss(&self, name: &str) {
        self.emit("cache_miss", None, Some(name.to_string()));
    }
}

static METRICS_HOOK: Lazy<Mutex<Option<MetricsHook>>> = Lazy::new(|| Mutex::new(None));

#[napi]
pub fn set_metrics_hook(env: Env, callback: Option<Function<'_>>) -> Result<()> {
    if let Some(cb) = callback {
        let func_ref = cb.create_ref()?;
        let borrowed = func_ref.borrow_back(&env)?;
        let borrowed_static: Function<'static> = unsafe { std::mem::transmute(borrowed) };
        let tsfn = borrowed_static
            .build_threadsafe_function::<MetricsEvent>()
            .max_queue_size::<0>()
            .callee_handled::<true>()
            .build_callback(|ctx: ThreadsafeCallContext<MetricsEvent>| {
                let env = ctx.env;
                let MetricsEvent {
                    event_type,
                    duration_ns,
                    name,
                } = ctx.value;
                let mut obj = Object::new(&env)?;
                obj.set("type", env.create_string(event_type)?)?;
                if let Some(ns) = duration_ns {
                    obj.set("durationNs", env.create_double(ns as f64)?)?;
                }
                if let Some(name) = name {
                    obj.set("name", env.create_string(&name)?)?;
                }
                let raw = obj.value().value;
                Ok(JsArgList(vec![raw]))
            })?;
        let arc = Arc::new(tsfn);
        let reference: FunctionRef<Unknown<'static>, Unknown<'static>> =
            unsafe { std::mem::transmute(func_ref) };
        metrics::set_sink(JsMetricsSink {
            tsfn: Arc::clone(&arc),
        });
        *METRICS_HOOK.lock() = Some(MetricsHook {
            _tsfn: arc,
            _reference: reference,
        });
    } else {
        metrics::clear_sink();
        *METRICS_HOOK.lock() = None;
    }
    Ok(())
}

#[derive(Clone)]
struct LogEvent {
    level: log::Level,
    message: String,
    target: String,
}

type LogCallback =
    ThreadsafeFunction<LogEvent, Unknown<'static>, JsArgList, Status, true, false, 0>;

struct JsLogSink {
    tsfn: Arc<LogCallback>,
}

struct LogHook {
    _tsfn: Arc<LogCallback>,
    _reference: FunctionRef<Unknown<'static>, Unknown<'static>>,
}

impl LogSink for JsLogSink {
    fn log(&self, record: &log::Record<'_>) {
        let event = LogEvent {
            level: record.level(),
            message: record.args().to_string(),
            target: record.target().to_string(),
        };
        let _ = self
            .tsfn
            .call(Ok(event), ThreadsafeFunctionCallMode::NonBlocking);
    }
}

static LOG_HOOK: Lazy<Mutex<Option<LogHook>>> = Lazy::new(|| Mutex::new(None));
static LOGGER_READY: OnceLock<()> = OnceLock::new();

fn ensure_logger_initialized() -> Result<()> {
    if LOGGER_READY.get().is_none() {
        ensure_core_logger().map_err(|e| Error::from_reason(format!("log init error: {e}")))?;
        let _ = LOGGER_READY.set(());
    }
    Ok(())
}

#[napi]
pub fn set_log_hook(env: Env, callback: Option<Function<'_>>) -> Result<()> {
    ensure_logger_initialized()?;

    if let Some(cb) = callback {
        let func_ref = cb.create_ref()?;
        let borrowed = func_ref.borrow_back(&env)?;
        let borrowed_static: Function<'static> = unsafe { std::mem::transmute(borrowed) };
        let tsfn = borrowed_static
            .build_threadsafe_function::<LogEvent>()
            .max_queue_size::<0>()
            .callee_handled::<true>()
            .build_callback(|ctx: ThreadsafeCallContext<LogEvent>| {
                let env = ctx.env;
                let LogEvent {
                    level,
                    message,
                    target,
                } = ctx.value;
                let mut obj = Object::new(&env)?;
                obj.set("level", env.create_string(level.as_str())?)?;
                obj.set("message", env.create_string(&message)?)?;
                obj.set("target", env.create_string(&target)?)?;
                let raw = obj.value().value;
                Ok(JsArgList(vec![raw]))
            })?;
        let arc = Arc::new(tsfn);
        let reference: FunctionRef<Unknown<'static>, Unknown<'static>> =
            unsafe { std::mem::transmute(func_ref) };
        set_log_sink(
            "node",
            Some(Arc::new(JsLogSink {
                tsfn: Arc::clone(&arc),
            })),
        );
        *LOG_HOOK.lock() = Some(LogHook {
            _tsfn: arc,
            _reference: reference,
        });
    } else {
        set_log_sink("node", None);
        *LOG_HOOK.lock() = None;
    }

    Ok(())
}
