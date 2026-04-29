#![allow(unsafe_code)]
#![deny(clippy::all)]
use lru::LruCache;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::num::NonZeroUsize;
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
    /// Bounded LRU. `LruCache.get` does move-to-MRU on hit; `LruCache.put`
    /// evicts the LRU entry at capacity. Honors `SessionCacheMaxSize` —
    /// previously a HashMap with `keys().next()` (random) eviction.
    sessions: LruCache<String, Arc<Session>>,
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
    pub dynamo_db_signing_region: Option<String>,
    pub dynamo_db_table_name: Option<String>,
    pub session_cache_max_size: Option<u32>,
    pub session_cache_duration: Option<i64>,
    pub kms: Option<String>, // "aws" | "static" | "vault" | "secrets-manager"
    pub region_map: Option<HashMap<String, String>>, // region -> arn
    pub preferred_region: Option<String>,
    pub aws_profile_name: Option<String>,
    pub enable_region_suffix: Option<bool>,
    pub enable_session_caching: Option<bool>,
    pub replica_read_consistency: Option<String>,
    pub verbose: Option<bool>,
    pub sql_metastore_db_type: Option<String>,
    pub disable_zero_copy: Option<bool>,
    pub null_data_check: Option<bool>,
    pub enable_canaries: Option<bool>,
    // Connection pool
    pub pool_max_open: Option<u32>,
    pub pool_max_idle: Option<u32>,
    pub pool_max_lifetime: Option<u32>,
    pub pool_max_idle_time: Option<u32>,
    // KMS: AWS
    pub kms_key_id: Option<String>,
    // KMS: Secrets Manager
    pub secrets_manager_secret_id: Option<String>,
    // KMS: Vault Transit
    pub vault_addr: Option<String>,
    pub vault_token: Option<String>,
    pub vault_auth_method: Option<String>,
    pub vault_auth_role: Option<String>,
    pub vault_auth_mount: Option<String>,
    pub vault_approle_role_id: Option<String>,
    pub vault_approle_secret_id: Option<String>,
    pub vault_client_cert: Option<String>,
    pub vault_client_key: Option<String>,
    pub vault_k8s_token_path: Option<String>,
    pub vault_transit_key: Option<String>,
    pub vault_transit_mount: Option<String>,
    // KMS: Static
    pub static_master_key_hex: Option<String>,
}

fn to_config_options(cfg: &AsherahConfig) -> asherah_config::ConfigOptions {
    asherah_config::ConfigOptions {
        service_name: Some(cfg.service_name.clone()),
        product_id: Some(cfg.product_id.clone()),
        expire_after: cfg.expire_after,
        check_interval: cfg.check_interval,
        metastore: Some(cfg.metastore.clone()),
        connection_string: cfg.connection_string.clone(),
        replica_read_consistency: cfg.replica_read_consistency.clone(),
        dynamo_db_endpoint: cfg.dynamo_db_endpoint.clone(),
        dynamo_db_region: cfg.dynamo_db_region.clone(),
        dynamo_db_signing_region: cfg.dynamo_db_signing_region.clone(),
        dynamo_db_table_name: cfg.dynamo_db_table_name.clone(),
        session_cache_max_size: cfg.session_cache_max_size,
        session_cache_duration: cfg.session_cache_duration,
        kms: cfg.kms.clone(),
        static_master_key_hex: cfg.static_master_key_hex.clone(),
        region_map: cfg.region_map.clone(),
        preferred_region: cfg.preferred_region.clone(),
        aws_profile_name: cfg.aws_profile_name.clone(),
        enable_region_suffix: cfg.enable_region_suffix,
        enable_session_caching: cfg.enable_session_caching,
        verbose: cfg.verbose,
        sql_metastore_db_type: cfg.sql_metastore_db_type.clone(),
        disable_zero_copy: cfg.disable_zero_copy,
        null_data_check: cfg.null_data_check,
        enable_canaries: cfg.enable_canaries,
        pool_max_open: cfg.pool_max_open.map(|v| v as usize),
        pool_max_idle: cfg.pool_max_idle.map(|v| v as usize),
        pool_max_lifetime: cfg.pool_max_lifetime.map(|v| v as u64),
        pool_max_idle_time: cfg.pool_max_idle_time.map(|v| v as u64),
        kms_key_id: cfg.kms_key_id.clone(),
        secrets_manager_secret_id: cfg.secrets_manager_secret_id.clone(),
        vault_addr: cfg.vault_addr.clone(),
        vault_token: cfg.vault_token.clone(),
        vault_auth_method: cfg.vault_auth_method.clone(),
        vault_auth_role: cfg.vault_auth_role.clone(),
        vault_auth_mount: cfg.vault_auth_mount.clone(),
        vault_approle_role_id: cfg.vault_approle_role_id.clone(),
        vault_approle_secret_id: cfg.vault_approle_secret_id.clone(),
        vault_client_cert: cfg.vault_client_cert.clone(),
        vault_client_key: cfg.vault_client_key.clone(),
        vault_k8s_token_path: cfg.vault_k8s_token_path.clone(),
        vault_transit_key: cfg.vault_transit_key.clone(),
        vault_transit_mount: cfg.vault_transit_mount.clone(),
    }
}

#[napi]
pub fn setup(config: AsherahConfig) -> Result<()> {
    let opts = to_config_options(&config);
    let (factory, applied) = asherah_config::factory_from_config(&opts)
        .map_err(|e| Error::from_reason(format!("setup error: {e:#}")))?;
    // Always enable per-factory metrics so an installed metrics hook
    // actually fires for encrypt/decrypt/store/load events. The
    // additional cost is one Instant::now() per encrypt regardless of
    // whether a hook is installed; the global metrics gate (toggled by
    // set_metrics_hook) decides whether the sink is actually invoked.
    let factory = factory.with_metrics(true);

    let dbg_env = std::env::var("ASHERAH_NODE_DEBUG")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "on" | "yes"));
    DEBUG_ENABLED.store(
        applied.verbose || dbg_env.unwrap_or(false),
        Ordering::Relaxed,
    );

    let mut guard = STATE.lock();
    if guard.is_some() {
        return Err(Error::from_reason(
            "asherah already configured; call shutdown() first",
        ));
    }

    let cap = NonZeroUsize::new(applied.session_cache_max_size)
        .or_else(|| NonZeroUsize::new(1000))
        .expect("1000 is non-zero");
    *guard = Some(GlobalState {
        factory,
        sessions: LruCache::new(cap),
        session_caching: applied.enable_session_caching,
    });
    Ok(())
}

#[napi]
pub async fn setup_async(config: AsherahConfig) -> Result<()> {
    // Use async factory creation — DynamoDB/KMS constructors .await on this
    // runtime instead of creating their own. Postgres uses spawn_blocking
    // internally (sync crate).
    let opts = to_config_options(&config);
    let (factory, applied) = asherah_config::factory_from_config_async(&opts)
        .await
        .map_err(|e| Error::from_reason(format!("setup error: {e:#}")))?;
    let factory = factory.with_metrics(true);

    let dbg_env = std::env::var("ASHERAH_NODE_DEBUG")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "on" | "yes"));
    DEBUG_ENABLED.store(
        applied.verbose || dbg_env.unwrap_or(false),
        Ordering::Relaxed,
    );

    let mut guard = STATE.lock();
    if guard.is_some() {
        return Err(Error::from_reason(
            "asherah already configured; call shutdown() first",
        ));
    }

    let cap = NonZeroUsize::new(applied.session_cache_max_size)
        .or_else(|| NonZeroUsize::new(1000))
        .expect("1000 is non-zero");
    *guard = Some(GlobalState {
        factory,
        sessions: LruCache::new(cap),
        session_caching: applied.enable_session_caching,
    });
    Ok(())
}

#[napi]
pub fn shutdown() -> Result<()> {
    let mut guard = STATE.lock();
    if let Some(mut state) = guard.take() {
        while let Some((_, session)) = state.sessions.pop_lru() {
            drop(session.close());
        }
        state
            .factory
            .close()
            .map_err(|e| Error::from_reason(format!("shutdown error: {e:#}")))?;
    }
    DEBUG_ENABLED.store(false, Ordering::Relaxed);
    Ok(())
}

#[napi]
pub async fn shutdown_async() -> Result<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let result = shutdown();
        drop(tx.send(result));
    });
    rx.await
        .map_err(|_| Error::from_reason("shutdown thread panicked"))?
}

fn with_session<R>(partition_id: &str, fcall: impl FnOnce(&Session) -> Result<R>) -> Result<R> {
    let session_arc;

    {
        let mut guard = STATE.lock();
        let state = guard
            .as_mut()
            .ok_or_else(|| Error::from_reason("asherah not configured; call setup() first"))?;

        if state.session_caching {
            // LruCache::get reorders to MRU on hit; put inserts and may
            // evict the LRU at capacity. Sessions are reference-counted
            // (Arc), so an evicted entry stays alive for any in-flight
            // caller until they drop their clone.
            session_arc = if let Some(existing) = state.sessions.get(partition_id) {
                existing.clone()
            } else {
                let fresh = Arc::new(state.factory.get_session(partition_id));
                state.sessions.put(partition_id.to_string(), fresh.clone());
                fresh
            };
        } else {
            let session = state.factory.get_session(partition_id);
            drop(guard);
            // Non-caching path: run crypto without lock, close session after
            let result = fcall(&session);
            let close_result = session
                .close()
                .map_err(|e| Error::from_reason(format!("session close error: {e:#}")));
            return match (result, close_result) {
                (Ok(value), Ok(())) => Ok(value),
                (Ok(_), Err(e)) | (Err(e), Ok(())) => Err(e),
                (Err(e), Err(close_err)) => {
                    debug_log(&format!("error closing session after failure: {close_err}"));
                    Err(e)
                }
            };
        }
    }
    // Lock dropped — run crypto outside the lock
    fcall(&session_arc)
}

/// Get a session for async operations. Returns an owned Arc so the lock is dropped before await.
fn get_session_arc(partition_id: &str) -> Result<(Arc<Session>, bool)> {
    let mut guard = STATE.lock();
    let state = guard
        .as_mut()
        .ok_or_else(|| Error::from_reason("asherah not configured; call setup() first"))?;

    if state.session_caching {
        let session = if let Some(existing) = state.sessions.get(partition_id) {
            existing.clone()
        } else {
            let fresh = Arc::new(state.factory.get_session(partition_id));
            state.sessions.put(partition_id.to_string(), fresh.clone());
            fresh
        };
        Ok((session, true))
    } else {
        let session = Arc::new(state.factory.get_session(partition_id));
        Ok((session, false))
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
            .map_err(|e| Error::from_reason(format!("encrypt error: {e:#}")));
        debug_log(&format!(
            "encrypt core {} us",
            t_core0.elapsed().as_micros()
        ));
        r
    })?;
    let t_json0 = Instant::now();
    let out = drr.to_json_fast();
    debug_log(&format!(
        "encrypt total={} us json={} us",
        t0.elapsed().as_micros(),
        t_json0.elapsed().as_micros()
    ));
    Ok(out)
}

#[napi]
pub async fn encrypt_async(partition_id: String, data: Buffer) -> Result<String> {
    let (session, cached) = get_session_arc(&partition_id)?;
    let drr = session
        .encrypt_async(&data)
        .await
        .map_err(|e| Error::from_reason(format!("encrypt error: {e:#}")))?;
    if !cached {
        drop(session.close());
    }
    Ok(drr.to_json_fast())
}

#[napi]
pub fn decrypt(partition_id: String, data_row_record: Buffer) -> Result<Buffer> {
    let t0 = Instant::now();
    let t_parse0 = Instant::now();
    let drr: asherah::types::DataRowRecord = serde_json::from_slice(&data_row_record)
        .map_err(|e| Error::from_reason(format!("invalid DataRowRecord JSON: {e}")))?;
    debug_log(&format!(
        "decrypt json parse {} us",
        t_parse0.elapsed().as_micros()
    ));
    let pt = with_session(&partition_id, |s| {
        let t_core0 = Instant::now();
        let r = s
            .decrypt(drr)
            .map_err(|e| Error::from_reason(format!("decrypt error: {e:#}")));
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
pub async fn decrypt_async(partition_id: String, data_row_record: Buffer) -> Result<Buffer> {
    let drr: asherah::types::DataRowRecord = serde_json::from_slice(&data_row_record)
        .map_err(|e| Error::from_reason(format!("invalid DataRowRecord JSON: {e}")))?;
    let (session, cached) = get_session_arc(&partition_id)?;
    let pt = session
        .decrypt_async(drr)
        .await
        .map_err(|e| Error::from_reason(format!("decrypt error: {e:#}")))?;
    if !cached {
        drop(session.close());
    }
    Ok(Buffer::from(pt))
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
    let buf = decrypt(partition_id, Buffer::from(drr.into_bytes()))?;
    String::from_utf8(buf.to_vec()).map_err(|e| Error::from_reason(format!("utf8 error: {e}")))
}

#[napi]
pub async fn decrypt_string_async(partition_id: String, drr: String) -> Result<String> {
    let buf = decrypt_async(partition_id, Buffer::from(drr.into_bytes())).await?;
    String::from_utf8(buf.to_vec()).map_err(|e| Error::from_reason(format!("utf8 error: {e}")))
}

// ── Factory/Session API ─────────────────────────────────────────────

#[napi]
pub struct SessionFactory {
    factory: Mutex<Option<Factory>>,
}

impl std::fmt::Debug for SessionFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionFactory")
            .field("open", &self.factory.lock().is_some())
            .finish()
    }
}

#[napi]
impl SessionFactory {
    #[napi(constructor)]
    pub fn new(config: AsherahConfig) -> Result<Self> {
        let opts = to_config_options(&config);
        let (factory, _applied) = asherah_config::factory_from_config(&opts)
            .map_err(|e| Error::from_reason(format!("factory creation failed: {e}")))?;
        // Always enable per-factory metrics — see comment in setup().
        let factory = factory.with_metrics(true);
        Ok(Self {
            factory: Mutex::new(Some(factory)),
        })
    }

    #[napi(factory)]
    pub fn from_env() -> Result<Self> {
        let opts = asherah_config::ConfigOptions::default();
        let (factory, _applied) = asherah_config::factory_from_config(&opts)
            .map_err(|e| Error::from_reason(format!("factory_from_env failed: {e}")))?;
        let factory = factory.with_metrics(true);
        Ok(Self {
            factory: Mutex::new(Some(factory)),
        })
    }

    #[napi]
    pub fn get_session(&self, partition_id: String) -> Result<AsherahSession> {
        let guard = self.factory.lock();
        let factory = guard
            .as_ref()
            .ok_or_else(|| Error::from_reason("factory is closed"))?;
        let session = factory.get_session(&partition_id);
        Ok(AsherahSession {
            session: Mutex::new(Some(session)),
        })
    }

    #[napi]
    pub fn close(&self) -> Result<()> {
        let mut guard = self.factory.lock();
        if let Some(factory) = guard.take() {
            factory
                .close()
                .map_err(|e| Error::from_reason(format!("factory close error: {e:#}")))?;
        }
        Ok(())
    }
}

#[napi]
pub struct AsherahSession {
    session: Mutex<Option<Session>>,
}

impl std::fmt::Debug for AsherahSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsherahSession")
            .field("open", &self.session.lock().is_some())
            .finish()
    }
}

#[napi]
impl AsherahSession {
    #[napi]
    pub fn encrypt(&self, data: Buffer) -> Result<String> {
        let guard = self.session.lock();
        let session = guard
            .as_ref()
            .ok_or_else(|| Error::from_reason("session is closed"))?;
        let drr = session
            .encrypt(&data)
            .map_err(|e| Error::from_reason(format!("encrypt error: {e:#}")))?;
        Ok(drr.to_json_fast())
    }

    #[napi]
    pub fn encrypt_string(&self, data: String) -> Result<String> {
        self.encrypt(Buffer::from(data.into_bytes()))
    }

    #[napi]
    pub fn decrypt(&self, data_row_record: String) -> Result<Buffer> {
        let drr: asherah::types::DataRowRecord = serde_json::from_str(&data_row_record)
            .map_err(|e| Error::from_reason(format!("invalid DataRowRecord JSON: {e}")))?;
        let guard = self.session.lock();
        let session = guard
            .as_ref()
            .ok_or_else(|| Error::from_reason("session is closed"))?;
        let pt = session
            .decrypt(drr)
            .map_err(|e| Error::from_reason(format!("decrypt error: {e:#}")))?;
        Ok(Buffer::from(pt))
    }

    #[napi]
    pub fn decrypt_string(&self, data_row_record: String) -> Result<String> {
        let buf = self.decrypt(data_row_record)?;
        String::from_utf8(buf.to_vec()).map_err(|e| Error::from_reason(format!("utf8 error: {e}")))
    }

    #[napi]
    pub fn close(&self) -> Result<()> {
        let mut guard = self.session.lock();
        if let Some(session) = guard.take() {
            session
                .close()
                .map_err(|e| Error::from_reason(format!("session close error: {e:#}")))?;
        }
        Ok(())
    }
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
    ThreadsafeFunction<MetricsEvent, Unknown<'static>, JsArgList, Status, false, false, 0>;

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
        let status = self
            .tsfn
            .call(event, ThreadsafeFunctionCallMode::NonBlocking);
        if status != napi::Status::Ok {
            log::warn!("metrics hook: failed to enqueue event: {status:?}");
        }
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

    fn cache_stale(&self, name: &str) {
        self.emit("cache_stale", None, Some(name.to_string()));
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
            .callee_handled::<false>()
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
        // Metrics are gated for performance; enable them when a hook is
        // installed and disable them when it is cleared.
        metrics::set_enabled(true);
        *METRICS_HOOK.lock() = Some(MetricsHook {
            _tsfn: arc,
            _reference: reference,
        });
    } else {
        metrics::clear_sink();
        metrics::set_enabled(false);
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
    ThreadsafeFunction<LogEvent, Unknown<'static>, JsArgList, Status, false, false, 0>;

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
        let status = self
            .tsfn
            .call(event, ThreadsafeFunctionCallMode::NonBlocking);
        if status != napi::Status::Ok {
            log::warn!("log hook: failed to enqueue event: {status:?}");
        }
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
            .callee_handled::<false>()
            .build_callback(|ctx: ThreadsafeCallContext<LogEvent>| {
                let env = ctx.env;
                let LogEvent {
                    level,
                    message,
                    target,
                } = ctx.value;
                let mut obj = Object::new(&env)?;
                // Lowercase for the documented LogEvent.level union type
                // ("trace" | "debug" | "info" | "warn" | "error").
                let level_str = match level {
                    log::Level::Error => "error",
                    log::Level::Warn => "warn",
                    log::Level::Info => "info",
                    log::Level::Debug => "debug",
                    log::Level::Trace => "trace",
                };
                obj.set("level", env.create_string(level_str)?)?;
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
