#![allow(unsafe_code)]
#![deny(clippy::all)]
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

use napi::bindgen_prelude::*;
// Log hook temporarily disabled for performance testing; add debug timers
use napi_derive::napi;
use once_cell::sync::Lazy;
use std::time::Instant;

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
        eprintln!("[asherah-node] {msg}");
    }
}

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
        eprintln!(
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

    let mut guard = STATE.lock().unwrap();
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
    let mut guard = STATE.lock().unwrap();
    if let Some(mut state) = guard.take() {
        for (_, session) in state.sessions.drain() {
            let _ = session.close();
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
    let mut guard = STATE.lock().unwrap();
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
        (Ok(_), Err(e)) => Err(e),
        (Err(e), Ok(())) => Err(e),
        (Err(e), Err(close_err)) => {
            debug_log(&format!("error closing session after failure: {close_err}"));
            Err(e)
        }
    }
}

#[napi]
pub fn get_setup_status() -> bool {
    STATE.lock().unwrap().is_some()
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

// Stub log hook (no-op). Could be wired to asherah metrics sink later.
#[napi]
pub fn set_log_hook(_hook: Function) -> Result<()> {
    Ok(())
}
