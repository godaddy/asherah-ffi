//! # Asherah FFI
//!
//! C ABI wrapper for the Asherah encryption library, providing the foreign
//! function interface consumed by language bindings (.NET, Ruby, Go).
//! Uses the Cobhan buffer format for cross-language data exchange.

#![allow(unsafe_code)]

// Link in asherah-cobhan to export its Cobhan-compatible symbols
// (SetupJson, Shutdown, SetEnv, EstimateBuffer, Encrypt, Decrypt,
// EncryptToJson, DecryptFromJson) from this shared library.
#[allow(unused_extern_crates)]
extern crate asherah_cobhan;

mod hooks;
pub use hooks::{
    asherah_clear_log_hook, asherah_clear_metrics_hook, asherah_set_log_hook,
    asherah_set_metrics_hook, AsherahLogCallback, AsherahMetricsCallback, ASHERAH_LOG_DEBUG,
    ASHERAH_LOG_ERROR, ASHERAH_LOG_INFO, ASHERAH_LOG_TRACE, ASHERAH_LOG_WARN,
    ASHERAH_METRIC_CACHE_HIT, ASHERAH_METRIC_CACHE_MISS, ASHERAH_METRIC_CACHE_STALE,
    ASHERAH_METRIC_DECRYPT, ASHERAH_METRIC_ENCRYPT, ASHERAH_METRIC_LOAD, ASHERAH_METRIC_STORE,
};

use std::ffi::{CStr, CString};
use std::fmt;
use std::mem::ManuallyDrop;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr::null_mut;
use std::sync::Arc;

use asherah as ael;
use asherah_config as config;
use once_cell::sync::Lazy;

type Factory = ael::session::PublicFactory<
    ael::aead::AES256GCM,
    ael::builders::DynKms,
    ael::builders::DynMetastore,
>;
type Session = ael::session::PublicSession<
    ael::aead::AES256GCM,
    ael::builders::DynKms,
    ael::builders::DynMetastore,
>;

#[repr(C)]
#[derive(Debug)]
pub struct AsherahBuffer {
    pub data: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

#[repr(C)]
pub struct AsherahFactory {
    inner: Factory,
}
pub struct AsherahSession {
    inner: Session,
}

/// Shared session handle returned to FFI callers. Wraps `Arc<AsherahSession>`
/// so async tasks can hold an owned reference that outlives a premature free.
pub struct SharedSession {
    session: Arc<AsherahSession>,
}

impl fmt::Debug for AsherahFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AsherahFactory { .. }")
    }
}

impl fmt::Debug for AsherahSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AsherahSession { .. }")
    }
}

impl fmt::Debug for SharedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSession { .. }")
    }
}

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

fn set_error(msg: impl Into<String>) {
    LAST_ERROR.with(|c| {
        let message = msg.into();
        let cstring =
            CString::new(message).unwrap_or_else(|_| CString::new("error").expect("static string"));
        *c.borrow_mut() = Some(cstring);
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn asherah_last_error_message() -> *const c_char {
    match std::panic::catch_unwind(|| {
        LAST_ERROR.with(|c| {
            c.borrow()
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null())
        })
    }) {
        Ok(result) => result,
        Err(_) => std::ptr::null(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn asherah_factory_new_from_env() -> *mut AsherahFactory {
    match std::panic::catch_unwind(|| match ael::builders::factory_from_env() {
        // Always enable per-factory metrics so an installed metrics hook
        // (asherah_set_metrics_hook) actually fires for encrypt/decrypt/
        // store/load events. The cost is one Instant::now() per encrypt
        // regardless of hook state; the global metrics gate (toggled by
        // asherah_set_metrics_hook) decides whether the sink is invoked.
        Ok(f) => Box::into_raw(Box::new(AsherahFactory {
            inner: f.with_metrics(true),
        })),
        Err(e) => {
            set_error(format!("{e:#}"));
            null_mut()
        }
    }) {
        Ok(result) => result,
        Err(_) => {
            set_error("internal panic in asherah_factory_new_from_env");
            null_mut()
        }
    }
}

fn factory_from_config_json(
    config_json: *const c_char,
) -> Result<(Factory, config::AppliedConfig), anyhow::Error> {
    let cfg_str = unsafe { cstr_to_str(config_json)? };
    let cfg = config::ConfigOptions::from_json(cfg_str)?;
    config::factory_from_config(&cfg)
}

/// # Safety
/// `config_json` must point to a valid, null-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_apply_config_json(config_json: *const c_char) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || match factory_from_config_json(config_json) {
            Ok((_factory, _applied)) => 0,
            Err(e) => {
                set_error(format!("{e:#}"));
                -1
            }
        },
    )) {
        Ok(result) => result,
        Err(_) => {
            set_error("internal panic in asherah_apply_config_json");
            -1
        }
    }
}

/// # Safety
/// `config_json` must point to a valid, null-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_factory_new_with_config(
    config_json: *const c_char,
) -> *mut AsherahFactory {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || match factory_from_config_json(config_json) {
            // Always enable per-factory metrics — see comment in
            // asherah_factory_new_from_env.
            Ok((factory, _applied)) => Box::into_raw(Box::new(AsherahFactory {
                inner: factory.with_metrics(true),
            })),
            Err(e) => {
                set_error(format!("{e:#}"));
                null_mut()
            }
        },
    )) {
        Ok(result) => result,
        Err(_) => {
            set_error("internal panic in asherah_factory_new_with_config");
            null_mut()
        }
    }
}

/// # Safety
/// `ptr` must be a factory pointer previously obtained from this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_factory_free(ptr: *mut AsherahFactory) {
    drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || {
            if ptr.is_null() {
                return;
            }
            drop(Box::from_raw(ptr));
        },
    )));
}

/// # Safety
/// `s` must point to a valid null-terminated C string that remains valid for the
/// returned reference's lifetime.
unsafe fn cstr_to_str<'ptr>(s: *const c_char) -> Result<&'ptr str, anyhow::Error> {
    if s.is_null() {
        return Err(anyhow::anyhow!("null string"));
    }
    Ok(CStr::from_ptr(s).to_str()?)
}

/// # Safety
/// `factory` must be a valid factory pointer and `partition_id` a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_factory_get_session(
    factory: *mut AsherahFactory,
    partition_id: *const c_char,
) -> *mut SharedSession {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if factory.is_null() {
            set_error("null factory");
            return null_mut();
        }
        let f = &*factory;
        let pid = match cstr_to_str(partition_id) {
            Ok(s) => s,
            Err(e) => {
                set_error(format!("{e:#}"));
                return null_mut();
            }
        };
        let s = f.inner.get_session(pid);
        let shared = SharedSession {
            session: Arc::new(AsherahSession { inner: s }),
        };
        Box::into_raw(Box::new(shared))
    })) {
        Ok(result) => result,
        Err(_) => {
            set_error("internal panic in asherah_factory_get_session");
            null_mut()
        }
    }
}

/// # Safety
/// `ptr` must be a session pointer previously obtained from this module.
/// If async operations still hold an `Arc` clone, the underlying session
/// remains alive until those operations complete.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_session_free(ptr: *mut SharedSession) {
    drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || {
            if ptr.is_null() {
                return;
            }
            drop(Box::from_raw(ptr));
        },
    )));
}

fn take_vec_into_buffer(v: Vec<u8>, out: *mut AsherahBuffer) -> c_int {
    if out.is_null() {
        set_error("null output buffer");
        return -1;
    }
    let mut v = ManuallyDrop::new(v);
    let buf = AsherahBuffer {
        data: v.as_mut_ptr(),
        len: v.len(),
        capacity: v.capacity(),
    };
    unsafe {
        *out = buf;
    }
    0
}

/// # Safety
/// `buf` must point to a valid `AsherahBuffer` initialized by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_buffer_free(buf: *mut AsherahBuffer) {
    drop(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || {
            if buf.is_null() {
                return;
            }
            let b = &mut *buf;
            if !b.data.is_null() && b.capacity > 0 {
                drop(Vec::from_raw_parts(b.data, b.len, b.capacity));
            }
            b.data = null_mut();
            b.len = 0;
            b.capacity = 0;
        },
    )));
}

/// # Safety
/// `session` must be valid, `data` must reference `len` bytes, and `out` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_encrypt_to_json(
    session: *mut SharedSession,
    data: *const u8,
    len: usize,
    out: *mut AsherahBuffer,
) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if session.is_null() {
            set_error("null session");
            return -1;
        }
        if data.is_null() && len > 0 {
            set_error("null data");
            return -1;
        }
        let s = &(*session).session;
        let bytes = if data.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(data, len)
        };
        match s.inner.encrypt(bytes) {
            Ok(drr) => {
                let v = drr.to_json_fast().into_bytes();
                take_vec_into_buffer(v, out)
            }
            Err(e) => {
                set_error(format!("{e:#}"));
                -1
            }
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            set_error("internal panic in asherah_encrypt_to_json");
            -1
        }
    }
}

/// # Safety
/// `session` must be valid, `json` must reference `len` bytes, and `out` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_decrypt_from_json(
    session: *mut SharedSession,
    json: *const u8,
    len: usize,
    out: *mut AsherahBuffer,
) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if session.is_null() {
            set_error("null session");
            return -1;
        }
        if json.is_null() && len > 0 {
            set_error("null json");
            return -1;
        }
        let s = &(*session).session;
        let bytes = if json.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(json, len)
        };
        match serde_json::from_slice::<ael::types::DataRowRecord>(bytes) {
            Ok(drr) => match s.inner.decrypt(drr) {
                Ok(pt) => take_vec_into_buffer(pt, out),
                Err(e) => {
                    set_error(format!("{e:#}"));
                    -1
                }
            },
            Err(e) => {
                set_error(format!("{e:#}"));
                -1
            }
        }
    })) {
        Ok(result) => result,
        Err(_) => {
            set_error("internal panic in asherah_decrypt_from_json");
            -1
        }
    }
}

// ── Async FFI ────────────────────────────────────────────────────────
//
// Callback-based async API for languages that use C FFI (.NET, Ruby, Java).
// The callback is invoked on a tokio worker thread when the operation completes.
// The result buffer is valid only for the duration of the callback.

/// Async FFI context. Holds an `Arc` clone of the session so the underlying
/// session cannot be freed while the tokio task is in flight.
struct AsyncContext {
    session: Arc<AsherahSession>,
    callback: usize,
    user_data: usize,
}

// callback and user_data are just integers (function pointer and opaque pointer
// cast to usize). Arc<AsherahSession> is Send. So AsyncContext is Send.
unsafe impl Send for AsyncContext {}

impl AsyncContext {
    fn new(
        session: Arc<AsherahSession>,
        callback: AsherahCompletionFn,
        user_data: *mut c_void,
    ) -> Self {
        Self {
            session,
            callback: callback as usize,
            user_data: user_data as usize,
        }
    }

    /// Restore the callback function pointer and user data for invocation.
    unsafe fn restore_callback(&self) -> (AsherahCompletionFn, usize) {
        let callback: AsherahCompletionFn = std::mem::transmute(self.callback);
        (callback, self.user_data)
    }
}

/// Shared tokio runtime for async FFI operations.
static ASYNC_RT: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("asherah-async-ffi")
        .enable_all()
        .build()
        .expect("failed to create async FFI tokio runtime")
});

/// Completion callback type for async operations.
/// - `user_data`: opaque pointer passed through from the async call.
/// - `result_data`/`result_len`: output bytes on success (NULL/0 on error).
/// - `error_message`: null-terminated UTF-8 error string on failure (NULL on success).
///
/// The callback runs on a tokio worker thread. Do not block in the callback.
/// The result buffer is freed after the callback returns — copy it if needed.
pub type AsherahCompletionFn = unsafe extern "C" fn(
    user_data: *mut c_void,
    result_data: *const u8,
    result_len: usize,
    error_message: *const c_char,
);

/// # Safety
/// `session` must be a valid session pointer. The session is kept alive by an
/// internal `Arc` clone until the async operation completes — callers may free
/// their handle before the callback fires.
/// `data` must reference `len` bytes. `callback` must be a valid function pointer.
/// `user_data` is passed through to the callback unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_encrypt_to_json_async(
    session: *mut SharedSession,
    data: *const u8,
    len: usize,
    callback: AsherahCompletionFn,
    user_data: *mut c_void,
) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if session.is_null() {
            set_error("null session");
            return -1;
        }
        if data.is_null() && len > 0 {
            set_error("null data");
            return -1;
        }
        // Clone the Arc so the session outlives a premature free.
        let arc = Arc::clone(&(*session).session);
        // Copy input data — the caller's buffer may not outlive the async task.
        let input = if data.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data, len).to_vec()
        };
        spawn_encrypt_async(AsyncContext::new(arc, callback, user_data), input);
        0
    })) {
        Ok(result) => result,
        Err(_) => {
            set_error("internal panic in asherah_encrypt_to_json_async");
            -1
        }
    }
}

fn spawn_encrypt_async(ctx: AsyncContext, input: Vec<u8>) {
    ASYNC_RT.spawn(async move {
        let (cb, ud) = unsafe { ctx.restore_callback() };
        match ctx.session.inner.encrypt_async(&input).await {
            Ok(drr) => {
                let json = drr.to_json_fast();
                let bytes = json.as_bytes();
                unsafe {
                    cb(
                        ud as *mut c_void,
                        bytes.as_ptr(),
                        bytes.len(),
                        std::ptr::null(),
                    )
                };
            }
            Err(e) => {
                let msg =
                    CString::new(e.to_string()).unwrap_or_else(|_| c"async encrypt error".into());
                unsafe { cb(ud as *mut c_void, std::ptr::null(), 0, msg.as_ptr()) };
            }
        }
    });
}

fn spawn_decrypt_async(ctx: AsyncContext, input: Vec<u8>) {
    ASYNC_RT.spawn(async move {
        let (cb, ud) = unsafe { ctx.restore_callback() };
        let drr = match serde_json::from_slice::<ael::types::DataRowRecord>(&input) {
            Ok(d) => d,
            Err(e) => {
                let msg = CString::new(format!("invalid DataRowRecord JSON: {e}"))
                    .unwrap_or_else(|_| c"json parse error".into());
                unsafe { cb(ud as *mut c_void, std::ptr::null(), 0, msg.as_ptr()) };
                return;
            }
        };
        match ctx.session.inner.decrypt_async(drr).await {
            Ok(pt) => {
                unsafe { cb(ud as *mut c_void, pt.as_ptr(), pt.len(), std::ptr::null()) };
            }
            Err(e) => {
                let msg =
                    CString::new(e.to_string()).unwrap_or_else(|_| c"async decrypt error".into());
                unsafe { cb(ud as *mut c_void, std::ptr::null(), 0, msg.as_ptr()) };
            }
        }
    });
}

/// # Safety
/// `session` must be a valid session pointer. The session is kept alive by an
/// internal `Arc` clone until the async operation completes.
/// `json` must reference `len` bytes. `callback` must be a valid function pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_decrypt_from_json_async(
    session: *mut SharedSession,
    json: *const u8,
    len: usize,
    callback: AsherahCompletionFn,
    user_data: *mut c_void,
) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if session.is_null() {
            set_error("null session");
            return -1;
        }
        if json.is_null() && len > 0 {
            set_error("null json");
            return -1;
        }
        let arc = Arc::clone(&(*session).session);
        let input = if json.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(json, len).to_vec()
        };
        spawn_decrypt_async(AsyncContext::new(arc, callback, user_data), input);
        0
    })) {
        Ok(result) => result,
        Err(_) => {
            set_error("internal panic in asherah_decrypt_from_json_async");
            -1
        }
    }
}

#[cfg(test)]
#[allow(unsafe_code, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr::null;

    #[test]
    fn null_factory_free_does_not_crash() {
        unsafe { asherah_factory_free(null_mut()) };
    }

    #[test]
    fn null_session_free_does_not_crash() {
        unsafe { asherah_session_free(null_mut()) };
    }

    #[test]
    fn null_buffer_free_does_not_crash() {
        unsafe { asherah_buffer_free(null_mut()) };
    }

    #[test]
    fn null_factory_get_session_returns_null() {
        let partition = CString::new("test").unwrap();
        let result = unsafe { asherah_factory_get_session(null_mut(), partition.as_ptr()) };
        assert!(result.is_null());
    }

    #[test]
    fn encrypt_with_null_session_returns_error() {
        let data = b"test";
        let result =
            unsafe { asherah_encrypt_to_json(null_mut(), data.as_ptr(), data.len(), null_mut()) };
        assert!(result != 0);
    }

    #[test]
    fn decrypt_with_null_session_returns_error() {
        let json = b"{}";
        let result =
            unsafe { asherah_decrypt_from_json(null_mut(), json.as_ptr(), json.len(), null_mut()) };
        assert!(result != 0);
    }

    #[test]
    fn invalid_config_returns_null_factory() {
        let bad = CString::new("not json").unwrap();
        let result = unsafe { asherah_factory_new_with_config(bad.as_ptr()) };
        assert!(result.is_null());
    }

    #[test]
    fn null_config_returns_null_factory() {
        let result = unsafe { asherah_factory_new_with_config(null()) };
        assert!(result.is_null());
    }

    fn make_factory_and_session() -> (*mut AsherahFactory, *mut SharedSession) {
        let cfg = CString::new(
            r#"{
                "ServiceName": "test-service",
                "ProductID": "test-product",
                "Metastore": "memory",
                "KMS": "static",
                "EnableSessionCaching": false
            }"#,
        )
        .unwrap();
        let factory = unsafe { asherah_factory_new_with_config(cfg.as_ptr()) };
        assert!(!factory.is_null(), "factory creation failed");
        let pid = CString::new("partition-1").unwrap();
        let session = unsafe { asherah_factory_get_session(factory, pid.as_ptr()) };
        assert!(!session.is_null(), "session creation failed");
        (factory, session)
    }

    fn free_factory_and_session(factory: *mut AsherahFactory, session: *mut SharedSession) {
        unsafe {
            asherah_session_free(session);
            asherah_factory_free(factory);
        }
    }

    fn empty_buffer() -> AsherahBuffer {
        AsherahBuffer {
            data: null_mut(),
            len: 0,
            capacity: 0,
        }
    }

    #[test]
    fn encrypt_null_data_zero_len_succeeds() {
        // Allowed: null pointer with len=0 is treated as empty plaintext.
        let (factory, session) = make_factory_and_session();
        let mut out = empty_buffer();
        let rc = unsafe { asherah_encrypt_to_json(session, null(), 0, &mut out) };
        assert_eq!(rc, 0, "encrypt empty should succeed");
        assert!(!out.data.is_null());
        assert!(out.len > 0, "encrypted JSON should be non-empty");
        unsafe { asherah_buffer_free(&mut out) };
        free_factory_and_session(factory, session);
    }

    #[test]
    fn encrypt_null_data_nonzero_len_returns_error() {
        let (factory, session) = make_factory_and_session();
        let mut out = empty_buffer();
        let rc = unsafe { asherah_encrypt_to_json(session, null(), 4, &mut out) };
        assert_ne!(rc, 0, "null data with len>0 must fail");
        free_factory_and_session(factory, session);
    }

    #[test]
    fn decrypt_null_json_nonzero_len_returns_error() {
        let (factory, session) = make_factory_and_session();
        let mut out = empty_buffer();
        let rc = unsafe { asherah_decrypt_from_json(session, null(), 4, &mut out) };
        assert_ne!(rc, 0, "null json with len>0 must fail");
        free_factory_and_session(factory, session);
    }

    #[test]
    fn decrypt_empty_json_returns_error() {
        // Empty input is not valid DataRowRecord JSON — must be rejected.
        let (factory, session) = make_factory_and_session();
        let mut out = empty_buffer();
        let rc = unsafe { asherah_decrypt_from_json(session, null(), 0, &mut out) };
        assert_ne!(rc, 0, "empty json must be rejected as invalid");
        free_factory_and_session(factory, session);
    }

    #[test]
    fn encrypt_empty_then_decrypt_round_trip() {
        // Empty plaintext must round-trip through encrypt/decrypt to empty bytes.
        let (factory, session) = make_factory_and_session();

        let mut ct = empty_buffer();
        let empty: [u8; 0] = [];
        let rc = unsafe { asherah_encrypt_to_json(session, empty.as_ptr(), 0, &mut ct) };
        assert_eq!(rc, 0);
        assert!(ct.len > 0);

        let mut pt = empty_buffer();
        let rc = unsafe { asherah_decrypt_from_json(session, ct.data, ct.len, &mut pt) };
        assert_eq!(rc, 0);
        assert_eq!(pt.len, 0, "decrypt of empty-encrypt must be empty");

        unsafe {
            asherah_buffer_free(&mut ct);
            asherah_buffer_free(&mut pt);
        }
        free_factory_and_session(factory, session);
    }
}
