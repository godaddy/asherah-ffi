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

use std::ffi::{CStr, CString};
use std::fmt;
use std::mem::ManuallyDrop;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr::null_mut;

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
#[repr(C)]
pub struct AsherahSession {
    inner: Session,
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
    LAST_ERROR.with(|c| {
        c.borrow()
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn asherah_factory_new_from_env() -> *mut AsherahFactory {
    match ael::builders::factory_from_env() {
        Ok(f) => Box::into_raw(Box::new(AsherahFactory { inner: f })),
        Err(e) => {
            set_error(format!("{}", e));
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
    match factory_from_config_json(config_json) {
        Ok((_factory, _applied)) => 0,
        Err(e) => {
            set_error(format!("{e}"));
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
    match factory_from_config_json(config_json) {
        Ok((factory, _applied)) => Box::into_raw(Box::new(AsherahFactory { inner: factory })),
        Err(e) => {
            set_error(format!("{e}"));
            null_mut()
        }
    }
}

/// # Safety
/// `ptr` must be a factory pointer previously obtained from this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_factory_free(ptr: *mut AsherahFactory) {
    if ptr.is_null() {
        return;
    }
    drop(Box::from_raw(ptr));
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
) -> *mut AsherahSession {
    if factory.is_null() {
        set_error("null factory");
        return null_mut();
    }
    let f = &*factory;
    let pid = match cstr_to_str(partition_id) {
        Ok(s) => s,
        Err(e) => {
            set_error(format!("{e}"));
            return null_mut();
        }
    };
    let s = f.inner.get_session(pid);
    Box::into_raw(Box::new(AsherahSession { inner: s }))
}

/// # Safety
/// `ptr` must be a session pointer previously obtained from this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_session_free(ptr: *mut AsherahSession) {
    if ptr.is_null() {
        return;
    }
    drop(Box::from_raw(ptr));
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
}

/// # Safety
/// `session` must be valid, `data` must reference `len` bytes, and `out` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_encrypt_to_json(
    session: *mut AsherahSession,
    data: *const u8,
    len: usize,
    out: *mut AsherahBuffer,
) -> c_int {
    if session.is_null() {
        set_error("null session");
        return -1;
    }
    if data.is_null() && len > 0 {
        set_error("null data");
        return -1;
    }
    let s = &*session;
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
            set_error(format!("{e}"));
            -1
        }
    }
}

/// # Safety
/// `session` must be valid, `json` must reference `len` bytes, and `out` must be non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_decrypt_from_json(
    session: *mut AsherahSession,
    json: *const u8,
    len: usize,
    out: *mut AsherahBuffer,
) -> c_int {
    if session.is_null() {
        set_error("null session");
        return -1;
    }
    if json.is_null() && len > 0 {
        set_error("null json");
        return -1;
    }
    let s = &*session;
    let bytes = if json.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(json, len)
    };
    match serde_json::from_slice::<ael::types::DataRowRecord>(bytes) {
        Ok(drr) => match s.inner.decrypt(drr) {
            Ok(pt) => take_vec_into_buffer(pt, out),
            Err(e) => {
                set_error(format!("{e}"));
                -1
            }
        },
        Err(e) => {
            set_error(format!("{e}"));
            -1
        }
    }
}

// ── Async FFI ────────────────────────────────────────────────────────
//
// Callback-based async API for languages that use C FFI (.NET, Ruby, Java).
// The callback is invoked on a tokio worker thread when the operation completes.
// The result buffer is valid only for the duration of the callback.

/// Send-safe wrapper for async FFI context. Converts all pointer types to usize
/// so the async task can be spawned on the tokio runtime. The caller guarantees
/// the session pointer remains valid until the callback fires.
struct AsyncContext {
    session: usize,
    callback: usize,
    user_data: usize,
}

// All fields are usize — trivially Send.
unsafe impl Send for AsyncContext {}

impl AsyncContext {
    fn new(
        session: *mut AsherahSession,
        callback: AsherahCompletionFn,
        user_data: *mut c_void,
    ) -> Self {
        Self {
            session: session as usize,
            callback: callback as usize,
            user_data: user_data as usize,
        }
    }

    /// Restore the session reference and callback. User data stays as usize
    /// until the callback call site to avoid holding a *mut c_void across await points.
    unsafe fn restore(&self) -> (&AsherahSession, AsherahCompletionFn, usize) {
        let session = &*(self.session as *const AsherahSession);
        let callback: AsherahCompletionFn = std::mem::transmute(self.callback);
        (session, callback, self.user_data)
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
/// `session` must be a valid session pointer that outlives the async operation.
/// `data` must reference `len` bytes. `callback` must be a valid function pointer.
/// `user_data` is passed through to the callback unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_encrypt_to_json_async(
    session: *mut AsherahSession,
    data: *const u8,
    len: usize,
    callback: AsherahCompletionFn,
    user_data: *mut c_void,
) -> c_int {
    if session.is_null() {
        set_error("null session");
        return -1;
    }
    if data.is_null() && len > 0 {
        set_error("null data");
        return -1;
    }
    // Copy input data — the caller's buffer may not outlive the async task.
    let input = if data.is_null() {
        Vec::new()
    } else {
        std::slice::from_raw_parts(data, len).to_vec()
    };
    spawn_encrypt_async(AsyncContext::new(session, callback, user_data), input);
    0
}

fn spawn_encrypt_async(ctx: AsyncContext, input: Vec<u8>) {
    ASYNC_RT.spawn(async move {
        let (session_ref, cb, ud) = unsafe { ctx.restore() };
        match session_ref.inner.encrypt_async(&input).await {
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
        let (session_ref, cb, ud) = unsafe { ctx.restore() };
        let drr = match serde_json::from_slice::<ael::types::DataRowRecord>(&input) {
            Ok(d) => d,
            Err(e) => {
                let msg = CString::new(format!("invalid DataRowRecord JSON: {e}"))
                    .unwrap_or_else(|_| c"json parse error".into());
                unsafe { cb(ud as *mut c_void, std::ptr::null(), 0, msg.as_ptr()) };
                return;
            }
        };
        match session_ref.inner.decrypt_async(drr).await {
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
/// `session` must be a valid session pointer that outlives the async operation.
/// `json` must reference `len` bytes. `callback` must be a valid function pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn asherah_decrypt_from_json_async(
    session: *mut AsherahSession,
    json: *const u8,
    len: usize,
    callback: AsherahCompletionFn,
    user_data: *mut c_void,
) -> c_int {
    if session.is_null() {
        set_error("null session");
        return -1;
    }
    if json.is_null() && len > 0 {
        set_error("null json");
        return -1;
    }
    let input = if json.is_null() {
        Vec::new()
    } else {
        std::slice::from_raw_parts(json, len).to_vec()
    };
    spawn_decrypt_async(AsyncContext::new(session, callback, user_data), input);
    0
}
