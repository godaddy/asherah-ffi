#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::fmt;
use std::mem::ManuallyDrop;
use std::os::raw::{c_char, c_int};
use std::ptr::null_mut;
use std::sync::Mutex;

use asherah as ael;
use asherah_config as config;

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
}

#[repr(C)]
pub struct AsherahFactory {
    inner: Factory,
}
#[repr(C)]
pub struct AsherahSession {
    inner: Session,
    last_error: Mutex<LastError>,
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
    static LAST_ERROR_CODE: std::cell::RefCell<c_int> = const { std::cell::RefCell::new(0) };
}

const ERR_NONE: c_int = 0;
const ERR_NULL_PTR: c_int = 1;
const ERR_INVALID_INPUT: c_int = 2;
const ERR_CONFIG: c_int = 3;
const ERR_JSON: c_int = 4;
const ERR_CRYPTO: c_int = 5;
const ERR_KMS: c_int = 6;
const ERR_METADATA: c_int = 7;
const ERR_METASTORE: c_int = 8;

#[derive(Default)]
struct LastError {
    code: c_int,
    message: Option<CString>,
}

fn classify_error(message: &str, fallback: c_int) -> c_int {
    let lower = message.to_lowercase();
    if lower.contains("metadata missing")
        || lower.contains("system key not found")
        || lower.contains("latest not found")
    {
        return ERR_METADATA;
    }
    if lower.contains("kms") {
        return ERR_KMS;
    }
    if lower.contains("metastore") {
        return ERR_METASTORE;
    }
    fallback
}

fn set_error(code: c_int, msg: impl Into<String>) {
    LAST_ERROR.with(|c| {
        let message = msg.into();
        let cstring =
            CString::new(message).unwrap_or_else(|_| CString::new("error").expect("static string"));
        *c.borrow_mut() = Some(cstring);
    });
    LAST_ERROR_CODE.with(|c| {
        *c.borrow_mut() = code;
    });
}

fn set_session_error(session: &AsherahSession, code: c_int, msg: impl Into<String>) {
    let message_str = msg.into();
    set_error(code, message_str.clone());
    let cstring =
        CString::new(message_str).unwrap_or_else(|_| CString::new("error").expect("static string"));
    let mut guard = session
        .last_error
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    guard.code = code;
    guard.message = Some(cstring);
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
pub extern "C" fn asherah_last_error_code() -> c_int {
    LAST_ERROR_CODE.with(|c| *c.borrow())
}

#[unsafe(no_mangle)]
pub extern "C" fn asherah_session_last_error_message(
    session: *mut AsherahSession,
) -> *const c_char {
    if session.is_null() {
        return std::ptr::null();
    }
    let s = unsafe { &*session };
    let guard = s
        .last_error
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    guard
        .message
        .as_ref()
        .map(|c| c.as_ptr())
        .unwrap_or(std::ptr::null())
}

#[unsafe(no_mangle)]
pub extern "C" fn asherah_session_last_error_code(session: *mut AsherahSession) -> c_int {
    if session.is_null() {
        return 0;
    }
    let s = unsafe { &*session };
    let guard = s
        .last_error
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    guard.code
}

#[unsafe(no_mangle)]
pub extern "C" fn asherah_factory_new_from_env() -> *mut AsherahFactory {
    match ael::builders::factory_from_env() {
        Ok(f) => Box::into_raw(Box::new(AsherahFactory { inner: f })),
        Err(e) => {
            set_error(ERR_CONFIG, format!("{}", e));
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
        Ok((_factory, _applied)) => ERR_NONE,
        Err(e) => {
            set_error(ERR_CONFIG, format!("{e}"));
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
            set_error(ERR_CONFIG, format!("{e}"));
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

unsafe fn cstr_to_str<'str>(s: *const c_char) -> Result<&'str str, anyhow::Error> {
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
        set_error(ERR_NULL_PTR, "null factory");
        return null_mut();
    }
    let f = &*factory;
    let pid = match cstr_to_str(partition_id) {
        Ok(s) => s,
        Err(e) => {
            set_error(ERR_INVALID_INPUT, format!("{e}"));
            return null_mut();
        }
    };
    let s = f.inner.get_session(pid);
    Box::into_raw(Box::new(AsherahSession {
        inner: s,
        last_error: Mutex::new(LastError::default()),
    }))
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
    let mut v = ManuallyDrop::new(v);
    let buf = AsherahBuffer {
        data: v.as_mut_ptr(),
        len: v.len(),
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
    if !b.data.is_null() && b.len > 0 {
        drop(Vec::from_raw_parts(b.data, b.len, b.len));
    }
    b.data = null_mut();
    b.len = 0;
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
        set_error(ERR_NULL_PTR, "null session");
        return -1;
    }
    if data.is_null() && len > 0 {
        set_error(ERR_NULL_PTR, "null data");
        return -1;
    }
    let s = &*session;
    let bytes = std::slice::from_raw_parts(data, len);
    match s.inner.encrypt(bytes) {
        Ok(drr) => match serde_json::to_vec(&drr) {
            Ok(v) => take_vec_into_buffer(v, out),
            Err(e) => {
                set_session_error(s, ERR_JSON, format!("{e}"));
                -1
            }
        },
        Err(e) => {
            let msg = format!("{e}");
            let code = classify_error(&msg, ERR_CRYPTO);
            set_session_error(s, code, msg);
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
        set_error(ERR_NULL_PTR, "null session");
        return -1;
    }
    if json.is_null() && len > 0 {
        set_error(ERR_NULL_PTR, "null json");
        return -1;
    }
    let s = &*session;
    let bytes = std::slice::from_raw_parts(json, len);
    match serde_json::from_slice::<ael::types::DataRowRecord>(bytes) {
        Ok(drr) => match s.inner.decrypt(drr) {
            Ok(pt) => take_vec_into_buffer(pt, out),
            Err(e) => {
                let msg = format!("{e}");
                let code = classify_error(&msg, ERR_CRYPTO);
                set_session_error(s, code, msg);
                -1
            }
        },
        Err(e) => {
            set_session_error(s, ERR_JSON, format!("{e}"));
            -1
        }
    }
}
