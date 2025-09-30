use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr::null_mut;

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
}

thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<CString>> = const { std::cell::RefCell::new(None) };
}

fn set_error(msg: impl Into<String>) {
    LAST_ERROR.with(|c| {
        *c.borrow_mut() =
            Some(CString::new(msg.into()).unwrap_or_else(|_| CString::new("error").unwrap()));
    });
}

#[no_mangle]
pub extern "C" fn asherah_last_error_message() -> *const c_char {
    LAST_ERROR.with(|c| {
        c.borrow()
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(std::ptr::null())
    })
}

#[no_mangle]
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
#[no_mangle]
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
#[no_mangle]
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
#[no_mangle]
pub unsafe extern "C" fn asherah_factory_free(ptr: *mut AsherahFactory) {
    if ptr.is_null() {
        return;
    }
    drop(Box::from_raw(ptr));
}

unsafe fn cstr_to_str<'a>(s: *const c_char) -> Result<&'a str, anyhow::Error> {
    if s.is_null() {
        return Err(anyhow::anyhow!("null string"));
    }
    Ok(CStr::from_ptr(s).to_str()?)
}

/// # Safety
/// `factory` must be a valid factory pointer and `partition_id` a valid C string.
#[no_mangle]
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
#[no_mangle]
pub unsafe extern "C" fn asherah_session_free(ptr: *mut AsherahSession) {
    if ptr.is_null() {
        return;
    }
    drop(Box::from_raw(ptr));
}

fn take_vec_into_buffer(mut v: Vec<u8>, out: *mut AsherahBuffer) -> c_int {
    let buf = AsherahBuffer {
        data: v.as_mut_ptr(),
        len: v.len(),
    };
    std::mem::forget(v);
    unsafe {
        *out = buf;
    }
    0
}

/// # Safety
/// `buf` must point to a valid `AsherahBuffer` initialized by this library.
#[no_mangle]
pub unsafe extern "C" fn asherah_buffer_free(buf: *mut AsherahBuffer) {
    if buf.is_null() {
        return;
    }
    let b = &mut *buf;
    if !b.data.is_null() && b.len > 0 {
        let _ = Vec::from_raw_parts(b.data, b.len, b.len);
    }
    b.data = std::ptr::null_mut();
    b.len = 0;
}

/// # Safety
/// `session` must be valid, `data` must reference `len` bytes, and `out` must be non-null.
#[no_mangle]
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
    let bytes = std::slice::from_raw_parts(data, len);
    match s.inner.encrypt(bytes) {
        Ok(drr) => match serde_json::to_vec(&drr) {
            Ok(v) => take_vec_into_buffer(v, out),
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

/// # Safety
/// `session` must be valid, `json` must reference `len` bytes, and `out` must be non-null.
#[no_mangle]
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
    let bytes = std::slice::from_raw_parts(json, len);
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
