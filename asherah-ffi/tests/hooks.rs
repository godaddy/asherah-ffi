//! Integration tests for the C ABI log/metrics hooks.
//!
//! These live in their own test binary so they don't race against the
//! lib's unit tests (which call `metrics::record_*` indirectly via the
//! encrypt/decrypt path and would fire any installed metrics hook).

#![allow(unsafe_code, clippy::unwrap_used, clippy::expect_used)]

use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering as AtomOrd};
use std::sync::Mutex;
use std::time::Duration;

use asherah::metrics;
use asherah_ffi::{
    asherah_clear_log_hook, asherah_clear_metrics_hook, asherah_set_log_hook,
    asherah_set_log_hook_sync, asherah_set_metrics_hook, asherah_set_metrics_hook_sync,
    ASHERAH_LOG_TRACE, ASHERAH_LOG_WARN, ASHERAH_METRIC_ENCRYPT,
};

// All tests in this binary touch the same global hook registration. A
// process-wide mutex serializes them within this binary.
static SERIAL: Mutex<()> = Mutex::new(());

static LOG_COUNT: AtomicU32 = AtomicU32::new(0);
static LOG_LAST_LEVEL: AtomicU32 = AtomicU32::new(0);
static METRICS_COUNT: AtomicU32 = AtomicU32::new(0);
static METRICS_LAST_TYPE: AtomicU32 = AtomicU32::new(0);
static METRICS_LAST_DUR: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn log_cb(
    _user_data: *mut c_void,
    level: i32,
    _target: *const c_char,
    _message: *const c_char,
) {
    LOG_COUNT.fetch_add(1, AtomOrd::Relaxed);
    LOG_LAST_LEVEL.store(level as u32, AtomOrd::Relaxed);
}

unsafe extern "C" fn metrics_cb(
    _user_data: *mut c_void,
    event_type: i32,
    duration_ns: u64,
    _name: *const c_char,
) {
    METRICS_COUNT.fetch_add(1, AtomOrd::Relaxed);
    METRICS_LAST_TYPE.store(event_type as u32, AtomOrd::Relaxed);
    METRICS_LAST_DUR.store(duration_ns, AtomOrd::Relaxed);
}

/// RAII guard: acquires the serial mutex, wipes any leftover hook state,
/// resets counters; on drop, clears hooks again so the next test starts
/// clean even if this one panicked.
struct HookTest {
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl HookTest {
    fn new() -> Self {
        let guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        asherah_clear_log_hook();
        asherah_clear_metrics_hook();
        LOG_COUNT.store(0, AtomOrd::Relaxed);
        LOG_LAST_LEVEL.store(0, AtomOrd::Relaxed);
        METRICS_COUNT.store(0, AtomOrd::Relaxed);
        METRICS_LAST_TYPE.store(0, AtomOrd::Relaxed);
        METRICS_LAST_DUR.store(0, AtomOrd::Relaxed);
        Self { _guard: guard }
    }
}

impl Drop for HookTest {
    fn drop(&mut self) {
        asherah_clear_log_hook();
        asherah_clear_metrics_hook();
    }
}

/// The C ABI hooks dispatch events asynchronously on a worker thread so a
/// slow user callback can't slow down the encrypt/decrypt hot path. Tests
/// that assert on a counter need to give the worker a moment to drain.
fn wait_for<F: FnMut() -> bool>(mut cond: F) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn log_hook_register_and_invoke() {
    let _t = HookTest::new();
    let rc = unsafe { asherah_set_log_hook(Some(log_cb), std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    log::warn!(target: "test-target", "hello world");
    wait_for(|| LOG_COUNT.load(AtomOrd::Relaxed) >= 1);
    assert!(LOG_COUNT.load(AtomOrd::Relaxed) >= 1);
    assert_eq!(
        LOG_LAST_LEVEL.load(AtomOrd::Relaxed),
        ASHERAH_LOG_WARN as u32
    );
    let rc = asherah_clear_log_hook();
    assert_eq!(rc, 0);
}

#[test]
fn log_hook_clear_stops_callbacks() {
    let _t = HookTest::new();
    unsafe { asherah_set_log_hook(Some(log_cb), std::ptr::null_mut()) };
    // `warn!` (not `info!`) because the default min level is Warn.
    log::warn!("first");
    wait_for(|| LOG_COUNT.load(AtomOrd::Relaxed) >= 1);
    let after_first = LOG_COUNT.load(AtomOrd::Relaxed);
    assert!(after_first >= 1);
    asherah_clear_log_hook();
    // Async dispatch worker is gone now; emitting more records cannot reach
    // the old callback. Give a moment for any in-flight events to drain
    // (there should be none at this point).
    log::warn!("second — should not fire callback");
    std::thread::sleep(Duration::from_millis(20));
    let after_clear = LOG_COUNT.load(AtomOrd::Relaxed);
    assert_eq!(after_first, after_clear, "callback fired after clear");
}

#[test]
fn log_hook_null_returns_error() {
    let _t = HookTest::new();
    let rc = unsafe { asherah_set_log_hook(None, std::ptr::null_mut()) };
    assert_eq!(rc, -1);
}

#[test]
fn log_hook_replace_works() {
    let _t = HookTest::new();
    unsafe { asherah_set_log_hook(Some(log_cb), std::ptr::null_mut()) };
    log::warn!("first");
    wait_for(|| LOG_COUNT.load(AtomOrd::Relaxed) >= 1);
    let after_first = LOG_COUNT.load(AtomOrd::Relaxed);
    // Re-register the same callback; replacement must keep firing.
    unsafe { asherah_set_log_hook(Some(log_cb), std::ptr::null_mut()) };
    log::warn!("second");
    wait_for(|| LOG_COUNT.load(AtomOrd::Relaxed) > after_first);
    assert!(LOG_COUNT.load(AtomOrd::Relaxed) > after_first);
}

#[test]
fn log_hook_user_data_passed_through() {
    let _t = HookTest::new();
    static USER_DATA_OBSERVED: AtomicU64 = AtomicU64::new(0);
    unsafe extern "C" fn cb(
        user_data: *mut c_void,
        _level: i32,
        _target: *const c_char,
        _message: *const c_char,
    ) {
        USER_DATA_OBSERVED.store(user_data as usize as u64, AtomOrd::Relaxed);
    }
    let sentinel = 0xDEAD_BEEF_usize as *mut c_void;
    unsafe { asherah_set_log_hook(Some(cb), sentinel) };
    log::error!("trigger");
    wait_for(|| USER_DATA_OBSERVED.load(AtomOrd::Relaxed) == 0xDEAD_BEEF);
    assert_eq!(
        USER_DATA_OBSERVED.load(AtomOrd::Relaxed),
        0xDEAD_BEEF,
        "user_data not propagated to callback"
    );
}

#[test]
fn metrics_hook_register_and_invoke() {
    let _t = HookTest::new();
    let rc = unsafe { asherah_set_metrics_hook(Some(metrics_cb), std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    let start = std::time::Instant::now();
    std::thread::sleep(Duration::from_millis(1));
    metrics::record_encrypt(start);
    wait_for(|| METRICS_COUNT.load(AtomOrd::Relaxed) >= 1);
    assert_eq!(METRICS_COUNT.load(AtomOrd::Relaxed), 1);
    assert_eq!(
        METRICS_LAST_TYPE.load(AtomOrd::Relaxed),
        ASHERAH_METRIC_ENCRYPT as u32
    );
    assert!(METRICS_LAST_DUR.load(AtomOrd::Relaxed) > 0);
}

#[test]
fn metrics_hook_each_event_type_fires() {
    let _t = HookTest::new();
    unsafe { asherah_set_metrics_hook(Some(metrics_cb), std::ptr::null_mut()) };
    let start = std::time::Instant::now();
    metrics::record_encrypt(start);
    metrics::record_decrypt(start);
    metrics::record_store(start);
    metrics::record_load(start);
    metrics::record_cache_hit("session");
    metrics::record_cache_miss("ik");
    metrics::record_cache_stale("sk");
    wait_for(|| METRICS_COUNT.load(AtomOrd::Relaxed) >= 7);
    assert_eq!(METRICS_COUNT.load(AtomOrd::Relaxed), 7);
}

#[test]
fn metrics_hook_clear_stops_callbacks() {
    let _t = HookTest::new();
    unsafe { asherah_set_metrics_hook(Some(metrics_cb), std::ptr::null_mut()) };
    metrics::record_encrypt(std::time::Instant::now());
    wait_for(|| METRICS_COUNT.load(AtomOrd::Relaxed) >= 1);
    let after_first = METRICS_COUNT.load(AtomOrd::Relaxed);
    assert_eq!(after_first, 1);
    asherah_clear_metrics_hook();
    metrics::record_encrypt(std::time::Instant::now());
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        METRICS_COUNT.load(AtomOrd::Relaxed),
        after_first,
        "callback fired after clear"
    );
}

#[test]
fn metrics_hook_replace_works() {
    let _t = HookTest::new();
    unsafe { asherah_set_metrics_hook(Some(metrics_cb), std::ptr::null_mut()) };
    metrics::record_encrypt(std::time::Instant::now());
    wait_for(|| METRICS_COUNT.load(AtomOrd::Relaxed) >= 1);
    let after_first = METRICS_COUNT.load(AtomOrd::Relaxed);
    unsafe { asherah_set_metrics_hook(Some(metrics_cb), std::ptr::null_mut()) };
    metrics::record_decrypt(std::time::Instant::now());
    wait_for(|| METRICS_COUNT.load(AtomOrd::Relaxed) > after_first);
    assert!(METRICS_COUNT.load(AtomOrd::Relaxed) > after_first);
}

#[test]
fn metrics_hook_null_returns_error() {
    let _t = HookTest::new();
    let rc = unsafe { asherah_set_metrics_hook(None, std::ptr::null_mut()) };
    assert_eq!(rc, -1);
}

#[test]
fn metrics_hook_user_data_passed_through() {
    let _t = HookTest::new();
    static OBSERVED: AtomicU64 = AtomicU64::new(0);
    unsafe extern "C" fn cb(
        user_data: *mut c_void,
        _event_type: i32,
        _duration_ns: u64,
        _name: *const c_char,
    ) {
        OBSERVED.store(user_data as usize as u64, AtomOrd::Relaxed);
    }
    let sentinel = 0xCAFE_BABE_usize as *mut c_void;
    unsafe { asherah_set_metrics_hook(Some(cb), sentinel) };
    metrics::record_encrypt(std::time::Instant::now());
    wait_for(|| OBSERVED.load(AtomOrd::Relaxed) == 0xCAFE_BABE);
    assert_eq!(OBSERVED.load(AtomOrd::Relaxed), 0xCAFE_BABE);
}

#[test]
fn metrics_hook_cache_event_carries_name() {
    let _t = HookTest::new();
    static NAME_OBSERVED: parking_lot::Mutex<Option<String>> = parking_lot::Mutex::new(None);
    unsafe extern "C" fn cb(
        _user_data: *mut c_void,
        _event_type: i32,
        _duration_ns: u64,
        name: *const c_char,
    ) {
        if !name.is_null() {
            let s = unsafe { std::ffi::CStr::from_ptr(name) };
            *NAME_OBSERVED.lock() = Some(s.to_string_lossy().into_owned());
        }
    }
    unsafe { asherah_set_metrics_hook(Some(cb), std::ptr::null_mut()) };
    metrics::record_cache_hit("session-cache");
    wait_for(|| NAME_OBSERVED.lock().is_some());
    assert_eq!(
        NAME_OBSERVED.lock().clone().unwrap(),
        "session-cache",
        "cache event name not propagated"
    );
}

// ─── Sync-mode hooks ────────────────────────────────────────────────────
//
// These verify the `_sync` entry points fire on the *calling* thread (no
// queue, no worker). The async-mode tests above already cover correctness
// of the events themselves; here we just need to prove the threading
// difference.

#[test]
fn log_hook_sync_fires_on_calling_thread() {
    let _t = HookTest::new();
    static OBSERVED_TID: AtomicU64 = AtomicU64::new(0);
    OBSERVED_TID.store(0, AtomOrd::Relaxed);
    unsafe extern "C" fn cb(
        _user_data: *mut c_void,
        _level: i32,
        _target: *const c_char,
        _message: *const c_char,
    ) {
        // std::thread::ThreadId is opaque, but its `as_u64` is unstable.
        // Use a process-unique stack address as a "current thread" proxy.
        let sentinel = 0_u8;
        OBSERVED_TID.store(
            std::ptr::addr_of!(sentinel) as usize as u64,
            AtomOrd::Relaxed,
        );
    }
    let my_sentinel = 0_u8;
    let my_thread_addr = std::ptr::addr_of!(my_sentinel) as usize as u64;
    // Sentinels from different stack frames in the same thread aren't
    // identical, but they ARE within a small range of each other; from a
    // worker thread the addresses would differ by megabytes.
    let rc =
        unsafe { asherah_set_log_hook_sync(Some(cb), std::ptr::null_mut(), ASHERAH_LOG_TRACE) };
    assert_eq!(rc, 0);
    log::warn!("trigger sync");
    let observed = OBSERVED_TID.load(AtomOrd::Relaxed);
    assert!(
        observed != 0,
        "sync log hook never fired — must have been called on this thread synchronously"
    );
    let diff = (observed as i64 - my_thread_addr as i64).unsigned_abs();
    assert!(
        diff < 64 * 1024,
        "sync log hook fired on a different thread (test stack ≈ {my_thread_addr:x}, callback observed ≈ {observed:x}, diff = {diff})"
    );
    asherah_clear_log_hook();
}

#[test]
fn log_hook_sync_min_level_filter() {
    let _t = HookTest::new();
    let rc =
        unsafe { asherah_set_log_hook_sync(Some(log_cb), std::ptr::null_mut(), ASHERAH_LOG_WARN) };
    assert_eq!(rc, 0);
    log::trace!("filtered");
    log::debug!("filtered");
    log::info!("filtered");
    log::warn!("kept");
    log::error!("kept");
    // Sync — no need to wait for a worker.
    assert_eq!(
        LOG_COUNT.load(AtomOrd::Relaxed),
        2,
        "expected exactly 2 records (warn + error) past the level filter, got {}",
        LOG_COUNT.load(AtomOrd::Relaxed)
    );
}

#[test]
fn metrics_hook_sync_fires_on_calling_thread() {
    let _t = HookTest::new();
    static OBSERVED_TID: AtomicU64 = AtomicU64::new(0);
    OBSERVED_TID.store(0, AtomOrd::Relaxed);
    unsafe extern "C" fn cb(
        _user_data: *mut c_void,
        _event_type: i32,
        _duration_ns: u64,
        _name: *const c_char,
    ) {
        let sentinel = 0_u8;
        OBSERVED_TID.store(
            std::ptr::addr_of!(sentinel) as usize as u64,
            AtomOrd::Relaxed,
        );
    }
    let my_sentinel = 0_u8;
    let my_thread_addr = std::ptr::addr_of!(my_sentinel) as usize as u64;
    let rc = unsafe { asherah_set_metrics_hook_sync(Some(cb), std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    metrics::record_encrypt(std::time::Instant::now());
    let observed = OBSERVED_TID.load(AtomOrd::Relaxed);
    assert!(observed != 0, "sync metrics hook never fired");
    let diff = (observed as i64 - my_thread_addr as i64).unsigned_abs();
    assert!(
        diff < 64 * 1024,
        "sync metrics hook fired on a different thread (test stack ≈ {my_thread_addr:x}, callback observed ≈ {observed:x})"
    );
    asherah_clear_metrics_hook();
}
