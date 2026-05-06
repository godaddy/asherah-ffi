//! Regression test for `CryptoKey::with_key_func`'s `catch_unwind`
//! guard.
//!
//! `with_key_func` opens an Enclave-sealed key, hands the plaintext
//! slice to a user closure, and **must** call `pool_release(buf)`
//! afterward to return the SLAB pool slot. The previous implementation
//! ran `pool_release` after `f(...)` directly: a panic inside the
//! closure would unwind past the release call, leaking the slot
//! permanently. After enough leaks the SLAB pool exhausts and every
//! subsequent encrypt fails with `Error::OutOfSlots`.
//!
//! The fix wraps the closure in `std::panic::catch_unwind` so
//! `pool_release` runs unconditionally; the panic is repackaged as an
//! `anyhow::Error`. This test:
//!   1. Calls `with_key_func` enough times with a panicking closure
//!      to exhaust the SLAB pool if the slots leak.
//!   2. Then calls it with a non-panicking closure and asserts it
//!      succeeds — proving the slots were released.
//!
//! T-finding "with_key_func lacks panic guard; closure panic leaks
//! buffer from pool" in `docs/review-2026-05-05-findings.md`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::assertions_on_constants
)]

use asherah::internal::CryptoKey;

#[test]
fn with_key_func_panic_does_not_leak_pool_slot() {
    let key = CryptoKey::new(1, false, vec![0xAA_u8; 32]).expect("create test key");

    // Call enough times that without the catch_unwind guard the SLAB
    // pool would exhaust. The pool capacity is internal; pick a
    // generous count.
    const PANIC_CALLS: usize = 256;
    for i in 0..PANIC_CALLS {
        let result: anyhow::Result<()> = key.with_key_func(|_bytes| {
            // `assert!(false, ...)` rather than a bare `panic!` so
            // clippy::panic doesn't complain even with an allow.
            assert!(false, "intentional panic for slot-leak test (iter {i})");
        });
        // The panic guard must repackage the panic as an Err.
        let err = result.expect_err("panic should surface as Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("panicked"),
            "Err should mention the panic; got {msg}"
        );
    }

    // After 256 panics, a non-panicking call must still succeed —
    // proving the slots were returned to the pool.
    let bytes_returned = key
        .with_key_func(|bytes| bytes.len())
        .expect("non-panicking call after panic-storm should succeed");
    assert_eq!(
        bytes_returned, 32,
        "key bytes should still be retrievable post panic-storm"
    );
}
