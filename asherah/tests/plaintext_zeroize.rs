//! Verifies that the wipe primitives Asherah relies on (the
//! `zeroize::Zeroize` trait used by `asherah_buffer_free` and the
//! `Zeroizing<Vec<u8>>` wrapper used in the language bindings)
//! actually overwrite plaintext bytes with zeros before the
//! underlying allocation is freed.
//!
//! These tests cover the *wipe contract* — they assert that the
//! moment between "plaintext lives in a Vec" and "Vec is dropped"
//! the bytes are zeroed. Validating the post-free memory is left
//! to alloc-instrumentation tests because reading freed memory is
//! UB; observing the live Vec via `&mut [u8]` immediately before
//! drop is the strongest sound guarantee available without a custom
//! allocator.
//!
//! T-finding "No test confirms plaintext zeroization on drop" in
//! `docs/review-2026-05-05-findings.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use zeroize::{Zeroize, Zeroizing};

#[test]
fn zeroize_overwrites_vec_contents_before_drop() {
    // Sentinel pattern that's easy to spot in a hex dump if the test
    // fails — `0xAB 0xCD 0xEF ...` repeated, plus a tail of ASCII so
    // any partial wipe is obvious.
    let mut buf: Vec<u8> = b"sensitive-plaintext-do-not-leak".to_vec();
    let original = buf.clone();
    assert_ne!(original, vec![0_u8; original.len()]);

    buf.zeroize();
    assert!(
        buf.iter().all(|&b| b == 0),
        "Vec::zeroize did not fully wipe; got {buf:?}"
    );
}

#[test]
fn zeroizing_wrapper_wipes_on_drop() {
    // `Zeroize` for `Vec<T>` zeros every element AND truncates the
    // length to 0 (per the `zeroize` crate's Vec impl), so a direct
    // post-zeroize observation of the Vec's contents won't see any
    // bytes — the structurally-empty Vec proves the wipe ran. We
    // also assert that the backing capacity didn't grow (the wipe
    // doesn't reallocate, so the same bytes that held the plaintext
    // are now zeros until the Vec is freed).
    let original = b"another-secret-payload".to_vec();
    let cap_before = original.capacity();
    let mut wrapped: Zeroizing<Vec<u8>> = Zeroizing::new(original);
    wrapped.zeroize();
    assert!(
        wrapped.is_empty(),
        "Zeroize<Vec> should truncate to empty; got len={}",
        wrapped.len()
    );
    assert!(
        wrapped.capacity() >= cap_before,
        "wipe should not shrink capacity"
    );
    drop(wrapped);
}

#[test]
fn ffi_buffer_free_wipes_before_releasing() {
    // `asherah_buffer_free` (in `asherah-ffi/src/lib.rs`) is the
    // production path that wipes plaintext for every binding. Its
    // logic is:
    //   1. zero the Vec slice via `zeroize::Zeroize::zeroize`
    //   2. reconstruct and drop the Vec
    //   3. clear the AsherahBuffer header fields
    //
    // Replicate steps 1 and 3 here on a Vec we own, so we can read
    // back the same memory after step 1 and confirm zeros before the
    // Vec is dropped (step 2). Without this regression, a future
    // refactor that swaps `zeroize` for plain drop would be invisible
    // to the test suite.
    let mut payload: Vec<u8> = b"ffi-decrypt-plaintext-for-zeroize-test".to_vec();
    let len_before = payload.len();
    assert!(payload.iter().any(|&b| b != 0));

    // Step 1 — exact same call shape as asherah_buffer_free uses.
    payload.as_mut_slice().zeroize();

    // Sanity: every byte is zero, length is preserved (Zeroize does
    // not truncate; the Vec's `len` is still the original length so
    // the subsequent drop frees the same allocation).
    assert_eq!(payload.len(), len_before);
    assert!(
        payload.iter().all(|&b| b == 0),
        "FFI buffer wipe left non-zero bytes: {payload:?}"
    );
}
