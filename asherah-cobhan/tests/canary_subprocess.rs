//! Subprocess test for `verify_canaries`.
//!
//! `verify_canaries` aborts the process on canary corruption — there's
//! no return path and no panic, so it can't be exercised inside the
//! parent test process without taking the process down with it. This
//! test re-invokes the test binary itself with a magic env var so the
//! child runs the corruption path, and asserts that the child exits
//! abnormally (signal-killed or non-zero exit code, depending on
//! platform ABI). T-finding "No isolated subprocess test verifies
//! canary `verify_canaries` actually triggers" in
//! `docs/review-2026-05-05-findings.md`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::exit)]

use asherah_cobhan::test_helpers::{create_input_buffer, BUFFER_HEADER_SIZE};
use asherah_cobhan::{set_canaries_enabled, verify_canaries_for_test};
use std::process::Command;

const TRIGGER_ENV: &str = "_ASHERAH_CANARY_SUBPROCESS_TRIGGER";

#[test]
fn verify_canaries_passes_on_pristine_buffer() {
    set_canaries_enabled(true);
    let buf = create_input_buffer(b"hello-canary-world");
    // Canary lives immediately after the data region.
    let canary_offset = BUFFER_HEADER_SIZE as usize + b"hello-canary-world".len();
    // The function aborts on corruption, so reaching the next line means
    // the canary check passed.
    verify_canaries_for_test(&buf, canary_offset);
}

#[test]
fn verify_canaries_aborts_on_corrupted_canary_in_subprocess() {
    if std::env::var(TRIGGER_ENV).is_ok() {
        // Child branch: build a buffer, flip a canary byte, call
        // verify_canaries. We must abort — the parent observes the
        // exit status to confirm.
        set_canaries_enabled(true);
        let mut buf = create_input_buffer(b"corruption-target");
        let canary_offset = BUFFER_HEADER_SIZE as usize + b"corruption-target".len();
        // Flip canary byte 0 — supposed to be `0` (CANARY1_VALUE LSB),
        // we make it `0xFF`.
        buf[canary_offset] = 0xFF;
        verify_canaries_for_test(&buf, canary_offset);
        // Unreachable: verify_canaries should have aborted.
        // Use a distinct exit code so a missing-abort regression is
        // distinguishable from a panic.
        std::process::exit(99);
    }

    // Parent branch: re-invoke the test binary, scoped to this test.
    let exe = std::env::current_exe().expect("test binary path");
    let status = Command::new(&exe)
        .args([
            "--exact",
            "verify_canaries_aborts_on_corrupted_canary_in_subprocess",
            "--nocapture",
        ])
        .env(TRIGGER_ENV, "1")
        .output()
        .expect("spawn subprocess");

    assert!(
        !status.status.success(),
        "child exited cleanly with code {:?} — verify_canaries did NOT abort. \
         stdout: {}\nstderr: {}",
        status.status.code(),
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
    );

    // Reached-the-fallback exit code means the abort was missed.
    if let Some(99) = status.status.code() {
        panic!(
            "child reached the post-verify_canaries fallback (exit 99); \
             corruption check did not fire"
        );
    }

    // On Unix, abort() raises SIGABRT (signal 6). Any non-success exit
    // is acceptable here — we don't pin to a specific signal because
    // CI runners differ in how they report aborted processes.
}
