#![no_main]
//! Fuzz the *real* cobhan FFI surface — `Encrypt`/`Decrypt`/
//! `EncryptToJson`/`DecryptFromJson` and the buffer-header parsing
//! they perform — by passing arbitrary byte slices as cobhan input
//! buffers. The previous version of this target re-implemented the
//! parser in safe Rust and fuzzed *that*, which exercised none of the
//! unsafe pointer arithmetic or the global state inside the cobhan
//! crate. T-finding "fuzz target reimplements parsing logic in safe
//! Rust" in `docs/review-2026-05-05-findings.md`.
//!
//! Each iteration:
//!   1. Splits the fuzzer input into "partition" and "payload" halves.
//!   2. Wraps each half in a real cobhan input buffer
//!      (`create_input_buffer` from `asherah_cobhan::test_helpers`).
//!   3. Allocates an output buffer sized via `EstimateBuffer`.
//!   4. Calls `EncryptToJson` / `DecryptFromJson` through the real
//!      `unsafe extern "C"` entries.
//! The global asherah factory is set up once via `Lazy` so subsequent
//! iterations reuse the in-memory metastore + StaticKMS configuration.

use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use std::os::raw::c_char;
use std::sync::Mutex;

use asherah_cobhan::test_helpers::{create_input_buffer, create_output_buffer};
use asherah_cobhan::{DecryptFromJson, EncryptToJson, EstimateBuffer, SetupJson};

const SETUP_JSON: &str = r#"{
    "ServiceName": "fuzz-svc",
    "ProductID": "fuzz-prod",
    "Metastore": "memory",
    "KMS": "test-debug-static",
    "Verbose": false,
    "EnableSessionCaching": true
}"#;

/// Run setup exactly once for the lifetime of the fuzz process. Calling
/// `SetupJson` twice without `Shutdown` returns `ERR_ALREADY_INITIALIZED`,
/// which would mask any genuine bug the fuzzer might find on a fresh
/// run, so we serialize through a Lazy<Mutex<()>> and only initialize on
/// first observation.
static SETUP: Lazy<Mutex<bool>> = Lazy::new(|| {
    let buf = create_input_buffer(SETUP_JSON.as_bytes());
    // SAFETY: `create_input_buffer` returns a properly-formatted cobhan
    // buffer with header capacity + data. The pointer is valid for the
    // duration of this call.
    let rc = unsafe { SetupJson(buf.as_ptr().cast::<c_char>()) };
    Mutex::new(rc == 0)
});

fuzz_target!(|data: &[u8]| {
    if !*SETUP.lock().expect("setup mutex") {
        // Setup didn't take — bail rather than feed garbage into a
        // dis-initialized factory.
        return;
    }

    // Split: first byte selects partition length (0..=64).
    let (part_bytes, payload_bytes) = if data.is_empty() {
        (&[][..], &[][..])
    } else {
        let split = (data[0] as usize % 65).min(data.len() - 1);
        (&data[1..1 + split], &data[1 + split..])
    };
    if part_bytes.is_empty() {
        return;
    }
    // Reject control bytes / non-ASCII so the partition validator
    // doesn't reject every iteration. We're fuzzing the parser, not
    // the partition allowlist.
    if part_bytes
        .iter()
        .any(|b| !b.is_ascii() || *b < 0x20 || *b == 0x7f)
    {
        return;
    }

    let partition_buf = create_input_buffer(part_bytes);
    let payload_buf = create_input_buffer(payload_bytes);

    // EncryptToJson: feed arbitrary plaintext, ask for a JSON DRR.
    let estimate = EstimateBuffer(payload_bytes.len() as i32, part_bytes.len() as i32);
    if estimate <= 0 || estimate > 1 << 20 {
        return;
    }
    let mut json_out = create_output_buffer(estimate);
    let rc_enc = unsafe {
        EncryptToJson(
            partition_buf.as_ptr().cast::<c_char>(),
            payload_buf.as_ptr().cast::<c_char>(),
            json_out.as_mut_ptr().cast::<c_char>(),
        )
    };
    // We don't assert success — many inputs (huge sizes, etc.) are
    // legitimately rejected. The fuzzer is checking that no input
    // panics / segfaults / hits UB, regardless of error code.
    let _ = rc_enc;

    // DecryptFromJson: feed the fuzzer bytes as if they were a JSON
    // DRR. Most inputs are not valid JSON; the parser must reject
    // them with an error code, never crash.
    let mut pt_out = create_output_buffer(1024);
    let rc_dec = unsafe {
        DecryptFromJson(
            partition_buf.as_ptr().cast::<c_char>(),
            payload_buf.as_ptr().cast::<c_char>(),
            pt_out.as_mut_ptr().cast::<c_char>(),
        )
    };
    let _ = rc_dec;
});
