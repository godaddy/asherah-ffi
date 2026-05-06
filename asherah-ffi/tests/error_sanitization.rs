//! Regression test for `set_error_sanitized` chain-stripping.
//!
//! `asherah-ffi/src/lib.rs:set_error_sanitized` writes the full anyhow
//! chain to `log::warn!` for the operator while storing only the
//! top-level Display in the thread-local `LAST_ERROR` that user code
//! reads via `asherah_last_error_message`. Without this, AWS SDK
//! errors include ARNs, request IDs, and other operational metadata
//! that shouldn't flow to language bindings.
//!
//! The test forces a multi-frame anyhow chain by invoking
//! `asherah_apply_config_json` with malformed JSON. `factory_from_config_json`
//! wraps the inner serde_json error in an anyhow context. The
//! sanitized error message must NOT contain the inner serde_json
//! frame's body (which `{e:#}` would surface) — only the outer
//! `op failed: ...` summary.
//!
//! T-finding "format!(\"{e:#}\") returns full anyhow chain to user
//! callbacks" in `docs/review-2026-05-05-findings.md`.

#![allow(unsafe_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::{CStr, CString};

use asherah_ffi::{asherah_apply_config_json, asherah_last_error_message};

#[test]
fn malformed_config_json_error_message_omits_chain() {
    // Malformed JSON triggers the serde_json error path inside
    // `factory_from_config_json`, which is wrapped by
    // `ConfigOptions::from_json` and then contextualized again by
    // `factory_from_config`. That's three potential frames in the
    // anyhow chain — `{e:#}` would join them with `: `.
    let bad = CString::new("{not valid json").unwrap();
    let rc = unsafe { asherah_apply_config_json(bad.as_ptr()) };
    assert_eq!(rc, -1, "bad config JSON should produce error rc -1");

    let msg_ptr = asherah_last_error_message();
    assert!(
        !msg_ptr.is_null(),
        "asherah_last_error_message returned null after failed apply_config_json"
    );
    let msg = unsafe { CStr::from_ptr(msg_ptr) }
        .to_str()
        .expect("error message is valid UTF-8");

    // The user-facing message must include the operation name we set
    // via `set_error_sanitized("apply_config_json", ...)`.
    assert!(
        msg.contains("apply_config_json failed"),
        "error message should include the op tag; got {msg:?}"
    );

    // Chain joiner. anyhow's `{e:#}` separates frames with ": " — if
    // the chain were leaked we'd see two or more frame-style segments
    // joined this way past the initial "op failed: ". Detect by
    // counting `: ` occurrences after the op tag. The sanitized
    // top-level message should have at most one `: ` joining "op
    // failed:" to the inner top-level Display.
    let post_tag = msg
        .strip_prefix("apply_config_json failed: ")
        .expect("message starts with the op tag");
    // Allow up to one `: ` in the inner Display itself (serde_json
    // includes a colon in "expected ident at line N column M") — but
    // the chain-leak case would compound multiple frames.
    let extra_chain_separators = post_tag.matches(": ").count();
    assert!(
        extra_chain_separators <= 2,
        "error message {msg:?} appears to leak the anyhow chain (found \
         {extra_chain_separators} extra `: ` separators in {post_tag:?}); \
         expected at most 2 from the inner Display itself"
    );

    // Belt-and-suspenders: the chain-leaked form would typically
    // include the literal phrase "Caused by" in some anyhow renderings.
    assert!(
        !msg.contains("Caused by"),
        "error message contains anyhow chain marker `Caused by`: {msg:?}"
    );
}
