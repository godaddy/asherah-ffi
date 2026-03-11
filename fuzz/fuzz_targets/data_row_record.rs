#![no_main]
//! Fuzz DataRowRecord JSON deserialization.
//!
//! Targets: malformed JSON, invalid base64, missing fields, oversized payloads,
//! invalid timestamps, nested object corruption.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test from arbitrary bytes (invalid UTF-8, truncated JSON, etc.)
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<asherah::types::DataRowRecord>(s);
    }

    // Also test from_slice directly
    let _ = serde_json::from_slice::<asherah::types::DataRowRecord>(data);
});
