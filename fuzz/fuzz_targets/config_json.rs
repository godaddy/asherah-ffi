#![no_main]
//! Fuzz ConfigOptions JSON deserialization.
//!
//! Targets: malformed JSON, extreme field values, malicious connection strings,
//! special characters in service/product names, oversized region maps.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Limit length
        if s.len() > 8192 {
            return;
        }

        // Deserialize ConfigOptions — should never panic
        let _ = serde_json::from_str::<asherah_config::ConfigOptions>(s);
    }
});
