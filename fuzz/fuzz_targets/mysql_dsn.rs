#![no_main]
//! Fuzz Go MySQL DSN parser and connection string classifier.
//!
//! Targets: malformed tcp() brackets, embedded special chars in user/pass,
//! multiple @ signs, port overflow, unbalanced parens, empty segments.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Limit length to avoid spending time on huge strings
        if s.len() > 1024 {
            return;
        }

        // Fuzz the DSN converter — should never panic
        let _ = asherah::builders::convert_go_mysql_dsn(s);

        // Fuzz the connection string classifier — should never panic
        let _ = asherah::builders::classify_connection_string(s);
    }
});
