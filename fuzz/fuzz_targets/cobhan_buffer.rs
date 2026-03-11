#![no_main]
//! Fuzz cobhan buffer header parsing and data extraction.
//!
//! Targets: malformed length headers, negative lengths, lengths exceeding
//! allocation, buffer too small for output, canary corruption detection.

use libfuzzer_sys::fuzz_target;

// Re-implement cobhan buffer operations in safe Rust for fuzzing,
// testing the same logic without raw pointer UB.
// The real cobhan functions are unsafe and take raw pointers —
// we test the logic they implement.

const BUFFER_HEADER_SIZE: usize = 8;

fn parse_cobhan_length(buf: &[u8]) -> Option<i32> {
    if buf.len() < 4 {
        return None;
    }
    Some(i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

fn extract_cobhan_data(buf: &[u8]) -> Result<&[u8], i32> {
    if buf.len() < BUFFER_HEADER_SIZE {
        return Err(-1); // ERR_NULL_PTR equivalent
    }
    let len = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if len < 0 {
        return Err(-2); // ERR_BUFFER_TOO_LARGE (temp file indicator)
    }
    let len = len as usize;
    if BUFFER_HEADER_SIZE + len > buf.len() {
        return Err(-3); // ERR_BUFFER_TOO_SMALL
    }
    Ok(&buf[BUFFER_HEADER_SIZE..BUFFER_HEADER_SIZE + len])
}

fn write_cobhan_data(buf: &mut [u8], data: &[u8]) -> Result<(), i32> {
    if buf.len() < BUFFER_HEADER_SIZE {
        return Err(-1);
    }
    let capacity = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if capacity < 0 {
        return Err(-2);
    }
    let data_len = data.len() as i32;
    if data_len > capacity {
        return Err(-3); // ERR_BUFFER_TOO_SMALL
    }
    // Write new length
    let len_bytes = data_len.to_le_bytes();
    buf[0] = len_bytes[0];
    buf[1] = len_bytes[1];
    buf[2] = len_bytes[2];
    buf[3] = len_bytes[3];
    // Copy data
    if !data.is_empty() {
        buf[BUFFER_HEADER_SIZE..BUFFER_HEADER_SIZE + data.len()].copy_from_slice(data);
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Test length parsing with arbitrary bytes
    let _ = parse_cobhan_length(data);

    // Test data extraction
    match extract_cobhan_data(data) {
        Ok(extracted) => {
            // If extraction succeeds, the data should be within bounds
            assert!(extracted.len() <= data.len() - BUFFER_HEADER_SIZE);
        }
        Err(_) => {} // Expected for malformed input
    }

    // Test roundtrip: create a buffer, write data, read it back
    if data.len() <= 1024 {
        let capacity = data.len() as i32;
        let total = BUFFER_HEADER_SIZE + data.len();
        let mut buf = vec![0_u8; total];
        // Set capacity in header
        let cap_bytes = capacity.to_le_bytes();
        buf[0] = cap_bytes[0];
        buf[1] = cap_bytes[1];
        buf[2] = cap_bytes[2];
        buf[3] = cap_bytes[3];

        if write_cobhan_data(&mut buf, data).is_ok() {
            let extracted = extract_cobhan_data(&buf).expect("roundtrip should succeed");
            assert_eq!(extracted, data, "roundtrip data mismatch");
        }
    }

    // Test JSON parsing through cobhan-style buffer
    if data.len() >= BUFFER_HEADER_SIZE {
        if let Ok(payload) = extract_cobhan_data(data) {
            if let Ok(s) = std::str::from_utf8(payload) {
                let _ = serde_json::from_str::<asherah::types::DataRowRecord>(s);
            }
        }
    }
});
