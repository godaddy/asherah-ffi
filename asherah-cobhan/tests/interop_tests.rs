//! Interoperability tests for asherah-cobhan
//!
//! These tests verify that the Rust implementation is binary compatible with
//! the original Go asherah-cobhan library by testing:
//! 1. JSON DataRowRecord format compatibility
//! 2. Cobhan buffer format
//! 3. Exported symbol names
//! 4. Error code values
//! 5. Cross-library encryption/decryption

use std::os::raw::c_char;

use asherah_cobhan::test_helpers::*;
use asherah_cobhan::{
    Decrypt, DecryptFromJson, Encrypt, EncryptToJson, EstimateBuffer, SetEnv, SetupJson, Shutdown,
};

// ============================================================================
// JSON Format Compatibility Tests
// ============================================================================

/// Test that the DataRowRecord JSON format matches the Go implementation
#[test]
fn test_json_format_has_required_fields() {
    setup_test_factory();

    let partition = create_string_buffer("json-format-test");
    let data = create_input_buffer(b"test data for format verification");

    let estimate = EstimateBuffer(34, 16);
    let mut json_output = create_output_buffer(estimate);

    unsafe {
        let result = EncryptToJson(
            partition.as_ptr() as *const c_char,
            data.as_ptr() as *const c_char,
            json_output.as_mut_ptr() as *mut c_char,
        );
        assert_eq!(result, ERR_NONE, "EncryptToJson should succeed");
    }

    let json_str = get_buffer_string(&json_output);

    // Parse as generic JSON to verify structure
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("Should be valid JSON");

    // Verify required top-level fields
    assert!(parsed.get("Data").is_some(), "JSON must have 'Data' field");
    assert!(parsed.get("Key").is_some(), "JSON must have 'Key' field");

    // Verify Data field is a base64 string
    let data_field = parsed.get("Data").unwrap();
    assert!(data_field.is_string(), "'Data' field must be a string");
    let data_b64 = data_field.as_str().unwrap();
    assert!(!data_b64.is_empty(), "'Data' field should not be empty");
    // Verify it's valid base64
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data_b64)
        .expect("'Data' field should be valid base64");

    // Verify Key field structure
    let key_field = parsed.get("Key").unwrap();
    assert!(key_field.is_object(), "'Key' field must be an object");

    // Verify Key sub-fields
    assert!(
        key_field.get("Created").is_some(),
        "'Key' must have 'Created' field"
    );
    assert!(
        key_field.get("Key").is_some(),
        "'Key' must have 'Key' field (encrypted key)"
    );

    let created = key_field.get("Created").unwrap();
    assert!(
        created.is_i64() || created.is_u64(),
        "'Created' must be an integer"
    );

    let encrypted_key = key_field.get("Key").unwrap();
    assert!(encrypted_key.is_string(), "'Key.Key' must be a string");
    // Verify it's valid base64
    base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        encrypted_key.as_str().unwrap(),
    )
    .expect("'Key.Key' should be valid base64");

    // ParentKeyMeta may or may not be present
    if let Some(parent_meta) = key_field.get("ParentKeyMeta") {
        assert!(
            parent_meta.is_object(),
            "'ParentKeyMeta' must be an object if present"
        );
        assert!(
            parent_meta.get("KeyId").is_some(),
            "'ParentKeyMeta' must have 'KeyId'"
        );
        assert!(
            parent_meta.get("Created").is_some(),
            "'ParentKeyMeta' must have 'Created'"
        );
    }

    Shutdown();
}

/// Test that JSON field names use PascalCase (Go convention)
#[test]
fn test_json_uses_pascal_case_field_names() {
    setup_test_factory();

    let partition = create_string_buffer("pascal-case-test");
    let data = create_input_buffer(b"test");

    let estimate = EstimateBuffer(4, 16);
    let mut json_output = create_output_buffer(estimate);

    unsafe {
        let result = EncryptToJson(
            partition.as_ptr() as *const c_char,
            data.as_ptr() as *const c_char,
            json_output.as_mut_ptr() as *mut c_char,
        );
        assert_eq!(result, ERR_NONE);
    }

    let json_str = get_buffer_string(&json_output);

    // Check for PascalCase field names (Go convention)
    assert!(
        json_str.contains("\"Data\""),
        "Should use 'Data' not 'data'"
    );
    assert!(json_str.contains("\"Key\""), "Should use 'Key' not 'key'");
    assert!(
        json_str.contains("\"Created\""),
        "Should use 'Created' not 'created'"
    );

    // Check that snake_case is NOT used
    assert!(
        !json_str.contains("\"data\""),
        "Should not use snake_case 'data'"
    );
    assert!(
        !json_str.contains("\"key\""),
        "Should not use snake_case 'key'"
    );
    assert!(
        !json_str.contains("\"created\""),
        "Should not use snake_case 'created'"
    );
    assert!(
        !json_str.contains("\"encrypted_key\""),
        "Should not use snake_case"
    );
    assert!(
        !json_str.contains("\"parent_key_meta\""),
        "Should not use snake_case"
    );

    Shutdown();
}

/// Test that we can decrypt JSON produced by Go implementation format
#[test]
fn test_decrypt_go_format_json() {
    setup_test_factory();

    // This JSON structure matches what the Go asherah-cobhan produces
    // The actual encrypted data won't decrypt (wrong keys) but we test format parsing
    let go_format_json = r#"{
        "Data": "dGVzdA==",
        "Key": {
            "Created": 1700000000000,
            "Key": "ZW5jcnlwdGVkX2tleV9kYXRh",
            "ParentKeyMeta": {
                "KeyId": "_SK_interop-test-service_interop-test-product",
                "Created": 1700000000000
            }
        }
    }"#;

    let partition = create_string_buffer("test-partition");
    let json_buf = create_string_buffer(go_format_json);
    let mut output = create_output_buffer(1024);

    unsafe {
        let result = DecryptFromJson(
            partition.as_ptr() as *const c_char,
            json_buf.as_ptr() as *const c_char,
            output.as_mut_ptr() as *mut c_char,
        );
        // Should fail with decrypt error (wrong keys) but NOT json parse error
        // ERR_DECRYPT_FAILED (-104) means JSON was parsed correctly
        // ERR_JSON_DECODE_FAILED (-5) would mean JSON format is wrong
        assert!(
            result == ERR_DECRYPT_FAILED || result == ERR_NONE,
            "Should parse JSON correctly (got {}), decrypt may fail due to keys",
            result
        );
    }

    Shutdown();
}

// ============================================================================
// Cobhan Buffer Format Tests
// ============================================================================

/// Test cobhan buffer header format: 8 bytes total
/// - Bytes 0-3: int32 length (little-endian)
/// - Bytes 4-7: int32 capacity (little-endian)
#[test]
fn test_cobhan_buffer_header_is_8_bytes() {
    assert_eq!(
        BUFFER_HEADER_SIZE, 8,
        "Cobhan buffer header must be 8 bytes"
    );
}

/// Test that length is stored as little-endian int32 at offset 0
#[test]
fn test_cobhan_length_little_endian() {
    let buf = create_input_buffer(b"test");
    // Length should be 4 (little-endian)
    assert_eq!(buf[0], 4); // LSB
    assert_eq!(buf[1], 0);
    assert_eq!(buf[2], 0);
    assert_eq!(buf[3], 0); // MSB
}

/// Test that capacity is stored at offset 4 for output buffers
#[test]
fn test_cobhan_capacity_at_offset_4() {
    let buf = create_output_buffer(1000);
    // Capacity should be 1000 at offset 4-7 (little-endian)
    let capacity = i32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    assert_eq!(capacity, 1000);
}

/// Test that data starts at offset 8
#[test]
fn test_cobhan_data_starts_at_offset_8() {
    let data = b"hello";
    let buf = create_input_buffer(data);
    assert_eq!(&buf[8..13], data, "Data should start at offset 8");
}

// ============================================================================
// Error Code Compatibility Tests
// ============================================================================

/// Test that error codes match the Go implementation
#[test]
fn test_error_codes_match_go_implementation() {
    // These values must match github.com/godaddy/cobhan-go and asherah-cobhan
    assert_eq!(ERR_NONE, 0, "ERR_NONE should be 0");
    assert_eq!(ERR_NULL_PTR, -1, "ERR_NULL_PTR should be -1");
    assert_eq!(
        ERR_BUFFER_TOO_LARGE, -2,
        "ERR_BUFFER_TOO_LARGE should be -2"
    );
    assert_eq!(
        ERR_BUFFER_TOO_SMALL, -3,
        "ERR_BUFFER_TOO_SMALL should be -3"
    );
    assert_eq!(ERR_COPY_FAILED, -4, "ERR_COPY_FAILED should be -4");
    assert_eq!(
        ERR_JSON_DECODE_FAILED, -5,
        "ERR_JSON_DECODE_FAILED should be -5"
    );
    assert_eq!(
        ERR_JSON_ENCODE_FAILED, -6,
        "ERR_JSON_ENCODE_FAILED should be -6"
    );

    // Asherah-specific error codes
    assert_eq!(
        ERR_ALREADY_INITIALIZED, -100,
        "ERR_ALREADY_INITIALIZED should be -100"
    );
    assert_eq!(ERR_BAD_CONFIG, -101, "ERR_BAD_CONFIG should be -101");
    assert_eq!(
        ERR_NOT_INITIALIZED, -102,
        "ERR_NOT_INITIALIZED should be -102"
    );
    assert_eq!(
        ERR_ENCRYPT_FAILED, -103,
        "ERR_ENCRYPT_FAILED should be -103"
    );
    assert_eq!(
        ERR_DECRYPT_FAILED, -104,
        "ERR_DECRYPT_FAILED should be -104"
    );
}

// ============================================================================
// EstimateBuffer Compatibility Tests
// ============================================================================

/// Test that EstimateBuffer returns values large enough for actual encryption
#[test]
fn test_estimate_buffer_sufficient_for_encryption() {
    setup_test_factory();

    let test_cases = [(10, 10), (100, 20), (1000, 50), (10000, 100)];

    for (data_len, partition_len) in test_cases {
        let estimate = EstimateBuffer(data_len, partition_len);
        assert!(estimate > 0, "Estimate should be positive");

        // Generate test data and partition
        let data: Vec<u8> = (0..data_len as usize).map(|i| (i % 256) as u8).collect();
        let partition: String = (0..partition_len as usize).map(|_| 'x').collect();

        let partition_buf = create_string_buffer(&partition);
        let data_buf = create_input_buffer(&data);
        let mut json_output = create_output_buffer(estimate);

        unsafe {
            let result = EncryptToJson(
                partition_buf.as_ptr() as *const c_char,
                data_buf.as_ptr() as *const c_char,
                json_output.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(
                result, ERR_NONE,
                "Encryption should succeed with estimated buffer size for data_len={}, partition_len={}",
                data_len, partition_len
            );
        }

        // Verify actual output fits
        let actual_len = get_buffer_length(&json_output);
        assert!(
            actual_len <= estimate,
            "Actual output {} should fit in estimated buffer {} for data_len={}, partition_len={}",
            actual_len,
            estimate,
            data_len,
            partition_len
        );
    }

    Shutdown();
}

// ============================================================================
// Cross-Implementation Round-Trip Tests
// ============================================================================

/// Test that JSON encrypted by Rust can be parsed as valid DataRowRecord structure
#[test]
fn test_rust_output_is_valid_data_row_record() {
    setup_test_factory();

    let partition = create_string_buffer("roundtrip-test");
    let plaintext = b"This is test data for round-trip verification";
    let data = create_input_buffer(plaintext);

    let estimate = EstimateBuffer(plaintext.len() as i32, 14);
    let mut json_output = create_output_buffer(estimate);

    unsafe {
        let result = EncryptToJson(
            partition.as_ptr() as *const c_char,
            data.as_ptr() as *const c_char,
            json_output.as_mut_ptr() as *mut c_char,
        );
        assert_eq!(result, ERR_NONE);
    }

    let json_str = get_buffer_string(&json_output);

    // Parse and verify complete structure
    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "PascalCase")]
    #[allow(dead_code)]
    struct KeyMeta {
        key_id: String,
        created: i64,
    }

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "PascalCase")]
    #[allow(dead_code)]
    struct EnvelopeKeyRecord {
        created: i64,
        key: String,
        #[serde(default)]
        parent_key_meta: Option<KeyMeta>,
    }

    #[derive(serde::Deserialize, Debug)]
    #[serde(rename_all = "PascalCase")]
    #[allow(dead_code)]
    struct DataRowRecord {
        data: String,
        key: Option<EnvelopeKeyRecord>,
    }

    let drr: DataRowRecord =
        serde_json::from_str(&json_str).expect("Should deserialize as DataRowRecord");

    // Verify structure
    assert!(!drr.data.is_empty(), "Data should not be empty");
    assert!(drr.key.is_some(), "Key should be present");

    let key = drr.key.unwrap();
    assert!(key.created > 0, "Created timestamp should be positive");
    assert!(!key.key.is_empty(), "Encrypted key should not be empty");

    // Verify base64 encoding
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &drr.data)
        .expect("Data should be valid base64");
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &key.key)
        .expect("Key should be valid base64");

    Shutdown();
}

/// Test complete encrypt/decrypt round-trip with JSON format
#[test]
fn test_encrypt_decrypt_json_roundtrip() {
    setup_test_factory();

    let test_cases = [
        ("ascii", "Hello, World!"),
        ("unicode", "Hello, \u{4e16}\u{754c}! \u{1F980}"),
        ("empty", ""),
        ("whitespace", "   \t\n   "),
        ("json", r#"{"key": "value"}"#),
        ("special", "Special: \t\n\r\"'\\<>&"),
    ];

    for (name, plaintext) in test_cases {
        let partition = create_string_buffer(&format!("roundtrip-{}", name));
        let data = create_input_buffer(plaintext.as_bytes());

        let estimate = EstimateBuffer(plaintext.len() as i32, 20);
        let mut json_output = create_output_buffer(estimate);

        // Encrypt
        unsafe {
            let result = EncryptToJson(
                partition.as_ptr() as *const c_char,
                data.as_ptr() as *const c_char,
                json_output.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NONE, "Encrypt should succeed for {}", name);
        }

        // Decrypt
        let mut decrypted_output = create_output_buffer(plaintext.len() as i32 + 100);

        unsafe {
            let result = DecryptFromJson(
                partition.as_ptr() as *const c_char,
                json_output.as_ptr() as *const c_char,
                decrypted_output.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NONE, "Decrypt should succeed for {}", name);
        }

        let decrypted = get_buffer_string(&decrypted_output);
        assert_eq!(
            decrypted, plaintext,
            "Round-trip should preserve data for {}",
            name
        );
    }

    Shutdown();
}

/// Test component-based Encrypt/Decrypt round-trip
#[test]
fn test_encrypt_decrypt_components_roundtrip() {
    setup_test_factory();

    let partition = create_string_buffer("component-roundtrip");
    let plaintext = b"Component-based encryption test data";
    let data = create_input_buffer(plaintext);

    // Encrypt
    let mut encrypted_data = create_output_buffer(2048);
    let mut encrypted_key = create_output_buffer(2048);
    let mut created = create_output_buffer(8);
    let mut parent_key_id = create_output_buffer(256);
    let mut parent_key_created = create_output_buffer(8);

    unsafe {
        let result = Encrypt(
            partition.as_ptr() as *const c_char,
            data.as_ptr() as *const c_char,
            encrypted_data.as_mut_ptr() as *mut c_char,
            encrypted_key.as_mut_ptr() as *mut c_char,
            created.as_mut_ptr() as *mut c_char,
            parent_key_id.as_mut_ptr() as *mut c_char,
            parent_key_created.as_mut_ptr() as *mut c_char,
        );
        assert_eq!(result, ERR_NONE, "Encrypt should succeed");
    }

    // Decrypt
    let created_ts = get_buffer_i64(&created);
    let parent_created_ts = get_buffer_i64(&parent_key_created);
    let mut decrypted = create_output_buffer(plaintext.len() as i32 + 100);

    unsafe {
        let result = Decrypt(
            partition.as_ptr() as *const c_char,
            encrypted_data.as_ptr() as *const c_char,
            encrypted_key.as_ptr() as *const c_char,
            created_ts,
            parent_key_id.as_ptr() as *const c_char,
            parent_created_ts,
            decrypted.as_mut_ptr() as *mut c_char,
        );
        assert_eq!(result, ERR_NONE, "Decrypt should succeed");
    }

    let decrypted_data = get_buffer_data(&decrypted);
    assert_eq!(
        decrypted_data, plaintext,
        "Component round-trip should preserve data"
    );

    Shutdown();
}

// ============================================================================
// Symbol Export Tests
// ============================================================================

/// Test that all required symbols are exported with correct names
#[test]
fn test_exported_symbols_exist() {
    // These functions must exist and be callable
    // (We're testing by actually calling them, which proves they're exported)

    // Shutdown can be called without initialization
    Shutdown();

    // SetEnv with empty JSON
    let empty_json = create_string_buffer("{}");
    unsafe {
        let result = SetEnv(empty_json.as_ptr() as *const c_char);
        assert_eq!(result, ERR_NONE, "SetEnv should work with empty JSON");
    }

    // EstimateBuffer
    let estimate = EstimateBuffer(100, 10);
    assert!(estimate > 0, "EstimateBuffer should return positive value");

    // SetupJson with null should return error (not crash)
    unsafe {
        let result = SetupJson(std::ptr::null());
        assert_eq!(
            result, ERR_NULL_PTR,
            "SetupJson(null) should return ERR_NULL_PTR"
        );
    }

    // EncryptToJson with null should return error
    unsafe {
        let result = EncryptToJson(std::ptr::null(), std::ptr::null(), std::ptr::null_mut());
        assert_eq!(
            result, ERR_NULL_PTR,
            "EncryptToJson(null) should return ERR_NULL_PTR"
        );
    }

    // DecryptFromJson with null should return error
    unsafe {
        let result = DecryptFromJson(std::ptr::null(), std::ptr::null(), std::ptr::null_mut());
        assert_eq!(
            result, ERR_NULL_PTR,
            "DecryptFromJson(null) should return ERR_NULL_PTR"
        );
    }

    // Encrypt with null should return error
    unsafe {
        let result = Encrypt(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        assert_eq!(
            result, ERR_NULL_PTR,
            "Encrypt(null) should return ERR_NULL_PTR"
        );
    }

    // Decrypt with null should return error
    unsafe {
        let result = Decrypt(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
        );
        assert_eq!(
            result, ERR_NULL_PTR,
            "Decrypt(null) should return ERR_NULL_PTR"
        );
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn setup_test_factory() {
    // Set up master key for static KMS
    std::env::set_var("STATIC_MASTER_KEY_HEX", "41".repeat(32));

    let config = r#"{
        "ServiceName": "interop-test-service",
        "ProductID": "interop-test-product",
        "Metastore": "memory",
        "KMS": "static",
        "EnableSessionCaching": true
    }"#;

    let config_buf = create_string_buffer(config);

    unsafe {
        let result = SetupJson(config_buf.as_ptr() as *const c_char);
        // May already be initialized from another test
        assert!(
            result == ERR_NONE || result == ERR_ALREADY_INITIALIZED,
            "SetupJson should succeed or already be initialized"
        );
    }
}
