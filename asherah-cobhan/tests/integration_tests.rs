//! Integration tests for asherah-cobhan
//!
//! These tests initialize the Asherah library and test full encrypt/decrypt workflows.
//! Since the library uses a global singleton factory, these tests must be run in a
//! single test binary with proper ordering.

use std::os::raw::c_char;

// Import from the library
use asherah_cobhan::test_helpers::{
    create_input_buffer, create_output_buffer, create_scalar_buffer, create_string_buffer,
    get_buffer_data, get_buffer_i64, get_buffer_length, get_buffer_string, ERR_ALREADY_INITIALIZED,
    ERR_BAD_CONFIG, ERR_BUFFER_TOO_SMALL, ERR_DECRYPT_FAILED, ERR_ENCRYPT_FAILED,
    ERR_JSON_DECODE_FAILED, ERR_NONE,
};
use asherah_cobhan::{
    Decrypt, DecryptFromJson, Encrypt, EncryptToJson, EstimateBuffer, SetEnv, SetupJson, Shutdown,
};

// ============================================================================
// Test Configuration
// ============================================================================

/// Creates a minimal configuration JSON for testing with in-memory metastore
fn create_test_config() -> String {
    r#"{
        "ServiceName": "test-service",
        "ProductID": "test-product",
        "Metastore": "memory",
        "KMS": "static",
        "Verbose": false,
        "EnableSessionCaching": true
    }"#
    .to_string()
}

// ============================================================================
// Integration Tests
// ============================================================================

/// Main integration test that runs the complete workflow
/// This test initializes the factory once and runs all encryption/decryption tests
#[test]
fn test_full_encryption_workflow() {
    // Setup phase
    let result = setup_asherah();
    assert_eq!(result, ERR_NONE, "SetupJson should succeed");

    // Run all subtests
    test_encrypt_to_json_and_decrypt_from_json();
    test_encrypt_and_decrypt_components();
    test_multiple_partitions();
    test_various_data_sizes();
    test_binary_data_encryption();
    test_unicode_data_encryption();
    test_empty_data_encryption();
    test_large_data_encryption();
    test_buffer_size_estimation();
    test_decrypt_with_wrong_partition();
    test_encrypt_decrypt_consistency();
    test_multiple_encryptions_different_ciphertext();
    test_encrypt_buffer_too_small();
    test_decrypt_buffer_too_small();
    test_decrypt_from_json_buffer_too_small();
    test_decrypt_wrong_partition_components();
    test_empty_partition_id();
    test_buffer_edge_cases_impl();
    test_decrypt_invalid_json_impl();

    // Shutdown and re-initialize lifecycle test
    test_shutdown_and_reinitialize_impl();
}

fn setup_asherah() -> i32 {
    let config = create_test_config();
    let config_buf = create_string_buffer(&config);

    unsafe { SetupJson(config_buf.as_ptr().cast::<c_char>()) }
}

// ============================================================================
// EncryptToJson / DecryptFromJson Tests
// ============================================================================

fn test_encrypt_to_json_and_decrypt_from_json() {
    let partition_id = "test-partition-json";
    let plaintext = b"Hello, World! This is a test message.";

    let partition_buf = create_string_buffer(partition_id);
    let data_buf = create_input_buffer(plaintext);

    // Estimate buffer size
    let estimate = EstimateBuffer(plaintext.len() as i32, partition_id.len() as i32);
    let mut json_output = create_output_buffer(estimate);

    // Encrypt
    unsafe {
        let result = EncryptToJson(
            partition_buf.as_ptr().cast::<c_char>(),
            data_buf.as_ptr().cast::<c_char>(),
            json_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "EncryptToJson should succeed");
    }

    // Verify JSON output is valid
    let json_str = get_buffer_string(&json_output);
    assert!(!json_str.is_empty(), "JSON output should not be empty");
    assert!(
        json_str.contains("\"Data\""),
        "JSON should contain Data field"
    );
    assert!(
        json_str.contains("\"Key\""),
        "JSON should contain Key field"
    );

    // Decrypt
    let mut decrypted_output = create_output_buffer(plaintext.len() as i32 + 100);

    unsafe {
        let result = DecryptFromJson(
            partition_buf.as_ptr().cast::<c_char>(),
            json_output.as_ptr().cast::<c_char>(),
            decrypted_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "DecryptFromJson should succeed");
    }

    // Verify decrypted data matches original
    let decrypted_data = get_buffer_data(&decrypted_output);
    assert_eq!(
        decrypted_data, plaintext,
        "Decrypted data should match original"
    );
}

// ============================================================================
// Encrypt / Decrypt Component Tests
// ============================================================================

fn test_encrypt_and_decrypt_components() {
    let partition_id = "test-partition-components";
    let plaintext = b"Component-based encryption test";

    let partition_buf = create_string_buffer(partition_id);
    let data_buf = create_input_buffer(plaintext);

    // Prepare output buffers for encryption
    let mut encrypted_data_buf = create_output_buffer(2048);
    let mut encrypted_key_buf = create_output_buffer(2048);
    let mut created_buf = create_scalar_buffer();
    let mut parent_key_id_buf = create_output_buffer(256);
    let mut parent_key_created_buf = create_scalar_buffer();

    // Encrypt
    unsafe {
        let result = Encrypt(
            partition_buf.as_ptr().cast::<c_char>(),
            data_buf.as_ptr().cast::<c_char>(),
            encrypted_data_buf.as_mut_ptr().cast::<c_char>(),
            encrypted_key_buf.as_mut_ptr().cast::<c_char>(),
            created_buf.as_mut_ptr().cast::<c_char>(),
            parent_key_id_buf.as_mut_ptr().cast::<c_char>(),
            parent_key_created_buf.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Encrypt should succeed");
    }

    // Verify outputs
    let encrypted_data = get_buffer_data(&encrypted_data_buf);
    assert!(
        !encrypted_data.is_empty(),
        "Encrypted data should not be empty"
    );

    let encrypted_key = get_buffer_data(&encrypted_key_buf);
    assert!(
        !encrypted_key.is_empty(),
        "Encrypted key should not be empty"
    );

    let created = get_buffer_i64(&created_buf);
    assert!(created > 0, "Created timestamp should be positive");

    // Decrypt
    let mut decrypted_output = create_output_buffer(plaintext.len() as i32 + 100);
    let parent_key_created = get_buffer_i64(&parent_key_created_buf);

    unsafe {
        let result = Decrypt(
            partition_buf.as_ptr().cast::<c_char>(),
            encrypted_data_buf.as_ptr().cast::<c_char>(),
            encrypted_key_buf.as_ptr().cast::<c_char>(),
            created,
            parent_key_id_buf.as_ptr().cast::<c_char>(),
            parent_key_created,
            decrypted_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Decrypt should succeed");
    }

    // Verify decrypted data
    let decrypted_data = get_buffer_data(&decrypted_output);
    assert_eq!(
        decrypted_data, plaintext,
        "Decrypted data should match original"
    );
}

// ============================================================================
// Multiple Partitions Test
// ============================================================================

fn test_multiple_partitions() {
    let partitions = [
        "partition-1",
        "partition-2",
        "partition-3",
        "user-123",
        "tenant-abc",
    ];

    for partition_id in partitions {
        let plaintext = format!("Data for partition: {}", partition_id);
        let plaintext_bytes = plaintext.as_bytes();

        let partition_buf = create_string_buffer(partition_id);
        let data_buf = create_input_buffer(plaintext_bytes);

        let estimate = EstimateBuffer(plaintext_bytes.len() as i32, partition_id.len() as i32);
        let mut json_output = create_output_buffer(estimate);

        // Encrypt
        unsafe {
            let result = EncryptToJson(
                partition_buf.as_ptr().cast::<c_char>(),
                data_buf.as_ptr().cast::<c_char>(),
                json_output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(
                result, ERR_NONE,
                "Encrypt should succeed for partition {}",
                partition_id
            );
        }

        // Decrypt
        let mut decrypted_output = create_output_buffer(plaintext_bytes.len() as i32 + 100);

        unsafe {
            let result = DecryptFromJson(
                partition_buf.as_ptr().cast::<c_char>(),
                json_output.as_ptr().cast::<c_char>(),
                decrypted_output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(
                result, ERR_NONE,
                "Decrypt should succeed for partition {}",
                partition_id
            );
        }

        let decrypted_data = get_buffer_data(&decrypted_output);
        assert_eq!(
            decrypted_data, plaintext_bytes,
            "Decrypted data should match for partition {}",
            partition_id
        );
    }
}

// ============================================================================
// Various Data Sizes Test
// ============================================================================

fn test_various_data_sizes() {
    let sizes = [1, 10, 100, 500, 1000, 5000, 10000];

    for size in sizes {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        let partition_buf = create_string_buffer("size-test");
        let data_buf = create_input_buffer(&plaintext);

        let estimate = EstimateBuffer(size, 9);
        let mut json_output = create_output_buffer(estimate);

        // Encrypt
        unsafe {
            let result = EncryptToJson(
                partition_buf.as_ptr().cast::<c_char>(),
                data_buf.as_ptr().cast::<c_char>(),
                json_output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(result, ERR_NONE, "Encrypt should succeed for size {}", size);
        }

        // Decrypt
        let mut decrypted_output = create_output_buffer(size + 100);

        unsafe {
            let result = DecryptFromJson(
                partition_buf.as_ptr().cast::<c_char>(),
                json_output.as_ptr().cast::<c_char>(),
                decrypted_output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(result, ERR_NONE, "Decrypt should succeed for size {}", size);
        }

        let decrypted_data = get_buffer_data(&decrypted_output);
        assert_eq!(
            decrypted_data, plaintext,
            "Decrypted data should match for size {}",
            size
        );
    }
}

// ============================================================================
// Binary Data Test
// ============================================================================

fn test_binary_data_encryption() {
    // Binary data with all byte values including null bytes
    let plaintext: Vec<u8> = (0u8..=255).collect();

    let partition_buf = create_string_buffer("binary-test");
    let data_buf = create_input_buffer(&plaintext);

    let estimate = EstimateBuffer(plaintext.len() as i32, 11);
    let mut json_output = create_output_buffer(estimate);

    // Encrypt
    unsafe {
        let result = EncryptToJson(
            partition_buf.as_ptr().cast::<c_char>(),
            data_buf.as_ptr().cast::<c_char>(),
            json_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Binary data encryption should succeed");
    }

    // Decrypt
    let mut decrypted_output = create_output_buffer(plaintext.len() as i32 + 100);

    unsafe {
        let result = DecryptFromJson(
            partition_buf.as_ptr().cast::<c_char>(),
            json_output.as_ptr().cast::<c_char>(),
            decrypted_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Binary data decryption should succeed");
    }

    let decrypted_data = get_buffer_data(&decrypted_output);
    assert_eq!(
        decrypted_data, plaintext,
        "Binary data should round-trip correctly"
    );
}

// ============================================================================
// Unicode Data Test
// ============================================================================

fn test_unicode_data_encryption() {
    let unicode_strings = [
        "Hello, World!",
        "Привет мир!",   // Russian
        "你好世界！",    // Chinese
        "مرحبا بالعالم", // Arabic
        "🦀🔐🎉💾",      // Emoji
        "Mixed: Hello 世界 🌍",
        "Special chars: \t\n\r\"'\\",
    ];

    for plaintext in unicode_strings {
        let plaintext_bytes = plaintext.as_bytes();

        let partition_buf = create_string_buffer("unicode-test");
        let data_buf = create_input_buffer(plaintext_bytes);

        let estimate = EstimateBuffer(plaintext_bytes.len() as i32, 12);
        let mut json_output = create_output_buffer(estimate);

        // Encrypt
        unsafe {
            let result = EncryptToJson(
                partition_buf.as_ptr().cast::<c_char>(),
                data_buf.as_ptr().cast::<c_char>(),
                json_output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(
                result, ERR_NONE,
                "Unicode encryption should succeed for: {}",
                plaintext
            );
        }

        // Decrypt
        let mut decrypted_output = create_output_buffer(plaintext_bytes.len() as i32 + 100);

        unsafe {
            let result = DecryptFromJson(
                partition_buf.as_ptr().cast::<c_char>(),
                json_output.as_ptr().cast::<c_char>(),
                decrypted_output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(
                result, ERR_NONE,
                "Unicode decryption should succeed for: {}",
                plaintext
            );
        }

        let decrypted_str = get_buffer_string(&decrypted_output);
        assert_eq!(
            decrypted_str, plaintext,
            "Unicode should round-trip correctly"
        );
    }
}

// ============================================================================
// Empty Data Test
// ============================================================================

fn test_empty_data_encryption() {
    let plaintext = b"";

    let partition_buf = create_string_buffer("empty-test");
    let data_buf = create_input_buffer(plaintext);

    let estimate = EstimateBuffer(0, 10);
    let mut json_output = create_output_buffer(estimate);

    // Encrypt
    unsafe {
        let result = EncryptToJson(
            partition_buf.as_ptr().cast::<c_char>(),
            data_buf.as_ptr().cast::<c_char>(),
            json_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Empty data encryption should succeed");
    }

    // Decrypt
    let mut decrypted_output = create_output_buffer(100);

    unsafe {
        let result = DecryptFromJson(
            partition_buf.as_ptr().cast::<c_char>(),
            json_output.as_ptr().cast::<c_char>(),
            decrypted_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Empty data decryption should succeed");
    }

    let decrypted_data = get_buffer_data(&decrypted_output);
    assert_eq!(
        decrypted_data, plaintext,
        "Empty data should round-trip correctly"
    );
}

// ============================================================================
// Large Data Test
// ============================================================================

fn test_large_data_encryption() {
    // 100KB of data
    let size = 100 * 1024;
    let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

    let partition_buf = create_string_buffer("large-test");
    let data_buf = create_input_buffer(&plaintext);

    let estimate = EstimateBuffer(size, 10);
    let mut json_output = create_output_buffer(estimate);

    // Encrypt
    unsafe {
        let result = EncryptToJson(
            partition_buf.as_ptr().cast::<c_char>(),
            data_buf.as_ptr().cast::<c_char>(),
            json_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Large data encryption should succeed");
    }

    // Decrypt
    let mut decrypted_output = create_output_buffer(size + 100);

    unsafe {
        let result = DecryptFromJson(
            partition_buf.as_ptr().cast::<c_char>(),
            json_output.as_ptr().cast::<c_char>(),
            decrypted_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Large data decryption should succeed");
    }

    let decrypted_data = get_buffer_data(&decrypted_output);
    assert_eq!(
        decrypted_data.len(),
        plaintext.len(),
        "Decrypted length should match"
    );
    assert_eq!(
        decrypted_data, plaintext,
        "Large data should round-trip correctly"
    );
}

// ============================================================================
// Buffer Size Estimation Test
// ============================================================================

fn test_buffer_size_estimation() {
    let test_cases = [(100, 10), (1000, 50), (10000, 100), (50000, 200)];

    for (data_len, partition_len) in test_cases {
        let estimate = EstimateBuffer(data_len, partition_len);

        // Generate test data
        let plaintext: Vec<u8> = (0..data_len as usize).map(|i| (i % 256) as u8).collect();
        let partition_id: String = (0..partition_len as usize).map(|_| 'x').collect();

        let partition_buf = create_string_buffer(&partition_id);
        let data_buf = create_input_buffer(&plaintext);

        let mut json_output = create_output_buffer(estimate);

        // Encrypt should succeed with estimated buffer size
        unsafe {
            let result = EncryptToJson(
                partition_buf.as_ptr().cast::<c_char>(),
                data_buf.as_ptr().cast::<c_char>(),
                json_output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(
                result, ERR_NONE,
                "Encryption should succeed with estimated buffer for data_len={}, partition_len={}",
                data_len, partition_len
            );
        }

        // Verify the actual output length doesn't exceed the estimate
        let actual_len = get_buffer_length(&json_output);
        assert!(
            actual_len <= estimate,
            "Actual output length {} should not exceed estimate {} for data_len={}, partition_len={}",
            actual_len, estimate, data_len, partition_len
        );
    }
}

// ============================================================================
// Wrong Partition Test
// ============================================================================

fn test_decrypt_with_wrong_partition() {
    let plaintext = b"Secret data";

    let partition1_buf = create_string_buffer("correct-partition");
    let partition2_buf = create_string_buffer("wrong-partition");
    let data_buf = create_input_buffer(plaintext);

    let estimate = EstimateBuffer(plaintext.len() as i32, 17);
    let mut json_output = create_output_buffer(estimate);

    // Encrypt with partition 1
    unsafe {
        let result = EncryptToJson(
            partition1_buf.as_ptr().cast::<c_char>(),
            data_buf.as_ptr().cast::<c_char>(),
            json_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Encryption should succeed");
    }

    // Try to decrypt with partition 2 - this should fail
    let mut decrypted_output = create_output_buffer(plaintext.len() as i32 + 100);

    unsafe {
        let result = DecryptFromJson(
            partition2_buf.as_ptr().cast::<c_char>(),
            json_output.as_ptr().cast::<c_char>(),
            decrypted_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_DECRYPT_FAILED,
            "Decryption with wrong partition should fail"
        );
    }
}

// ============================================================================
// Consistency Test
// ============================================================================

fn test_encrypt_decrypt_consistency() {
    // Encrypt the same data multiple times and verify all decrypt correctly
    let plaintext = b"Consistency test data";
    let partition_buf = create_string_buffer("consistency-test");
    let data_buf = create_input_buffer(plaintext);

    let estimate = EstimateBuffer(plaintext.len() as i32, 16);

    let mut encrypted_jsons = Vec::new();

    // Encrypt 5 times
    for _ in 0..5 {
        let mut json_output = create_output_buffer(estimate);

        unsafe {
            let result = EncryptToJson(
                partition_buf.as_ptr().cast::<c_char>(),
                data_buf.as_ptr().cast::<c_char>(),
                json_output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(result, ERR_NONE, "Encryption should succeed");
        }

        encrypted_jsons.push(json_output);
    }

    // Decrypt all and verify
    for (i, json_buf) in encrypted_jsons.iter().enumerate() {
        let mut decrypted_output = create_output_buffer(plaintext.len() as i32 + 100);

        unsafe {
            let result = DecryptFromJson(
                partition_buf.as_ptr().cast::<c_char>(),
                json_buf.as_ptr().cast::<c_char>(),
                decrypted_output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(result, ERR_NONE, "Decryption {} should succeed", i);
        }

        let decrypted_data = get_buffer_data(&decrypted_output);
        assert_eq!(
            decrypted_data, plaintext,
            "Decrypted data {} should match original",
            i
        );
    }
}

// ============================================================================
// Different Ciphertext Test
// ============================================================================

fn test_multiple_encryptions_different_ciphertext() {
    // Encrypt the same data multiple times - ciphertexts should be different
    // (due to random IV/nonce)
    let plaintext = b"Same plaintext, different ciphertext";
    let partition_buf = create_string_buffer("ciphertext-test");
    let data_buf = create_input_buffer(plaintext);

    let estimate = EstimateBuffer(plaintext.len() as i32, 15);

    let mut ciphertexts = Vec::new();

    // Encrypt 3 times
    for _ in 0..3 {
        let mut json_output = create_output_buffer(estimate);

        unsafe {
            let result = EncryptToJson(
                partition_buf.as_ptr().cast::<c_char>(),
                data_buf.as_ptr().cast::<c_char>(),
                json_output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(result, ERR_NONE, "Encryption should succeed");
        }

        ciphertexts.push(get_buffer_string(&json_output));
    }

    // Verify ciphertexts are different
    for i in 0..ciphertexts.len() {
        for j in (i + 1)..ciphertexts.len() {
            assert_ne!(
                ciphertexts[i], ciphertexts[j],
                "Ciphertexts {} and {} should be different",
                i, j
            );
        }
    }
}

// ============================================================================
// Buffer Too Small Tests (called from test_full_encryption_workflow)
// ============================================================================

fn test_encrypt_buffer_too_small() {
    let partition = create_string_buffer("buffer-small-test");
    let data = create_input_buffer(b"data to encrypt for buffer test");

    // Undersized encrypted data buffer
    let mut tiny_data = create_output_buffer(1);
    let mut key_buf = create_output_buffer(4096);
    let mut created = create_scalar_buffer();
    let mut parent_key_id = create_output_buffer(256);
    let mut parent_key_created = create_scalar_buffer();

    unsafe {
        let result = Encrypt(
            partition.as_ptr().cast::<c_char>(),
            data.as_ptr().cast::<c_char>(),
            tiny_data.as_mut_ptr().cast::<c_char>(),
            key_buf.as_mut_ptr().cast::<c_char>(),
            created.as_mut_ptr().cast::<c_char>(),
            parent_key_id.as_mut_ptr().cast::<c_char>(),
            parent_key_created.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_BUFFER_TOO_SMALL,
            "Encrypt with tiny encrypted_data buffer should return ERR_BUFFER_TOO_SMALL"
        );
    }

    // Undersized encrypted key buffer
    let mut data_buf = create_output_buffer(4096);
    let mut tiny_key = create_output_buffer(1);

    unsafe {
        let result = Encrypt(
            partition.as_ptr().cast::<c_char>(),
            data.as_ptr().cast::<c_char>(),
            data_buf.as_mut_ptr().cast::<c_char>(),
            tiny_key.as_mut_ptr().cast::<c_char>(),
            created.as_mut_ptr().cast::<c_char>(),
            parent_key_id.as_mut_ptr().cast::<c_char>(),
            parent_key_created.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_BUFFER_TOO_SMALL,
            "Encrypt with tiny encrypted_key buffer should return ERR_BUFFER_TOO_SMALL"
        );
    }

    // Undersized parent key ID buffer
    let mut data_buf2 = create_output_buffer(4096);
    let mut key_buf2 = create_output_buffer(4096);
    let mut tiny_parent = create_output_buffer(1);

    unsafe {
        let result = Encrypt(
            partition.as_ptr().cast::<c_char>(),
            data.as_ptr().cast::<c_char>(),
            data_buf2.as_mut_ptr().cast::<c_char>(),
            key_buf2.as_mut_ptr().cast::<c_char>(),
            created.as_mut_ptr().cast::<c_char>(),
            tiny_parent.as_mut_ptr().cast::<c_char>(),
            parent_key_created.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_BUFFER_TOO_SMALL,
            "Encrypt with tiny parent_key_id buffer should return ERR_BUFFER_TOO_SMALL"
        );
    }
}

fn test_decrypt_buffer_too_small() {
    let partition = create_string_buffer("decrypt-small-test");
    let plaintext = b"data for decrypt buffer test with enough content";
    let data = create_input_buffer(plaintext);

    // First encrypt to get valid components
    let mut encrypted_data = create_output_buffer(4096);
    let mut encrypted_key = create_output_buffer(4096);
    let mut created = create_scalar_buffer();
    let mut parent_key_id = create_output_buffer(256);
    let mut parent_key_created = create_scalar_buffer();

    unsafe {
        let result = Encrypt(
            partition.as_ptr().cast::<c_char>(),
            data.as_ptr().cast::<c_char>(),
            encrypted_data.as_mut_ptr().cast::<c_char>(),
            encrypted_key.as_mut_ptr().cast::<c_char>(),
            created.as_mut_ptr().cast::<c_char>(),
            parent_key_id.as_mut_ptr().cast::<c_char>(),
            parent_key_created.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Encrypt should succeed");
    }

    // Try to decrypt into a tiny buffer
    let created_ts = get_buffer_i64(&created);
    let parent_created_ts = get_buffer_i64(&parent_key_created);
    let mut tiny_output = create_output_buffer(1);

    unsafe {
        let result = Decrypt(
            partition.as_ptr().cast::<c_char>(),
            encrypted_data.as_ptr().cast::<c_char>(),
            encrypted_key.as_ptr().cast::<c_char>(),
            created_ts,
            parent_key_id.as_ptr().cast::<c_char>(),
            parent_created_ts,
            tiny_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_BUFFER_TOO_SMALL,
            "Decrypt with tiny output buffer should return ERR_BUFFER_TOO_SMALL"
        );
    }
}

fn test_decrypt_from_json_buffer_too_small() {
    let partition = create_string_buffer("json-small-test");
    let plaintext = b"data for json decrypt buffer test with enough content";
    let data = create_input_buffer(plaintext);

    // Encrypt to get valid JSON
    let estimate = EstimateBuffer(plaintext.len() as i32, 15);
    let mut json_output = create_output_buffer(estimate);

    unsafe {
        let result = EncryptToJson(
            partition.as_ptr().cast::<c_char>(),
            data.as_ptr().cast::<c_char>(),
            json_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "EncryptToJson should succeed");
    }

    // Try to decrypt into a tiny buffer
    let mut tiny_output = create_output_buffer(1);

    unsafe {
        let result = DecryptFromJson(
            partition.as_ptr().cast::<c_char>(),
            json_output.as_ptr().cast::<c_char>(),
            tiny_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_BUFFER_TOO_SMALL,
            "DecryptFromJson with tiny output buffer should return ERR_BUFFER_TOO_SMALL"
        );
    }
}

fn test_decrypt_wrong_partition_components() {
    let partition1 = create_string_buffer("correct-component-partition");
    let partition2 = create_string_buffer("wrong-component-partition");
    let plaintext = b"component partition test data";
    let data = create_input_buffer(plaintext);

    // Encrypt with partition 1
    let mut encrypted_data = create_output_buffer(4096);
    let mut encrypted_key = create_output_buffer(4096);
    let mut created = create_scalar_buffer();
    let mut parent_key_id = create_output_buffer(256);
    let mut parent_key_created = create_scalar_buffer();

    unsafe {
        let result = Encrypt(
            partition1.as_ptr().cast::<c_char>(),
            data.as_ptr().cast::<c_char>(),
            encrypted_data.as_mut_ptr().cast::<c_char>(),
            encrypted_key.as_mut_ptr().cast::<c_char>(),
            created.as_mut_ptr().cast::<c_char>(),
            parent_key_id.as_mut_ptr().cast::<c_char>(),
            parent_key_created.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Encrypt should succeed");
    }

    // Decrypt with partition 2 - should fail
    let created_ts = get_buffer_i64(&created);
    let parent_created_ts = get_buffer_i64(&parent_key_created);
    let mut output = create_output_buffer(plaintext.len() as i32 + 100);

    unsafe {
        let result = Decrypt(
            partition2.as_ptr().cast::<c_char>(),
            encrypted_data.as_ptr().cast::<c_char>(),
            encrypted_key.as_ptr().cast::<c_char>(),
            created_ts,
            parent_key_id.as_ptr().cast::<c_char>(),
            parent_created_ts,
            output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_DECRYPT_FAILED,
            "Decrypt with wrong partition should return ERR_DECRYPT_FAILED"
        );
    }
}

fn test_empty_partition_id() {
    let partition = create_string_buffer("");
    let plaintext = b"data with empty partition";
    let data = create_input_buffer(plaintext);

    let estimate = EstimateBuffer(plaintext.len() as i32, 0);
    let mut json_output = create_output_buffer(estimate);

    // Empty partition IDs are rejected by the asherah library
    unsafe {
        let result = EncryptToJson(
            partition.as_ptr().cast::<c_char>(),
            data.as_ptr().cast::<c_char>(),
            json_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_ENCRYPT_FAILED,
            "EncryptToJson with empty partition should fail"
        );
    }
}

// ============================================================================
// SetEnv Integration Test
// ============================================================================

#[test]
fn test_set_env_integration() {
    let pid = std::process::id();
    let key1 = format!("ASHERAH_INT_TEST_1_{}", pid);
    let key2 = format!("ASHERAH_INT_TEST_2_{}", pid);

    let json = format!(r#"{{"{key1}": "integration_value_1", "{key2}": "integration_value_2"}}"#);
    let buf = create_string_buffer(&json);

    unsafe {
        let result = SetEnv(buf.as_ptr().cast::<c_char>());
        assert_eq!(result, ERR_NONE, "SetEnv should succeed");
    }

    assert_eq!(
        std::env::var(&key1).ok(),
        Some("integration_value_1".to_string()),
        "Environment variable should be set"
    );
    assert_eq!(
        std::env::var(&key2).ok(),
        Some("integration_value_2".to_string()),
        "Environment variable should be set"
    );

    // Cleanup
    std::env::remove_var(&key1);
    std::env::remove_var(&key2);
}

// ============================================================================
// Shutdown and Re-initialize Test
// ============================================================================

fn test_shutdown_and_reinitialize_impl() {
    // Shutdown the factory that was initialized by the parent test
    Shutdown();

    // Re-initialize
    let result = setup_asherah();
    assert_eq!(result, ERR_NONE, "SetupJson after Shutdown should succeed");

    // Encrypt some data with the new factory
    let partition = create_string_buffer("reinit-test");
    let plaintext = b"data before shutdown";
    let data = create_input_buffer(plaintext);
    let estimate = EstimateBuffer(plaintext.len() as i32, 11);
    let mut json1 = create_output_buffer(estimate);

    unsafe {
        let result = EncryptToJson(
            partition.as_ptr().cast::<c_char>(),
            data.as_ptr().cast::<c_char>(),
            json1.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Encrypt before shutdown should succeed");
    }

    // Shutdown
    Shutdown();

    // Re-initialize
    let result = setup_asherah();
    assert_eq!(result, ERR_NONE, "SetupJson after Shutdown should succeed");

    // Encrypt again with the new factory
    let plaintext2 = b"data after re-initialize";
    let data2 = create_input_buffer(plaintext2);
    let estimate2 = EstimateBuffer(plaintext2.len() as i32, 11);
    let mut json2 = create_output_buffer(estimate2);

    unsafe {
        let result = EncryptToJson(
            partition.as_ptr().cast::<c_char>(),
            data2.as_ptr().cast::<c_char>(),
            json2.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_NONE,
            "Encrypt after re-initialize should succeed"
        );
    }

    // Decrypt the second encryption
    let mut decrypted = create_output_buffer(plaintext2.len() as i32 + 100);

    unsafe {
        let result = DecryptFromJson(
            partition.as_ptr().cast::<c_char>(),
            json2.as_ptr().cast::<c_char>(),
            decrypted.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_NONE,
            "Decrypt after re-initialize should succeed"
        );
    }

    let decrypted_data = get_buffer_data(&decrypted);
    assert_eq!(
        decrypted_data, plaintext2,
        "Decrypted data should match after re-initialization"
    );

    Shutdown();
}

// ============================================================================
// Error Handling Tests
// ============================================================================
// NOTE: ERR_NOT_INITIALIZED tests are in tests/uninitialized_tests.rs
// (a separate binary that runs in a guaranteed-clean process).

#[test]
fn test_invalid_json_config() {
    let invalid_configs = [
        "not json at all",
        "{incomplete json",
        r#"{"ServiceName": "test"}"#, // Missing required fields
        "{}",                         // Empty config
    ];

    for config in invalid_configs {
        let buf = create_string_buffer(config);

        unsafe {
            let result = SetupJson(buf.as_ptr().cast::<c_char>());
            // Should return BAD_CONFIG or ALREADY_INITIALIZED (if another test ran first)
            assert!(
                result == ERR_BAD_CONFIG || result == ERR_ALREADY_INITIALIZED,
                "Invalid config '{}' should fail with BAD_CONFIG or ALREADY_INITIALIZED, got {}",
                config,
                result
            );
        }
    }
}

fn test_decrypt_invalid_json_impl() {
    let partition_buf = create_string_buffer("test");
    let invalid_json = create_string_buffer("not valid json");
    let mut output = create_output_buffer(100);

    unsafe {
        let result = DecryptFromJson(
            partition_buf.as_ptr().cast::<c_char>(),
            invalid_json.as_ptr().cast::<c_char>(),
            output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_JSON_DECODE_FAILED,
            "DecryptFromJson with invalid JSON should return ERR_JSON_DECODE_FAILED"
        );
    }
}

fn test_buffer_edge_cases_impl() {
    let partition_buf = create_string_buffer("edge-test");
    let data_buf = create_input_buffer(b"x");

    // Very small output buffer - should fail with buffer too small
    let mut tiny_output = create_output_buffer(1);

    unsafe {
        let result = EncryptToJson(
            partition_buf.as_ptr().cast::<c_char>(),
            data_buf.as_ptr().cast::<c_char>(),
            tiny_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_BUFFER_TOO_SMALL,
            "EncryptToJson with tiny buffer should return ERR_BUFFER_TOO_SMALL"
        );
    }
}
