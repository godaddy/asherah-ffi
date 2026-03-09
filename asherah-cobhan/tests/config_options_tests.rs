//! Tests for configurable cobhan options: DisableZeroCopy, NullDataCheck, Verbose, EnableCanaries.
//!
//! Each test does its own SetupJson/Shutdown cycle with specific config flags.
//! Uses harness=false to run sequentially since Setup/Shutdown uses global state.

use std::os::raw::c_char;

use asherah_cobhan::test_helpers::{
    create_input_buffer, create_output_buffer, create_string_buffer, get_buffer_data,
    get_buffer_string, verify_output_canaries, ERR_NONE,
};
use asherah_cobhan::{
    DecryptFromJson, Encrypt, EncryptToJson, EstimateBuffer, SetupJson, Shutdown,
};

// ============================================================================
// Helpers
// ============================================================================

fn setup_with_config(config_json: &str) -> i32 {
    let buf = create_string_buffer(config_json);
    unsafe { SetupJson(buf.as_ptr().cast::<c_char>()) }
}

fn encrypt_roundtrip_json(partition: &str, plaintext: &[u8]) -> Vec<u8> {
    let partition_buf = create_string_buffer(partition);
    let data_buf = create_input_buffer(plaintext);
    let estimate = EstimateBuffer(plaintext.len() as i32, partition.len() as i32);
    let mut json_output = create_output_buffer(estimate);

    unsafe {
        let result = EncryptToJson(
            partition_buf.as_ptr().cast::<c_char>(),
            data_buf.as_ptr().cast::<c_char>(),
            json_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "EncryptToJson should succeed");
    }
    verify_output_canaries(&json_output, estimate);

    // Decrypt
    let decrypt_capacity = plaintext.len() as i32 + 100;
    let mut decrypted_output = create_output_buffer(decrypt_capacity);
    unsafe {
        let result = DecryptFromJson(
            partition_buf.as_ptr().cast::<c_char>(),
            json_output.as_ptr().cast::<c_char>(),
            decrypted_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "DecryptFromJson should succeed");
    }
    verify_output_canaries(&decrypted_output, decrypt_capacity);
    get_buffer_data(&decrypted_output).to_vec()
}

fn encrypt_roundtrip_components(partition: &str, plaintext: &[u8]) -> Vec<u8> {
    use asherah_cobhan::test_helpers::{create_scalar_buffer, get_buffer_i64};
    use asherah_cobhan::Decrypt;

    let partition_buf = create_string_buffer(partition);
    let data_buf = create_input_buffer(plaintext);

    let mut encrypted_data = create_output_buffer(4096);
    let mut encrypted_key = create_output_buffer(4096);
    let mut created = create_scalar_buffer();
    let mut parent_key_id = create_output_buffer(256);
    let mut parent_key_created = create_scalar_buffer();

    unsafe {
        let result = Encrypt(
            partition_buf.as_ptr().cast::<c_char>(),
            data_buf.as_ptr().cast::<c_char>(),
            encrypted_data.as_mut_ptr().cast::<c_char>(),
            encrypted_key.as_mut_ptr().cast::<c_char>(),
            created.as_mut_ptr().cast::<c_char>(),
            parent_key_id.as_mut_ptr().cast::<c_char>(),
            parent_key_created.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Encrypt should succeed");
    }
    verify_output_canaries(&encrypted_data, 4096);
    verify_output_canaries(&encrypted_key, 4096);
    verify_output_canaries(&parent_key_id, 256);

    let created_ts = get_buffer_i64(&created);
    let parent_created_ts = get_buffer_i64(&parent_key_created);
    let decrypt_capacity = plaintext.len() as i32 + 100;
    let mut decrypted_output = create_output_buffer(decrypt_capacity);

    unsafe {
        let result = Decrypt(
            partition_buf.as_ptr().cast::<c_char>(),
            encrypted_data.as_ptr().cast::<c_char>(),
            encrypted_key.as_ptr().cast::<c_char>(),
            created_ts,
            parent_key_id.as_ptr().cast::<c_char>(),
            parent_created_ts,
            decrypted_output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(result, ERR_NONE, "Decrypt should succeed");
    }
    verify_output_canaries(&decrypted_output, decrypt_capacity);
    get_buffer_data(&decrypted_output).to_vec()
}

// ============================================================================
// Test functions
// ============================================================================

fn test_zero_copy_enabled_roundtrip() {
    let config = r#"{
        "ServiceName": "zc-test",
        "ProductID": "zc-prod",
        "Metastore": "memory",
        "KMS": "static",
        "DisableZeroCopy": false,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    let plaintext = b"zero-copy enabled payload";
    let result = encrypt_roundtrip_json("zc-partition", plaintext);
    assert_eq!(
        result, plaintext,
        "Zero-copy roundtrip via JSON should work"
    );

    let result2 = encrypt_roundtrip_components("zc-partition", plaintext);
    assert_eq!(
        result2, plaintext,
        "Zero-copy roundtrip via components should work"
    );

    Shutdown();
}

fn test_zero_copy_disabled_roundtrip() {
    let config = r#"{
        "ServiceName": "nozc-test",
        "ProductID": "nozc-prod",
        "Metastore": "memory",
        "KMS": "static",
        "DisableZeroCopy": true,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    let plaintext = b"zero-copy disabled payload";
    let result = encrypt_roundtrip_json("nozc-partition", plaintext);
    assert_eq!(
        result, plaintext,
        "Copy-mode roundtrip via JSON should work"
    );

    let result2 = encrypt_roundtrip_components("nozc-partition", plaintext);
    assert_eq!(
        result2, plaintext,
        "Copy-mode roundtrip via components should work"
    );

    Shutdown();
}

fn test_zero_copy_large_data() {
    let config = r#"{
        "ServiceName": "zclarge-test",
        "ProductID": "zclarge-prod",
        "Metastore": "memory",
        "KMS": "static",
        "DisableZeroCopy": false,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    // 50KB payload
    let plaintext: Vec<u8> = (0..50 * 1024).map(|i| (i % 256) as u8).collect();
    let result = encrypt_roundtrip_json("zclarge-partition", &plaintext);
    assert_eq!(result, plaintext, "Large zero-copy roundtrip should work");

    Shutdown();
}

fn test_null_data_check_normal_data() {
    let config = r#"{
        "ServiceName": "ndc-test",
        "ProductID": "ndc-prod",
        "Metastore": "memory",
        "KMS": "static",
        "NullDataCheck": true,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    let plaintext = b"non-null data for null check test";
    let result = encrypt_roundtrip_json("ndc-partition", plaintext);
    assert_eq!(
        result, plaintext,
        "NullDataCheck with non-null data should round-trip"
    );

    let result2 = encrypt_roundtrip_components("ndc-partition", plaintext);
    assert_eq!(
        result2, plaintext,
        "NullDataCheck component roundtrip should work"
    );

    Shutdown();
}

fn test_null_data_check_with_null_input() {
    let config = r#"{
        "ServiceName": "ndcnull-test",
        "ProductID": "ndcnull-prod",
        "Metastore": "memory",
        "KMS": "static",
        "NullDataCheck": true,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    // All-null input data (should trigger the null check log but still encrypt)
    let null_data = vec![0u8; 32];
    let partition_buf = create_string_buffer("ndcnull-partition");
    let data_buf = create_input_buffer(&null_data);
    let estimate = EstimateBuffer(null_data.len() as i32, 17);
    let mut json_output = create_output_buffer(estimate);

    unsafe {
        let result = EncryptToJson(
            partition_buf.as_ptr().cast::<c_char>(),
            data_buf.as_ptr().cast::<c_char>(),
            json_output.as_mut_ptr().cast::<c_char>(),
        );
        // Should succeed (NullDataCheck only logs, doesn't fail)
        assert_eq!(
            result, ERR_NONE,
            "EncryptToJson with null data should still succeed"
        );
    }

    // Verify the JSON output is valid
    let json_str = get_buffer_string(&json_output);
    assert!(
        json_str.contains("\"Data\""),
        "Output should contain encrypted data"
    );

    Shutdown();
}

fn test_null_data_check_disabled() {
    let config = r#"{
        "ServiceName": "ndcoff-test",
        "ProductID": "ndcoff-prod",
        "Metastore": "memory",
        "KMS": "static",
        "NullDataCheck": false,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    let null_data = vec![0u8; 64];
    let result = encrypt_roundtrip_json("ndcoff-partition", &null_data);
    assert_eq!(
        result, null_data,
        "Null data with NullDataCheck off should round-trip"
    );

    Shutdown();
}

fn test_null_data_check_short_buffer() {
    let config = r#"{
        "ServiceName": "ndcshort-test",
        "ProductID": "ndcshort-prod",
        "Metastore": "memory",
        "KMS": "static",
        "NullDataCheck": true,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    // 10-byte all-null buffer (shorter than 64-byte check window)
    let null_data = vec![0u8; 10];
    let result = encrypt_roundtrip_json("ndcshort-partition", &null_data);
    assert_eq!(
        result, null_data,
        "Short null data should round-trip with NullDataCheck"
    );

    Shutdown();
}

fn test_null_data_check_long_non_null_prefix() {
    let config = r#"{
        "ServiceName": "ndclong-test",
        "ProductID": "ndclong-prod",
        "Metastore": "memory",
        "KMS": "static",
        "NullDataCheck": true,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    // 128 bytes: first 64 non-null, rest all null
    // Should NOT trigger null check since first 64 bytes aren't all null
    let mut data = vec![0xABu8; 64];
    data.extend(vec![0u8; 64]);
    let result = encrypt_roundtrip_json("ndclong-partition", &data);
    assert_eq!(result, data, "Non-null prefix data should round-trip");

    Shutdown();
}

fn test_verbose_enabled() {
    let config = r#"{
        "ServiceName": "verbose-test",
        "ProductID": "verbose-prod",
        "Metastore": "memory",
        "KMS": "static",
        "Verbose": true,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    let plaintext = b"verbose mode payload";
    let result = encrypt_roundtrip_json("verbose-partition", plaintext);
    assert_eq!(
        result, plaintext,
        "Verbose mode should not affect roundtrip"
    );

    Shutdown();
}

fn test_all_options_enabled() {
    let config = r#"{
        "ServiceName": "all-opts-test",
        "ProductID": "all-opts-prod",
        "Metastore": "memory",
        "KMS": "static",
        "DisableZeroCopy": true,
        "NullDataCheck": true,
        "Verbose": true,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    let plaintext = b"all options enabled payload";
    let result = encrypt_roundtrip_json("all-opts-partition", plaintext);
    assert_eq!(
        result, plaintext,
        "All options enabled roundtrip should work"
    );

    let result2 = encrypt_roundtrip_components("all-opts-partition", plaintext);
    assert_eq!(
        result2, plaintext,
        "All options enabled component roundtrip should work"
    );

    Shutdown();
}

fn test_options_toggle_between_cycles() {
    // First cycle: zero-copy enabled
    let config1 = r#"{
        "ServiceName": "toggle-test",
        "ProductID": "toggle-prod",
        "Metastore": "memory",
        "KMS": "static",
        "DisableZeroCopy": false,
        "NullDataCheck": false,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config1), ERR_NONE);

    let plaintext1 = b"first cycle data";
    let result1 = encrypt_roundtrip_json("toggle-partition", plaintext1);
    assert_eq!(result1, plaintext1, "First cycle roundtrip should work");

    Shutdown();

    // Second cycle: zero-copy disabled, null check enabled
    let config2 = r#"{
        "ServiceName": "toggle-test",
        "ProductID": "toggle-prod",
        "Metastore": "memory",
        "KMS": "static",
        "DisableZeroCopy": true,
        "NullDataCheck": true,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config2), ERR_NONE);

    let plaintext2 = b"second cycle data";
    let result2 = encrypt_roundtrip_json("toggle-partition", plaintext2);
    assert_eq!(result2, plaintext2, "Second cycle roundtrip should work");

    Shutdown();
}

// ============================================================================
// Canary Tests
// ============================================================================

fn test_canaries_enabled_json_roundtrip() {
    let config = r#"{
        "ServiceName": "canary-test",
        "ProductID": "canary-prod",
        "Metastore": "memory",
        "KMS": "static",
        "EnableCanaries": true,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);
    assert!(
        asherah_cobhan::canaries_enabled(),
        "Canaries should be enabled after setup"
    );

    let plaintext = b"canary-protected payload";
    let result = encrypt_roundtrip_json("canary-partition", plaintext);
    assert_eq!(
        result, plaintext,
        "Canary-enabled roundtrip via JSON should work"
    );

    Shutdown();
    // Canaries should remain enabled until next setup changes them
}

fn test_canaries_enabled_component_roundtrip() {
    let config = r#"{
        "ServiceName": "canary-comp",
        "ProductID": "canary-comp-prod",
        "Metastore": "memory",
        "KMS": "static",
        "EnableCanaries": true,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    let plaintext = b"canary component test";
    let result = encrypt_roundtrip_components("canary-comp-part", plaintext);
    assert_eq!(
        result, plaintext,
        "Canary-enabled roundtrip via components should work"
    );

    Shutdown();
}

fn test_canaries_enabled_large_data() {
    let config = r#"{
        "ServiceName": "canary-large",
        "ProductID": "canary-large-prod",
        "Metastore": "memory",
        "KMS": "static",
        "EnableCanaries": true,
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);

    // 50KB payload
    let plaintext: Vec<u8> = (0..50 * 1024).map(|i| (i % 256) as u8).collect();
    let result = encrypt_roundtrip_json("canary-large-part", &plaintext);
    assert_eq!(
        result, plaintext,
        "Large canary-enabled roundtrip should work"
    );

    Shutdown();
}

fn test_canaries_disabled_by_default() {
    // Reset canaries state by running setup without EnableCanaries
    let config = r#"{
        "ServiceName": "no-canary",
        "ProductID": "no-canary-prod",
        "Metastore": "memory",
        "KMS": "static",
        "EnableSessionCaching": false
    }"#;
    assert_eq!(setup_with_config(config), ERR_NONE);
    assert!(
        !asherah_cobhan::canaries_enabled(),
        "Canaries should be disabled by default"
    );

    let plaintext = b"no canary payload";
    let result = encrypt_roundtrip_json("no-canary-part", plaintext);
    assert_eq!(result, plaintext, "Roundtrip without canaries should work");

    Shutdown();
}

// ============================================================================
// Main — runs all tests sequentially (harness=false)
// ============================================================================

fn run_test(name: &str, f: fn()) {
    print!("test {} ... ", name);
    f();
    println!("ok");
}

fn main() {
    run_test(
        "test_zero_copy_enabled_roundtrip",
        test_zero_copy_enabled_roundtrip,
    );
    run_test(
        "test_zero_copy_disabled_roundtrip",
        test_zero_copy_disabled_roundtrip,
    );
    run_test("test_zero_copy_large_data", test_zero_copy_large_data);
    run_test(
        "test_null_data_check_normal_data",
        test_null_data_check_normal_data,
    );
    run_test(
        "test_null_data_check_with_null_input",
        test_null_data_check_with_null_input,
    );
    run_test(
        "test_null_data_check_disabled",
        test_null_data_check_disabled,
    );
    run_test(
        "test_null_data_check_short_buffer",
        test_null_data_check_short_buffer,
    );
    run_test(
        "test_null_data_check_long_non_null_prefix",
        test_null_data_check_long_non_null_prefix,
    );
    run_test("test_verbose_enabled", test_verbose_enabled);
    run_test("test_all_options_enabled", test_all_options_enabled);
    run_test(
        "test_options_toggle_between_cycles",
        test_options_toggle_between_cycles,
    );
    run_test(
        "test_canaries_enabled_json_roundtrip",
        test_canaries_enabled_json_roundtrip,
    );
    run_test(
        "test_canaries_enabled_component_roundtrip",
        test_canaries_enabled_component_roundtrip,
    );
    run_test(
        "test_canaries_enabled_large_data",
        test_canaries_enabled_large_data,
    );
    run_test(
        "test_canaries_disabled_by_default",
        test_canaries_disabled_by_default,
    );

    println!("\ntest result: ok. 15 passed; 0 failed");
}
