//! Tests for cobhan functions called without prior initialization.
//!
//! These tests run in a separate test binary, guaranteeing a fresh process
//! with no factory initialized. This makes ERR_NOT_INITIALIZED assertions
//! deterministic (unlike tests in the main integration binary where parallel
//! tests may have already called SetupJson).

use std::os::raw::c_char;

use asherah_cobhan::test_helpers::{
    create_input_buffer, create_output_buffer, create_scalar_buffer, create_string_buffer,
    ERR_NOT_INITIALIZED,
};
use asherah_cobhan::{Decrypt, DecryptFromJson, Encrypt, EncryptToJson};

#[test]
fn test_encrypt_to_json_not_initialized() {
    let partition = create_string_buffer("test-partition");
    let data = create_input_buffer(b"test data");
    let mut output = create_output_buffer(4096);

    unsafe {
        let result = EncryptToJson(
            partition.as_ptr().cast::<c_char>(),
            data.as_ptr().cast::<c_char>(),
            output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_NOT_INITIALIZED,
            "EncryptToJson should return ERR_NOT_INITIALIZED when factory is not set up"
        );
    }
}

#[test]
fn test_decrypt_from_json_not_initialized() {
    let partition = create_string_buffer("test-partition");
    let json = create_string_buffer(r#"{"Data":"dGVzdA==","Key":{"Created":1,"Key":"a2V5"}}"#);
    let mut output = create_output_buffer(4096);

    unsafe {
        let result = DecryptFromJson(
            partition.as_ptr().cast::<c_char>(),
            json.as_ptr().cast::<c_char>(),
            output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_NOT_INITIALIZED,
            "DecryptFromJson should return ERR_NOT_INITIALIZED when factory is not set up"
        );
    }
}

#[test]
fn test_encrypt_not_initialized() {
    let partition = create_string_buffer("test-partition");
    let data = create_input_buffer(b"test data");
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
        assert_eq!(
            result, ERR_NOT_INITIALIZED,
            "Encrypt should return ERR_NOT_INITIALIZED when factory is not set up"
        );
    }
}

#[test]
fn test_decrypt_not_initialized() {
    let partition = create_string_buffer("test-partition");
    let encrypted_data = create_input_buffer(b"fake encrypted data");
    let encrypted_key = create_input_buffer(b"fake key");
    let parent_key_id = create_string_buffer("_SK_test_test");
    let mut output = create_output_buffer(4096);

    unsafe {
        let result = Decrypt(
            partition.as_ptr().cast::<c_char>(),
            encrypted_data.as_ptr().cast::<c_char>(),
            encrypted_key.as_ptr().cast::<c_char>(),
            1234567890,
            parent_key_id.as_ptr().cast::<c_char>(),
            1234567890,
            output.as_mut_ptr().cast::<c_char>(),
        );
        assert_eq!(
            result, ERR_NOT_INITIALIZED,
            "Decrypt should return ERR_NOT_INITIALIZED when factory is not set up"
        );
    }
}
