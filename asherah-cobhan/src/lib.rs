//! Asherah Cobhan - C ABI for Asherah using Cobhan buffer format
//!
//! This crate provides a drop-in replacement for the Go asherah-cobhan library,
//! implementing the same C ABI with the Cobhan buffer format for cross-language FFI.

#![allow(unsafe_code)]
#![allow(dead_code)] // Some error codes are defined for API completeness

use std::collections::HashMap;
use std::os::raw::c_char;
use std::ptr;
use std::sync::OnceLock;

use asherah::session::PublicFactory;
use asherah::types::{DataRowRecord, EnvelopeKeyRecord, KeyMeta};
use asherah::{aead::AES256GCM, builders::DynKms, builders::DynMetastore};
use asherah_config::ConfigOptions;
use base64::Engine;
use serde::Deserialize;

// ============================================================================
// Type Aliases
// ============================================================================

type Factory = PublicFactory<AES256GCM, DynKms, DynMetastore>;

// ============================================================================
// Cobhan Buffer Format Constants
// ============================================================================

/// Size of the cobhan buffer header in bytes (64-bit aligned)
const BUFFER_HEADER_SIZE: i32 = 8;

// ============================================================================
// Cobhan Error Codes (matching Go cobhan library)
// ============================================================================

/// Success
const ERR_NONE: i32 = 0;
/// Null pointer provided
const ERR_NULL_PTR: i32 = -1;
/// Buffer length exceeds maximum
const ERR_BUFFER_TOO_LARGE: i32 = -2;
/// Destination buffer insufficient
const ERR_BUFFER_TOO_SMALL: i32 = -3;
/// Copy operation incomplete
const ERR_COPY_FAILED: i32 = -4;
/// JSON unmarshaling error
const ERR_JSON_DECODE_FAILED: i32 = -5;
/// JSON marshaling error
const ERR_JSON_ENCODE_FAILED: i32 = -6;

// ============================================================================
// Asherah-specific Error Codes (matching Go asherah-cobhan library)
// ============================================================================

/// Already initialized error
const ERR_ALREADY_INITIALIZED: i32 = -100;
/// Bad configuration error
const ERR_BAD_CONFIG: i32 = -101;
/// Not initialized error
const ERR_NOT_INITIALIZED: i32 = -102;
/// Encryption failed
const ERR_ENCRYPT_FAILED: i32 = -103;
/// Decryption failed
const ERR_DECRYPT_FAILED: i32 = -104;

// ============================================================================
// Global State
// ============================================================================

/// Global factory instance (singleton pattern matching Go implementation)
static FACTORY: OnceLock<Factory> = OnceLock::new();

// ============================================================================
// Cobhan Buffer Format Implementation
// ============================================================================

/// Reads the length from a cobhan buffer header.
/// The length is stored as a little-endian i32 at offset 0.
/// Negative values indicate temp file references (not supported in this implementation).
unsafe fn cobhan_buffer_get_length(buf: *const c_char) -> i32 {
    if buf.is_null() {
        return 0;
    }
    let bytes = buf as *const u8;
    i32::from_le_bytes([
        *bytes,
        *bytes.add(1),
        *bytes.add(2),
        *bytes.add(3),
    ])
}

/// Writes the length to a cobhan buffer header.
unsafe fn cobhan_buffer_set_length(buf: *mut c_char, len: i32) {
    if buf.is_null() {
        return;
    }
    let bytes = buf as *mut u8;
    let len_bytes = len.to_le_bytes();
    *bytes = len_bytes[0];
    *bytes.add(1) = len_bytes[1];
    *bytes.add(2) = len_bytes[2];
    *bytes.add(3) = len_bytes[3];
}

/// Gets a pointer to the data section of a cobhan buffer (after the 8-byte header).
unsafe fn cobhan_buffer_get_data_ptr(buf: *const c_char) -> *const u8 {
    if buf.is_null() {
        return ptr::null();
    }
    (buf as *const u8).add(BUFFER_HEADER_SIZE as usize)
}

/// Gets a mutable pointer to the data section of a cobhan buffer.
unsafe fn cobhan_buffer_get_data_ptr_mut(buf: *mut c_char) -> *mut u8 {
    if buf.is_null() {
        return ptr::null_mut();
    }
    (buf as *mut u8).add(BUFFER_HEADER_SIZE as usize)
}

/// Reads bytes from a cobhan buffer into a Vec<u8>.
unsafe fn cobhan_buffer_to_bytes(buf: *const c_char) -> Result<Vec<u8>, i32> {
    if buf.is_null() {
        return Err(ERR_NULL_PTR);
    }
    let len = cobhan_buffer_get_length(buf);
    if len < 0 {
        // Negative length indicates temp file - not supported
        return Err(ERR_BUFFER_TOO_LARGE);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    let data_ptr = cobhan_buffer_get_data_ptr(buf);
    let slice = std::slice::from_raw_parts(data_ptr, len as usize);
    Ok(slice.to_vec())
}

/// Reads a UTF-8 string from a cobhan buffer.
unsafe fn cobhan_buffer_to_string(buf: *const c_char) -> Result<String, i32> {
    let bytes = cobhan_buffer_to_bytes(buf)?;
    String::from_utf8(bytes).map_err(|_| ERR_JSON_DECODE_FAILED)
}

/// Deserializes JSON from a cobhan buffer into a struct.
unsafe fn cobhan_buffer_to_json<T: for<'de> Deserialize<'de>>(buf: *const c_char) -> Result<T, i32> {
    let bytes = cobhan_buffer_to_bytes(buf)?;
    serde_json::from_slice(&bytes).map_err(|_| ERR_JSON_DECODE_FAILED)
}

/// Writes bytes to a cobhan buffer.
/// Returns the number of bytes written, or an error code.
unsafe fn cobhan_bytes_to_buffer(data: &[u8], buf: *mut c_char, capacity: i32) -> i32 {
    if buf.is_null() {
        return ERR_NULL_PTR;
    }
    let data_len = data.len() as i32;
    if data_len > capacity {
        return ERR_BUFFER_TOO_SMALL;
    }
    cobhan_buffer_set_length(buf, data_len);
    if data_len > 0 {
        let dest = cobhan_buffer_get_data_ptr_mut(buf);
        ptr::copy_nonoverlapping(data.as_ptr(), dest, data.len());
    }
    ERR_NONE
}

/// Serializes a value to JSON and writes it to a cobhan buffer.
unsafe fn cobhan_json_to_buffer<T: serde::Serialize>(value: &T, buf: *mut c_char, capacity: i32) -> i32 {
    let json = match serde_json::to_vec(value) {
        Ok(v) => v,
        Err(_) => return ERR_JSON_ENCODE_FAILED,
    };
    cobhan_bytes_to_buffer(&json, buf, capacity)
}

/// Writes an i32 value to a cobhan buffer (as 4 bytes in the data section).
unsafe fn cobhan_int32_to_buffer(value: i32, buf: *mut c_char) -> i32 {
    if buf.is_null() {
        return ERR_NULL_PTR;
    }
    cobhan_buffer_set_length(buf, 4);
    let dest = cobhan_buffer_get_data_ptr_mut(buf);
    let bytes = value.to_le_bytes();
    ptr::copy_nonoverlapping(bytes.as_ptr(), dest, 4);
    ERR_NONE
}

/// Writes an i64 value to a cobhan buffer (as 8 bytes in the data section).
unsafe fn cobhan_int64_to_buffer(value: i64, buf: *mut c_char) -> i32 {
    if buf.is_null() {
        return ERR_NULL_PTR;
    }
    cobhan_buffer_set_length(buf, 8);
    let dest = cobhan_buffer_get_data_ptr_mut(buf);
    let bytes = value.to_le_bytes();
    ptr::copy_nonoverlapping(bytes.as_ptr(), dest, 8);
    ERR_NONE
}

/// Gets the capacity of a cobhan output buffer.
/// For output buffers, the capacity is stored at offset 4 (second i32).
unsafe fn cobhan_buffer_get_capacity(buf: *const c_char) -> i32 {
    if buf.is_null() {
        return 0;
    }
    let bytes = (buf as *const u8).add(4);
    i32::from_le_bytes([
        *bytes,
        *bytes.add(1),
        *bytes.add(2),
        *bytes.add(3),
    ])
}

// ============================================================================
// Exported C ABI Functions
// ============================================================================

/// Gracefully shuts down Asherah.
/// Note: Due to Rust's OnceLock semantics, the factory cannot be reinitialized
/// after shutdown in the same process.
#[unsafe(no_mangle)]
pub extern "C" fn Shutdown() {
    // OnceLock doesn't support taking the value out, so we just leave it.
    // The factory will be dropped when the process exits.
    // This matches the behavior where re-initialization isn't expected.
}

/// Sets environment variables from a JSON object.
///
/// # Parameters
/// - `env_json`: Cobhan buffer containing JSON object with string key-value pairs
///
/// # Returns
/// - `ERR_NONE` on success
/// - `ERR_NULL_PTR` if buffer is null
/// - `ERR_JSON_DECODE_FAILED` if JSON parsing fails
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetEnv(env_json: *const c_char) -> i32 {
    if env_json.is_null() {
        return ERR_NULL_PTR;
    }

    let env_map: HashMap<String, String> = match cobhan_buffer_to_json(env_json) {
        Ok(m) => m,
        Err(e) => return e,
    };

    for (key, value) in env_map {
        std::env::set_var(&key, &value);
    }

    ERR_NONE
}

/// Initializes Asherah with the provided JSON configuration.
///
/// # Parameters
/// - `config_json`: Cobhan buffer containing JSON configuration matching ConfigOptions
///
/// # Returns
/// - `ERR_NONE` on success
/// - `ERR_ALREADY_INITIALIZED` if already initialized
/// - `ERR_BAD_CONFIG` if configuration is invalid
/// - `ERR_NULL_PTR` if buffer is null
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetupJson(config_json: *const c_char) -> i32 {
    if config_json.is_null() {
        return ERR_NULL_PTR;
    }

    // Check if already initialized
    if FACTORY.get().is_some() {
        return ERR_ALREADY_INITIALIZED;
    }

    // Parse configuration
    let config: ConfigOptions = match cobhan_buffer_to_json(config_json) {
        Ok(c) => c,
        Err(_) => return ERR_BAD_CONFIG,
    };

    // Apply configuration and create factory
    match asherah_config::factory_from_config(&config) {
        Ok((factory, _applied)) => {
            if FACTORY.set(factory).is_err() {
                // Race condition - another thread initialized first
                return ERR_ALREADY_INITIALIZED;
            }
            ERR_NONE
        }
        Err(_) => ERR_BAD_CONFIG,
    }
}

/// Estimates the buffer size needed for encryption output.
///
/// # Parameters
/// - `data_len`: Length of data to encrypt
/// - `partition_len`: Length of partition ID
///
/// # Returns
/// - Estimated buffer size in bytes
#[unsafe(no_mangle)]
pub extern "C" fn EstimateBuffer(data_len: i32, partition_len: i32) -> i32 {
    // This estimation matches the Go implementation's formula:
    // The output includes:
    // - Base64 encoded encrypted data (4/3 * data_len, rounded up)
    // - JSON structure overhead
    // - Envelope key record
    // - Key metadata
    // - Partition ID in key ID
    let base64_data_len = ((data_len as i64 * 4) / 3) + 4;
    let key_overhead = 256_i64; // Key, KeyId, Created, ParentKeyMeta
    let json_overhead = 128_i64; // JSON structure, field names
    let partition_overhead = partition_len as i64 + 64; // Partition in KeyId

    let total = base64_data_len + key_overhead + json_overhead + partition_overhead + BUFFER_HEADER_SIZE as i64;

    // Round up to nearest 256 for safety margin
    ((total + 255) / 256 * 256) as i32
}

/// Encrypts data and returns the components separately.
///
/// # Parameters
/// - `partition_id_ptr`: Cobhan buffer with partition ID string
/// - `data_ptr`: Cobhan buffer with data to encrypt
/// - `output_encrypted_data_ptr`: Output cobhan buffer for encrypted data (base64)
/// - `output_encrypted_key_ptr`: Output cobhan buffer for encrypted key (base64)
/// - `output_created_ptr`: Output cobhan buffer for created timestamp (i64)
/// - `output_parent_key_id_ptr`: Output cobhan buffer for parent key ID string
/// - `output_parent_key_created_ptr`: Output cobhan buffer for parent key created timestamp (i64)
///
/// # Returns
/// - `ERR_NONE` on success
/// - Error code on failure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Encrypt(
    partition_id_ptr: *const c_char,
    data_ptr: *const c_char,
    output_encrypted_data_ptr: *mut c_char,
    output_encrypted_key_ptr: *mut c_char,
    output_created_ptr: *mut c_char,
    output_parent_key_id_ptr: *mut c_char,
    output_parent_key_created_ptr: *mut c_char,
) -> i32 {
    // Validate inputs
    if partition_id_ptr.is_null()
        || data_ptr.is_null()
        || output_encrypted_data_ptr.is_null()
        || output_encrypted_key_ptr.is_null()
        || output_created_ptr.is_null()
        || output_parent_key_id_ptr.is_null()
        || output_parent_key_created_ptr.is_null()
    {
        return ERR_NULL_PTR;
    }

    // Get factory
    let factory = match FACTORY.get() {
        Some(f) => f,
        None => return ERR_NOT_INITIALIZED,
    };

    // Read inputs
    let partition_id = match cobhan_buffer_to_string(partition_id_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let data = match cobhan_buffer_to_bytes(data_ptr) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Get session and encrypt
    let session = factory.get_session(&partition_id);
    let drr = match session.encrypt(&data) {
        Ok(d) => d,
        Err(_) => return ERR_ENCRYPT_FAILED,
    };

    // Extract components from DataRowRecord
    let key_record = match drr.key {
        Some(k) => k,
        None => return ERR_ENCRYPT_FAILED,
    };

    // Write encrypted data (base64)
    let encrypted_data_b64 = base64::engine::general_purpose::STANDARD.encode(&drr.data);
    let data_capacity = cobhan_buffer_get_capacity(output_encrypted_data_ptr);
    let result = cobhan_bytes_to_buffer(encrypted_data_b64.as_bytes(), output_encrypted_data_ptr, data_capacity);
    if result != ERR_NONE {
        return result;
    }

    // Write encrypted key (base64)
    let encrypted_key_b64 = base64::engine::general_purpose::STANDARD.encode(&key_record.encrypted_key);
    let key_capacity = cobhan_buffer_get_capacity(output_encrypted_key_ptr);
    let result = cobhan_bytes_to_buffer(encrypted_key_b64.as_bytes(), output_encrypted_key_ptr, key_capacity);
    if result != ERR_NONE {
        return result;
    }

    // Write created timestamp
    let result = cobhan_int64_to_buffer(key_record.created, output_created_ptr);
    if result != ERR_NONE {
        return result;
    }

    // Write parent key metadata
    if let Some(parent_meta) = &key_record.parent_key_meta {
        let parent_id_capacity = cobhan_buffer_get_capacity(output_parent_key_id_ptr);
        let result = cobhan_bytes_to_buffer(parent_meta.id.as_bytes(), output_parent_key_id_ptr, parent_id_capacity);
        if result != ERR_NONE {
            return result;
        }

        let result = cobhan_int64_to_buffer(parent_meta.created, output_parent_key_created_ptr);
        if result != ERR_NONE {
            return result;
        }
    } else {
        // No parent key - write empty string and 0 timestamp
        cobhan_buffer_set_length(output_parent_key_id_ptr, 0);
        let result = cobhan_int64_to_buffer(0, output_parent_key_created_ptr);
        if result != ERR_NONE {
            return result;
        }
    }

    ERR_NONE
}

/// Decrypts data from components.
///
/// # Parameters
/// - `partition_id_ptr`: Cobhan buffer with partition ID string
/// - `encrypted_data_ptr`: Cobhan buffer with encrypted data (base64)
/// - `encrypted_key_ptr`: Cobhan buffer with encrypted key (base64)
/// - `created`: Created timestamp
/// - `parent_key_id_ptr`: Cobhan buffer with parent key ID string
/// - `parent_key_created`: Parent key created timestamp
/// - `output_decrypted_data_ptr`: Output cobhan buffer for decrypted data
///
/// # Returns
/// - `ERR_NONE` on success
/// - Error code on failure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn Decrypt(
    partition_id_ptr: *const c_char,
    encrypted_data_ptr: *const c_char,
    encrypted_key_ptr: *const c_char,
    created: i64,
    parent_key_id_ptr: *const c_char,
    parent_key_created: i64,
    output_decrypted_data_ptr: *mut c_char,
) -> i32 {
    // Validate inputs
    if partition_id_ptr.is_null()
        || encrypted_data_ptr.is_null()
        || encrypted_key_ptr.is_null()
        || parent_key_id_ptr.is_null()
        || output_decrypted_data_ptr.is_null()
    {
        return ERR_NULL_PTR;
    }

    // Get factory
    let factory = match FACTORY.get() {
        Some(f) => f,
        None => return ERR_NOT_INITIALIZED,
    };

    // Read inputs
    let partition_id = match cobhan_buffer_to_string(partition_id_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let encrypted_data_b64 = match cobhan_buffer_to_string(encrypted_data_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let encrypted_key_b64 = match cobhan_buffer_to_string(encrypted_key_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let parent_key_id = match cobhan_buffer_to_string(parent_key_id_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Decode base64
    let encrypted_data = match base64::engine::general_purpose::STANDARD.decode(&encrypted_data_b64) {
        Ok(d) => d,
        Err(_) => return ERR_DECRYPT_FAILED,
    };

    let encrypted_key = match base64::engine::general_purpose::STANDARD.decode(&encrypted_key_b64) {
        Ok(k) => k,
        Err(_) => return ERR_DECRYPT_FAILED,
    };

    // Build parent key metadata
    let parent_key_meta = if !parent_key_id.is_empty() {
        Some(KeyMeta {
            id: parent_key_id,
            created: parent_key_created,
        })
    } else {
        None
    };

    // Build DataRowRecord
    let drr = DataRowRecord {
        data: encrypted_data,
        key: Some(EnvelopeKeyRecord {
            revoked: None,
            id: String::new(), // ID is not serialized anyway
            created,
            encrypted_key,
            parent_key_meta,
        }),
    };

    // Get session and decrypt
    let session = factory.get_session(&partition_id);
    let plaintext = match session.decrypt(drr) {
        Ok(p) => p,
        Err(_) => return ERR_DECRYPT_FAILED,
    };

    // Write output
    let output_capacity = cobhan_buffer_get_capacity(output_decrypted_data_ptr);
    cobhan_bytes_to_buffer(&plaintext, output_decrypted_data_ptr, output_capacity)
}

/// Encrypts data and returns the result as a JSON DataRowRecord.
///
/// # Parameters
/// - `partition_id_ptr`: Cobhan buffer with partition ID string
/// - `data_ptr`: Cobhan buffer with data to encrypt
/// - `json_ptr`: Output cobhan buffer for JSON result
///
/// # Returns
/// - `ERR_NONE` on success
/// - Error code on failure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn EncryptToJson(
    partition_id_ptr: *const c_char,
    data_ptr: *const c_char,
    json_ptr: *mut c_char,
) -> i32 {
    // Validate inputs
    if partition_id_ptr.is_null() || data_ptr.is_null() || json_ptr.is_null() {
        return ERR_NULL_PTR;
    }

    // Get factory
    let factory = match FACTORY.get() {
        Some(f) => f,
        None => return ERR_NOT_INITIALIZED,
    };

    // Read inputs
    let partition_id = match cobhan_buffer_to_string(partition_id_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let data = match cobhan_buffer_to_bytes(data_ptr) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Get session and encrypt
    let session = factory.get_session(&partition_id);
    let drr = match session.encrypt(&data) {
        Ok(d) => d,
        Err(_) => return ERR_ENCRYPT_FAILED,
    };

    // Serialize to JSON and write to output buffer
    let json_capacity = cobhan_buffer_get_capacity(json_ptr);
    cobhan_json_to_buffer(&drr, json_ptr, json_capacity)
}

/// Decrypts data from a JSON DataRowRecord.
///
/// # Parameters
/// - `partition_id_ptr`: Cobhan buffer with partition ID string
/// - `json_ptr`: Cobhan buffer with JSON DataRowRecord
/// - `data_ptr`: Output cobhan buffer for decrypted data
///
/// # Returns
/// - `ERR_NONE` on success
/// - Error code on failure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DecryptFromJson(
    partition_id_ptr: *const c_char,
    json_ptr: *const c_char,
    data_ptr: *mut c_char,
) -> i32 {
    // Validate inputs
    if partition_id_ptr.is_null() || json_ptr.is_null() || data_ptr.is_null() {
        return ERR_NULL_PTR;
    }

    // Get factory
    let factory = match FACTORY.get() {
        Some(f) => f,
        None => return ERR_NOT_INITIALIZED,
    };

    // Read inputs
    let partition_id = match cobhan_buffer_to_string(partition_id_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let drr: DataRowRecord = match cobhan_buffer_to_json(json_ptr) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Get session and decrypt
    let session = factory.get_session(&partition_id);
    let plaintext = match session.decrypt(drr) {
        Ok(p) => p,
        Err(_) => return ERR_DECRYPT_FAILED,
    };

    // Write output
    let output_capacity = cobhan_buffer_get_capacity(data_ptr);
    cobhan_bytes_to_buffer(&plaintext, data_ptr, output_capacity)
}

// ============================================================================
// Test Helpers (available for integration tests)
// ============================================================================

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    /// Buffer header size constant
    pub const BUFFER_HEADER_SIZE: i32 = 8;

    /// Error code constants (re-exported for tests)
    pub const ERR_NONE: i32 = 0;
    pub const ERR_NULL_PTR: i32 = -1;
    pub const ERR_BUFFER_TOO_LARGE: i32 = -2;
    pub const ERR_BUFFER_TOO_SMALL: i32 = -3;
    pub const ERR_COPY_FAILED: i32 = -4;
    pub const ERR_JSON_DECODE_FAILED: i32 = -5;
    pub const ERR_JSON_ENCODE_FAILED: i32 = -6;
    pub const ERR_ALREADY_INITIALIZED: i32 = -100;
    pub const ERR_BAD_CONFIG: i32 = -101;
    pub const ERR_NOT_INITIALIZED: i32 = -102;
    pub const ERR_ENCRYPT_FAILED: i32 = -103;
    pub const ERR_DECRYPT_FAILED: i32 = -104;

    /// Creates a cobhan input buffer from bytes.
    /// Returns a Vec<u8> that can be cast to *const c_char.
    pub fn create_input_buffer(data: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; BUFFER_HEADER_SIZE as usize + data.len()];
        let len = data.len() as i32;
        buf[0..4].copy_from_slice(&len.to_le_bytes());
        buf[BUFFER_HEADER_SIZE as usize..].copy_from_slice(data);
        buf
    }

    /// Creates a cobhan input buffer from a string.
    pub fn create_string_buffer(s: &str) -> Vec<u8> {
        create_input_buffer(s.as_bytes())
    }

    /// Creates a cobhan output buffer with the given capacity.
    /// The capacity is stored in bytes 4-7 of the header.
    pub fn create_output_buffer(capacity: i32) -> Vec<u8> {
        let mut buf = vec![0u8; BUFFER_HEADER_SIZE as usize + capacity as usize];
        // Length starts at 0
        buf[0..4].copy_from_slice(&0_i32.to_le_bytes());
        // Capacity in bytes 4-7
        buf[4..8].copy_from_slice(&capacity.to_le_bytes());
        buf
    }

    /// Reads the length from a cobhan buffer.
    pub fn get_buffer_length(buf: &[u8]) -> i32 {
        i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
    }

    /// Reads the data from a cobhan buffer.
    pub fn get_buffer_data(buf: &[u8]) -> &[u8] {
        let len = get_buffer_length(buf) as usize;
        &buf[BUFFER_HEADER_SIZE as usize..BUFFER_HEADER_SIZE as usize + len]
    }

    /// Reads a string from a cobhan buffer.
    pub fn get_buffer_string(buf: &[u8]) -> String {
        String::from_utf8_lossy(get_buffer_data(buf)).to_string()
    }

    /// Reads an i64 from a cobhan buffer's data section.
    pub fn get_buffer_i64(buf: &[u8]) -> i64 {
        let data = get_buffer_data(buf);
        i64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ])
    }
}

// ============================================================================
// Unit Tests - Cobhan Buffer Format
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_helpers::{
        create_input_buffer, create_output_buffer, create_string_buffer,
        get_buffer_data, get_buffer_i64, get_buffer_length, get_buffer_string,
    };

    // ========================================================================
    // Buffer Length Tests
    // ========================================================================

    #[test]
    fn test_buffer_length_zero() {
        let buf = create_output_buffer(100);
        assert_eq!(get_buffer_length(&buf), 0);
    }

    #[test]
    fn test_buffer_length_positive() {
        let buf = create_input_buffer(b"hello");
        assert_eq!(get_buffer_length(&buf), 5);
    }

    #[test]
    fn test_buffer_length_set_and_get() {
        let mut buf = [0u8; 16];
        unsafe {
            cobhan_buffer_set_length(buf.as_mut_ptr() as *mut c_char, 42);
            let len = cobhan_buffer_get_length(buf.as_ptr() as *const c_char);
            assert_eq!(len, 42);
        }
    }

    #[test]
    fn test_buffer_length_max_positive() {
        let mut buf = [0u8; 16];
        unsafe {
            cobhan_buffer_set_length(buf.as_mut_ptr() as *mut c_char, i32::MAX);
            let len = cobhan_buffer_get_length(buf.as_ptr() as *const c_char);
            assert_eq!(len, i32::MAX);
        }
    }

    #[test]
    fn test_buffer_length_negative() {
        let mut buf = [0u8; 16];
        unsafe {
            cobhan_buffer_set_length(buf.as_mut_ptr() as *mut c_char, -1);
            let len = cobhan_buffer_get_length(buf.as_ptr() as *const c_char);
            assert_eq!(len, -1);
        }
    }

    #[test]
    fn test_buffer_length_null_returns_zero() {
        unsafe {
            let len = cobhan_buffer_get_length(ptr::null());
            assert_eq!(len, 0);
        }
    }

    #[test]
    fn test_buffer_set_length_null_is_safe() {
        unsafe {
            // Should not panic or crash
            cobhan_buffer_set_length(ptr::null_mut(), 42);
        }
    }

    // ========================================================================
    // Buffer Capacity Tests
    // ========================================================================

    #[test]
    fn test_buffer_capacity_read() {
        let buf = create_output_buffer(1024);
        unsafe {
            let capacity = cobhan_buffer_get_capacity(buf.as_ptr() as *const c_char);
            assert_eq!(capacity, 1024);
        }
    }

    #[test]
    fn test_buffer_capacity_null_returns_zero() {
        unsafe {
            let capacity = cobhan_buffer_get_capacity(ptr::null());
            assert_eq!(capacity, 0);
        }
    }

    // ========================================================================
    // Buffer Data Pointer Tests
    // ========================================================================

    #[test]
    fn test_buffer_data_ptr_offset() {
        let buf = create_input_buffer(b"test data");
        unsafe {
            let data_ptr = cobhan_buffer_get_data_ptr(buf.as_ptr() as *const c_char);
            let expected_ptr = buf.as_ptr().add(BUFFER_HEADER_SIZE as usize);
            assert_eq!(data_ptr, expected_ptr);
        }
    }

    #[test]
    fn test_buffer_data_ptr_null_returns_null() {
        unsafe {
            let data_ptr = cobhan_buffer_get_data_ptr(ptr::null());
            assert!(data_ptr.is_null());
        }
    }

    #[test]
    fn test_buffer_data_ptr_mut_null_returns_null() {
        unsafe {
            let data_ptr = cobhan_buffer_get_data_ptr_mut(ptr::null_mut());
            assert!(data_ptr.is_null());
        }
    }

    // ========================================================================
    // Buffer to Bytes Tests
    // ========================================================================

    #[test]
    fn test_buffer_to_bytes_empty() {
        let buf = create_input_buffer(b"");
        unsafe {
            let result = cobhan_buffer_to_bytes(buf.as_ptr() as *const c_char);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), Vec::<u8>::new());
        }
    }

    #[test]
    fn test_buffer_to_bytes_simple() {
        let data = b"hello world";
        let buf = create_input_buffer(data);
        unsafe {
            let result = cobhan_buffer_to_bytes(buf.as_ptr() as *const c_char);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), data.to_vec());
        }
    }

    #[test]
    fn test_buffer_to_bytes_binary_data() {
        let data: Vec<u8> = (0u8..=255).collect();
        let buf = create_input_buffer(&data);
        unsafe {
            let result = cobhan_buffer_to_bytes(buf.as_ptr() as *const c_char);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), data);
        }
    }

    #[test]
    fn test_buffer_to_bytes_with_null_bytes() {
        let data = b"hello\0world\0test";
        let buf = create_input_buffer(data);
        unsafe {
            let result = cobhan_buffer_to_bytes(buf.as_ptr() as *const c_char);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), data.to_vec());
        }
    }

    #[test]
    fn test_buffer_to_bytes_null_ptr() {
        unsafe {
            let result = cobhan_buffer_to_bytes(ptr::null());
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_buffer_to_bytes_negative_length() {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&(-1_i32).to_le_bytes());
        unsafe {
            let result = cobhan_buffer_to_bytes(buf.as_ptr() as *const c_char);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), ERR_BUFFER_TOO_LARGE);
        }
    }

    // ========================================================================
    // Buffer to String Tests
    // ========================================================================

    #[test]
    fn test_buffer_to_string_simple() {
        let buf = create_string_buffer("hello world");
        unsafe {
            let result = cobhan_buffer_to_string(buf.as_ptr() as *const c_char);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "hello world");
        }
    }

    #[test]
    fn test_buffer_to_string_empty() {
        let buf = create_string_buffer("");
        unsafe {
            let result = cobhan_buffer_to_string(buf.as_ptr() as *const c_char);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "");
        }
    }

    #[test]
    fn test_buffer_to_string_unicode() {
        let buf = create_string_buffer("Hello, 世界! 🦀");
        unsafe {
            let result = cobhan_buffer_to_string(buf.as_ptr() as *const c_char);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "Hello, 世界! 🦀");
        }
    }

    #[test]
    fn test_buffer_to_string_invalid_utf8() {
        let invalid_utf8 = vec![0xFF, 0xFE, 0x00, 0x01];
        let buf = create_input_buffer(&invalid_utf8);
        unsafe {
            let result = cobhan_buffer_to_string(buf.as_ptr() as *const c_char);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), ERR_JSON_DECODE_FAILED);
        }
    }

    #[test]
    fn test_buffer_to_string_null_ptr() {
        unsafe {
            let result = cobhan_buffer_to_string(ptr::null());
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), ERR_NULL_PTR);
        }
    }

    // ========================================================================
    // Bytes to Buffer Tests
    // ========================================================================

    #[test]
    fn test_bytes_to_buffer_simple() {
        let data = b"hello world";
        let mut buf = create_output_buffer(data.len() as i32);
        unsafe {
            let result = cobhan_bytes_to_buffer(
                data,
                buf.as_mut_ptr() as *mut c_char,
                data.len() as i32,
            );
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_length(&buf), data.len() as i32);
            assert_eq!(get_buffer_data(&buf), data);
        }
    }

    #[test]
    fn test_bytes_to_buffer_empty() {
        let data = b"";
        let mut buf = create_output_buffer(100);
        unsafe {
            let result = cobhan_bytes_to_buffer(
                data,
                buf.as_mut_ptr() as *mut c_char,
                100,
            );
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_length(&buf), 0);
        }
    }

    #[test]
    fn test_bytes_to_buffer_exact_capacity() {
        let data = b"exactly fits";
        let mut buf = create_output_buffer(data.len() as i32);
        unsafe {
            let result = cobhan_bytes_to_buffer(
                data,
                buf.as_mut_ptr() as *mut c_char,
                data.len() as i32,
            );
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_data(&buf), data);
        }
    }

    #[test]
    fn test_bytes_to_buffer_insufficient_capacity() {
        let data = b"this is too long for the buffer";
        let mut buf = create_output_buffer(10);
        unsafe {
            let result = cobhan_bytes_to_buffer(
                data,
                buf.as_mut_ptr() as *mut c_char,
                10,
            );
            assert_eq!(result, ERR_BUFFER_TOO_SMALL);
        }
    }

    #[test]
    fn test_bytes_to_buffer_null_ptr() {
        let data = b"hello";
        unsafe {
            let result = cobhan_bytes_to_buffer(data, ptr::null_mut(), 100);
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_bytes_to_buffer_binary_data() {
        let data: Vec<u8> = (0u8..=255).collect();
        let mut buf = create_output_buffer(data.len() as i32);
        unsafe {
            let result = cobhan_bytes_to_buffer(
                &data,
                buf.as_mut_ptr() as *mut c_char,
                data.len() as i32,
            );
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_data(&buf), data.as_slice());
        }
    }

    // ========================================================================
    // Bytes Roundtrip Tests
    // ========================================================================

    #[test]
    fn test_bytes_roundtrip() {
        let data = b"hello world";
        let mut buf = create_output_buffer(data.len() as i32);

        unsafe {
            let write_result = cobhan_bytes_to_buffer(
                data,
                buf.as_mut_ptr() as *mut c_char,
                data.len() as i32,
            );
            assert_eq!(write_result, ERR_NONE);

            let read_result = cobhan_buffer_to_bytes(buf.as_ptr() as *const c_char);
            assert!(read_result.is_ok());
            assert_eq!(read_result.unwrap(), data.to_vec());
        }
    }

    #[test]
    fn test_bytes_roundtrip_large_data() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let mut buf = create_output_buffer(data.len() as i32);

        unsafe {
            let write_result = cobhan_bytes_to_buffer(
                &data,
                buf.as_mut_ptr() as *mut c_char,
                data.len() as i32,
            );
            assert_eq!(write_result, ERR_NONE);

            let read_result = cobhan_buffer_to_bytes(buf.as_ptr() as *const c_char);
            assert!(read_result.is_ok());
            assert_eq!(read_result.unwrap(), data);
        }
    }

    // ========================================================================
    // JSON Buffer Tests
    // ========================================================================

    #[test]
    fn test_buffer_to_json_simple_object() {
        let json = r#"{"key": "value"}"#;
        let buf = create_string_buffer(json);
        unsafe {
            let result: Result<HashMap<String, String>, i32> =
                cobhan_buffer_to_json(buf.as_ptr() as *const c_char);
            assert!(result.is_ok());
            let map = result.unwrap();
            assert_eq!(map.get("key"), Some(&"value".to_string()));
        }
    }

    #[test]
    fn test_buffer_to_json_complex_object() {
        let json = r#"{"name": "test", "count": 42, "active": true}"#;
        let buf = create_string_buffer(json);

        #[derive(Deserialize, Debug)]
        struct TestObj {
            name: String,
            count: i32,
            active: bool,
        }

        unsafe {
            let result: Result<TestObj, i32> =
                cobhan_buffer_to_json(buf.as_ptr() as *const c_char);
            assert!(result.is_ok());
            let obj = result.unwrap();
            assert_eq!(obj.name, "test");
            assert_eq!(obj.count, 42);
            assert!(obj.active);
        }
    }

    #[test]
    fn test_buffer_to_json_invalid_json() {
        let invalid_json = "not valid json {";
        let buf = create_string_buffer(invalid_json);
        unsafe {
            let result: Result<HashMap<String, String>, i32> =
                cobhan_buffer_to_json(buf.as_ptr() as *const c_char);
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), ERR_JSON_DECODE_FAILED);
        }
    }

    #[test]
    fn test_buffer_to_json_null_ptr() {
        unsafe {
            let result: Result<HashMap<String, String>, i32> =
                cobhan_buffer_to_json(ptr::null());
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_json_to_buffer_simple() {
        let map: HashMap<String, String> =
            [("key".to_string(), "value".to_string())].into_iter().collect();
        let mut buf = create_output_buffer(100);

        unsafe {
            let result = cobhan_json_to_buffer(
                &map,
                buf.as_mut_ptr() as *mut c_char,
                100,
            );
            assert_eq!(result, ERR_NONE);

            let json_str = get_buffer_string(&buf);
            assert!(json_str.contains("\"key\""));
            assert!(json_str.contains("\"value\""));
        }
    }

    #[test]
    fn test_json_to_buffer_insufficient_capacity() {
        let large_map: HashMap<String, String> = (0..100)
            .map(|i| (format!("key_{}", i), format!("value_{}", i)))
            .collect();
        let mut buf = create_output_buffer(10);

        unsafe {
            let result = cobhan_json_to_buffer(
                &large_map,
                buf.as_mut_ptr() as *mut c_char,
                10,
            );
            assert_eq!(result, ERR_BUFFER_TOO_SMALL);
        }
    }

    // ========================================================================
    // Int64 Buffer Tests
    // ========================================================================

    #[test]
    fn test_int64_to_buffer_positive() {
        let mut buf = create_output_buffer(8);
        unsafe {
            let result = cobhan_int64_to_buffer(
                1234567890123_i64,
                buf.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_length(&buf), 8);
            assert_eq!(get_buffer_i64(&buf), 1234567890123_i64);
        }
    }

    #[test]
    fn test_int64_to_buffer_negative() {
        let mut buf = create_output_buffer(8);
        unsafe {
            let result = cobhan_int64_to_buffer(
                -9876543210_i64,
                buf.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_i64(&buf), -9876543210_i64);
        }
    }

    #[test]
    fn test_int64_to_buffer_zero() {
        let mut buf = create_output_buffer(8);
        unsafe {
            let result = cobhan_int64_to_buffer(0, buf.as_mut_ptr() as *mut c_char);
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_i64(&buf), 0);
        }
    }

    #[test]
    fn test_int64_to_buffer_max() {
        let mut buf = create_output_buffer(8);
        unsafe {
            let result = cobhan_int64_to_buffer(
                i64::MAX,
                buf.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_i64(&buf), i64::MAX);
        }
    }

    #[test]
    fn test_int64_to_buffer_min() {
        let mut buf = create_output_buffer(8);
        unsafe {
            let result = cobhan_int64_to_buffer(
                i64::MIN,
                buf.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_i64(&buf), i64::MIN);
        }
    }

    #[test]
    fn test_int64_to_buffer_null() {
        unsafe {
            let result = cobhan_int64_to_buffer(42, ptr::null_mut());
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    // ========================================================================
    // Int32 Buffer Tests
    // ========================================================================

    #[test]
    fn test_int32_to_buffer_positive() {
        let mut buf = create_output_buffer(4);
        unsafe {
            let result = cobhan_int32_to_buffer(
                123456,
                buf.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_length(&buf), 4);
        }
    }

    #[test]
    fn test_int32_to_buffer_null() {
        unsafe {
            let result = cobhan_int32_to_buffer(42, ptr::null_mut());
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    // ========================================================================
    // EstimateBuffer Tests
    // ========================================================================

    #[test]
    fn test_estimate_buffer_small_data() {
        let estimate = EstimateBuffer(10, 10);
        assert!(estimate > 10, "Estimate should be larger than data length");
        assert!(estimate >= BUFFER_HEADER_SIZE + 256, "Should include minimum overhead");
    }

    #[test]
    fn test_estimate_buffer_medium_data() {
        let estimate = EstimateBuffer(1000, 50);
        // Base64 encoding expands data by ~33%
        let min_expected = (1000 * 4 / 3) + BUFFER_HEADER_SIZE;
        assert!(estimate > min_expected, "Should account for base64 expansion");
    }

    #[test]
    fn test_estimate_buffer_large_data() {
        let estimate = EstimateBuffer(100_000, 100);
        let min_expected = (100_000 * 4 / 3) + BUFFER_HEADER_SIZE;
        assert!(estimate > min_expected, "Should handle large data");
    }

    #[test]
    fn test_estimate_buffer_zero_data() {
        let estimate = EstimateBuffer(0, 10);
        assert!(estimate > 0, "Should return positive estimate even for zero data");
        assert!(estimate >= 256, "Should include minimum overhead");
    }

    #[test]
    fn test_estimate_buffer_zero_partition() {
        let estimate = EstimateBuffer(100, 0);
        assert!(estimate > 100, "Should be larger than data length");
    }

    #[test]
    fn test_estimate_buffer_long_partition() {
        let short_estimate = EstimateBuffer(100, 10);
        let long_estimate = EstimateBuffer(100, 1000);
        assert!(
            long_estimate > short_estimate,
            "Longer partition should increase estimate"
        );
    }

    #[test]
    fn test_estimate_buffer_consistent() {
        // Same inputs should produce same output
        let e1 = EstimateBuffer(500, 25);
        let e2 = EstimateBuffer(500, 25);
        assert_eq!(e1, e2, "EstimateBuffer should be deterministic");
    }

    #[test]
    fn test_estimate_buffer_monotonic_with_data() {
        // Larger data should produce larger or equal estimate
        let e1 = EstimateBuffer(100, 20);
        let e2 = EstimateBuffer(200, 20);
        let e3 = EstimateBuffer(300, 20);
        assert!(e2 >= e1, "Estimate should increase with data size");
        assert!(e3 >= e2, "Estimate should increase with data size");
    }

    // ========================================================================
    // SetEnv Tests (using null pointer - no factory needed)
    // ========================================================================

    #[test]
    fn test_set_env_null_pointer() {
        unsafe {
            let result = SetEnv(ptr::null());
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_set_env_invalid_json() {
        let buf = create_string_buffer("not json");
        unsafe {
            let result = SetEnv(buf.as_ptr() as *const c_char);
            assert_eq!(result, ERR_JSON_DECODE_FAILED);
        }
    }

    #[test]
    fn test_set_env_empty_object() {
        let buf = create_string_buffer("{}");
        unsafe {
            let result = SetEnv(buf.as_ptr() as *const c_char);
            assert_eq!(result, ERR_NONE);
        }
    }

    #[test]
    fn test_set_env_sets_variables() {
        let unique_key = format!("ASHERAH_TEST_VAR_{}", std::process::id());
        let json = format!(r#"{{"{unique_key}": "test_value"}}"#);
        let buf = create_string_buffer(&json);

        // Ensure variable doesn't exist
        std::env::remove_var(&unique_key);

        unsafe {
            let result = SetEnv(buf.as_ptr() as *const c_char);
            assert_eq!(result, ERR_NONE);
        }

        assert_eq!(std::env::var(&unique_key).ok(), Some("test_value".to_string()));

        // Cleanup
        std::env::remove_var(&unique_key);
    }

    #[test]
    fn test_set_env_multiple_variables() {
        let pid = std::process::id();
        let key1 = format!("ASHERAH_TEST_A_{}", pid);
        let key2 = format!("ASHERAH_TEST_B_{}", pid);
        let json = format!(r#"{{"{key1}": "value1", "{key2}": "value2"}}"#);
        let buf = create_string_buffer(&json);

        unsafe {
            let result = SetEnv(buf.as_ptr() as *const c_char);
            assert_eq!(result, ERR_NONE);
        }

        assert_eq!(std::env::var(&key1).ok(), Some("value1".to_string()));
        assert_eq!(std::env::var(&key2).ok(), Some("value2".to_string()));

        // Cleanup
        std::env::remove_var(&key1);
        std::env::remove_var(&key2);
    }

    // ========================================================================
    // SetupJson Tests (null pointer checks only - no factory initialization)
    // ========================================================================

    #[test]
    fn test_setup_json_null_pointer() {
        unsafe {
            let result = SetupJson(ptr::null());
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    // ========================================================================
    // Encrypt/Decrypt Null Pointer Tests (no factory needed)
    // ========================================================================

    #[test]
    fn test_encrypt_null_partition_id() {
        let data = create_input_buffer(b"test");
        let mut out1 = create_output_buffer(1000);
        let mut out2 = create_output_buffer(1000);
        let mut out3 = create_output_buffer(8);
        let mut out4 = create_output_buffer(100);
        let mut out5 = create_output_buffer(8);

        unsafe {
            let result = Encrypt(
                ptr::null(),
                data.as_ptr() as *const c_char,
                out1.as_mut_ptr() as *mut c_char,
                out2.as_mut_ptr() as *mut c_char,
                out3.as_mut_ptr() as *mut c_char,
                out4.as_mut_ptr() as *mut c_char,
                out5.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_encrypt_null_data() {
        let partition = create_string_buffer("partition");
        let mut out1 = create_output_buffer(1000);
        let mut out2 = create_output_buffer(1000);
        let mut out3 = create_output_buffer(8);
        let mut out4 = create_output_buffer(100);
        let mut out5 = create_output_buffer(8);

        unsafe {
            let result = Encrypt(
                partition.as_ptr() as *const c_char,
                ptr::null(),
                out1.as_mut_ptr() as *mut c_char,
                out2.as_mut_ptr() as *mut c_char,
                out3.as_mut_ptr() as *mut c_char,
                out4.as_mut_ptr() as *mut c_char,
                out5.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_encrypt_null_outputs() {
        let partition = create_string_buffer("partition");
        let data = create_input_buffer(b"test");

        unsafe {
            // Test each output being null
            let result = Encrypt(
                partition.as_ptr() as *const c_char,
                data.as_ptr() as *const c_char,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_decrypt_null_inputs() {
        let partition = create_string_buffer("partition");
        let mut output = create_output_buffer(1000);

        unsafe {
            let result = Decrypt(
                ptr::null(),
                partition.as_ptr() as *const c_char,
                partition.as_ptr() as *const c_char,
                0,
                partition.as_ptr() as *const c_char,
                0,
                output.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_encrypt_to_json_null_inputs() {
        let partition = create_string_buffer("partition");
        let data = create_input_buffer(b"test");
        let mut output = create_output_buffer(1000);

        unsafe {
            // Null partition
            let result = EncryptToJson(
                ptr::null(),
                data.as_ptr() as *const c_char,
                output.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NULL_PTR);

            // Null data
            let result = EncryptToJson(
                partition.as_ptr() as *const c_char,
                ptr::null(),
                output.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NULL_PTR);

            // Null output
            let result = EncryptToJson(
                partition.as_ptr() as *const c_char,
                data.as_ptr() as *const c_char,
                ptr::null_mut(),
            );
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_decrypt_from_json_null_inputs() {
        let partition = create_string_buffer("partition");
        let json = create_string_buffer("{}");
        let mut output = create_output_buffer(1000);

        unsafe {
            // Null partition
            let result = DecryptFromJson(
                ptr::null(),
                json.as_ptr() as *const c_char,
                output.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NULL_PTR);

            // Null json
            let result = DecryptFromJson(
                partition.as_ptr() as *const c_char,
                ptr::null(),
                output.as_mut_ptr() as *mut c_char,
            );
            assert_eq!(result, ERR_NULL_PTR);

            // Null output
            let result = DecryptFromJson(
                partition.as_ptr() as *const c_char,
                json.as_ptr() as *const c_char,
                ptr::null_mut(),
            );
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    // ========================================================================
    // Shutdown Test
    // ========================================================================

    #[test]
    fn test_shutdown_is_safe() {
        // Shutdown should be safe to call even without initialization
        Shutdown();
        // And safe to call multiple times
        Shutdown();
        Shutdown();
    }
}
