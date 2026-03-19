//! Asherah Cobhan - C ABI for Asherah using Cobhan buffer format
//!
//! This crate provides a drop-in replacement for the Go asherah-cobhan library,
//! implementing the same C ABI with the Cobhan buffer format for cross-language FFI.

#![allow(unsafe_code)]
#![allow(dead_code)] // Some error codes are defined for API completeness

use std::collections::HashMap;
use std::os::raw::c_char;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::RwLock;

use asherah::session::PublicFactory;
use asherah::types::{DataRowRecord, EnvelopeKeyRecord, KeyMeta};
use asherah::{aead::AES256GCM, builders::DynKms, builders::DynMetastore};
use asherah_config::ConfigOptions;
use serde::Deserialize;

// ============================================================================
// Stderr Log Sink (matches Go asherah-cobhan logging behavior)
// ============================================================================

/// Stderr log sink matching Go asherah-cobhan's logging:
/// - Error messages always go to stderr
/// - Debug/info/warn messages only when verbose=true
struct StderrLogSink {
    verbose: bool,
}

impl asherah::logging::LogSink for StderrLogSink {
    fn log(&self, record: &log::Record<'_>) {
        // Go cobhan: ErrorLog is always on, DebugLog only when verbose
        let should_log = match record.level() {
            log::Level::Error => true,
            _ => self.verbose,
        };
        if should_log {
            eprintln!("asherah-cobhan: [{}] {}", record.level(), record.args());
        }
    }
}

// ============================================================================
// Type Aliases
// ============================================================================

type Factory = PublicFactory<AES256GCM, DynKms, DynMetastore>;

// ============================================================================
// Cobhan Buffer Format Constants
// ============================================================================

/// Size of the cobhan buffer header in bytes (64-bit aligned)
const BUFFER_HEADER_SIZE: i32 = 8;

/// Canary values placed after data in cobhan buffers (matching C++ CobhanBuffer)
const CANARY1_VALUE: i32 = 0;
const CANARY2_VALUE: i32 = 0xDEADBEEFu32 as i32;
/// Size of canary region: two i32 values
const CANARY_SIZE: usize = 8;
/// Safety padding after canaries (matching C++ safety_padding_bytes)
const SAFETY_PADDING_SIZE: usize = 8;

/// Global flag controlling canary checks (default: false, matching C++)
static CANARIES_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable or disable canary buffer overflow detection.
pub fn set_canaries_enabled(enabled: bool) {
    CANARIES_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Returns whether canaries are currently enabled.
pub fn canaries_enabled() -> bool {
    CANARIES_ENABLED.load(Ordering::Relaxed)
}

/// Writes canary values at the given offset in a buffer.
fn write_canaries(buf: &mut [u8], offset: usize) {
    if offset + CANARY_SIZE <= buf.len() {
        buf[offset..offset + 4].copy_from_slice(&CANARY1_VALUE.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&CANARY2_VALUE.to_le_bytes());
    }
}

/// Verifies canary values at the given offset in a buffer.
/// Panics (aborts) if canaries are corrupted, matching C++ std::terminate behavior.
fn verify_canaries(buf: &[u8], offset: usize) {
    if !canaries_enabled() {
        return;
    }
    if offset + CANARY_SIZE > buf.len() {
        eprintln!("CobhanBuffer: Canary region out of bounds. Buffer too small.");
        std::process::abort();
    }
    let c1 = i32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]);
    let c2 = i32::from_le_bytes([
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]);
    if c1 != CANARY1_VALUE {
        eprintln!("Canary 1 corrupted! Expected: 0, Found: {:#010x}", c1);
        eprintln!("CobhanBuffer: Memory corruption detected: Canary values are corrupted. Terminating process.");
        std::process::abort();
    }
    if c2 != CANARY2_VALUE {
        eprintln!(
            "Canary 2 corrupted! Expected: 0xdeadbeef, Found: {:#010x}",
            c2
        );
        eprintln!("CobhanBuffer: Memory corruption detected: Canary values are corrupted. Terminating process.");
        std::process::abort();
    }
}

/// Returns the total extra bytes needed per buffer when canaries are enabled.
fn canary_overhead() -> usize {
    if canaries_enabled() {
        CANARY_SIZE + SAFETY_PADDING_SIZE
    } else {
        0
    }
}

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
// Asherah-specific Error Codes (matching Go asherah-cobhan constants.go)
// ============================================================================

/// Not initialized error
const ERR_NOT_INITIALIZED: i32 = -100;
/// Already initialized error
const ERR_ALREADY_INITIALIZED: i32 = -101;
/// Get session failed
const ERR_GET_SESSION_FAILED: i32 = -102;
/// Encryption failed
const ERR_ENCRYPT_FAILED: i32 = -103;
/// Decryption failed
const ERR_DECRYPT_FAILED: i32 = -104;
/// Bad configuration error
const ERR_BAD_CONFIG: i32 = -105;
/// Panic recovery error
const ERR_PANIC: i32 = -106;

/// Estimated encryption overhead (matches Go EstimatedEncryptionOverhead)
const ESTIMATED_ENCRYPTION_OVERHEAD: i32 = 48;
/// Estimated envelope overhead (matches Go EstimatedEnvelopeOverhead)
const ESTIMATED_ENVELOPE_OVERHEAD: i32 = 185;

// ============================================================================
// Global State
// ============================================================================

/// Global factory instance (RwLock allows proper shutdown/re-initialization)
static FACTORY: RwLock<Option<Factory>> = RwLock::new(None);

/// Estimated intermediate key overhead, set during SetupJson
/// (len(ProductID) + len(ServiceName), matching Go behavior)
static ESTIMATED_INTERMEDIATE_KEY_OVERHEAD: AtomicI32 = AtomicI32::new(0);

// ============================================================================
// Cobhan Buffer Format Implementation
// ============================================================================

/// Reads the length from a cobhan buffer header.
/// The length is stored as a little-endian i32 at offset 0.
/// For output buffers, this field initially holds the capacity.
/// Negative values indicate temp file references (not supported).
unsafe fn cobhan_buffer_get_length(buf: *const c_char) -> i32 {
    if buf.is_null() {
        return 0;
    }
    let bytes = buf.cast::<u8>();
    i32::from_le_bytes([*bytes, *bytes.add(1), *bytes.add(2), *bytes.add(3)])
}

/// Writes the length to a cobhan buffer header.
unsafe fn cobhan_buffer_set_length(buf: *mut c_char, len: i32) {
    if buf.is_null() {
        return;
    }
    let bytes = buf.cast::<u8>();
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
    buf.cast::<u8>().add(BUFFER_HEADER_SIZE as usize)
}

/// Gets a mutable pointer to the data section of a cobhan buffer.
unsafe fn cobhan_buffer_get_data_ptr_mut(buf: *mut c_char) -> *mut u8 {
    if buf.is_null() {
        return ptr::null_mut();
    }
    buf.cast::<u8>().add(BUFFER_HEADER_SIZE as usize)
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
unsafe fn cobhan_buffer_to_json<T: for<'de> Deserialize<'de>>(
    buf: *const c_char,
) -> Result<T, i32> {
    let bytes = cobhan_buffer_to_bytes(buf)?;
    serde_json::from_slice(&bytes).map_err(|_| ERR_JSON_DECODE_FAILED)
}

/// Writes bytes to a cobhan buffer.
/// Reads capacity from bytes 0-3 of the output buffer (matching Go behavior).
unsafe fn cobhan_bytes_to_buffer(data: &[u8], buf: *mut c_char) -> i32 {
    if buf.is_null() {
        return ERR_NULL_PTR;
    }
    let capacity = cobhan_buffer_get_length(buf as *const c_char);
    if capacity < 0 {
        return ERR_BUFFER_TOO_LARGE;
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
unsafe fn cobhan_json_to_buffer<T: serde::Serialize>(value: &T, buf: *mut c_char) -> i32 {
    let json = match serde_json::to_vec(value) {
        Ok(v) => v,
        Err(_) => return ERR_JSON_ENCODE_FAILED,
    };
    cobhan_bytes_to_buffer(&json, buf)
}

/// Writes an i32 value directly to a buffer (no header).
/// Matches Go cobhan.Int32ToBuffer which writes raw value at offset 0.
unsafe fn cobhan_int32_to_buffer(value: i32, buf: *mut c_char) -> i32 {
    if buf.is_null() {
        return ERR_NULL_PTR;
    }
    let bytes = value.to_le_bytes();
    ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), 4);
    ERR_NONE
}

/// Writes an i64 value directly to a buffer (no header).
/// Matches Go cobhan.Int64ToBuffer which writes raw value at offset 0.
unsafe fn cobhan_int64_to_buffer(value: i64, buf: *mut c_char) -> i32 {
    if buf.is_null() {
        return ERR_NULL_PTR;
    }
    let bytes = value.to_le_bytes();
    ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), 8);
    ERR_NONE
}

/// Writes a string to a cobhan buffer.
/// Reads capacity from bytes 0-3 of the output buffer (matching Go behavior).
unsafe fn cobhan_string_to_buffer(s: &str, buf: *mut c_char) -> i32 {
    cobhan_bytes_to_buffer(s.as_bytes(), buf)
}

// ============================================================================
// Exported C ABI Functions
// ============================================================================

/// Gracefully shuts down Asherah, releasing the global factory.
/// After shutdown, SetupJson can be called again to re-initialize.
#[unsafe(no_mangle)]
pub extern "C" fn Shutdown() {
    if let Ok(mut guard) = FACTORY.write() {
        let _ = guard.take();
    }
    ESTIMATED_INTERMEDIATE_KEY_OVERHEAD.store(0, Ordering::Relaxed);
}

/// Sets environment variables from a JSON object.
///
/// # Safety
/// `env_json` must point to a valid Cobhan buffer with a properly initialized header.
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

    let env_map: HashMap<String, Option<String>> = match cobhan_buffer_to_json(env_json) {
        Ok(m) => m,
        Err(e) => return e,
    };

    for (key, value) in env_map {
        match value {
            Some(v) => std::env::set_var(&key, &v),
            None => std::env::remove_var(&key),
        }
    }

    ERR_NONE
}

/// Initializes Asherah with the provided JSON configuration.
///
/// # Safety
/// `config_json` must point to a valid Cobhan buffer with a properly initialized header.
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

    // Install error-only stderr sink immediately so setup errors are visible
    let _ = asherah::logging::ensure_logger();
    asherah::logging::set_sink(
        "stderr",
        Some(std::sync::Arc::new(StderrLogSink { verbose: false })),
    );

    let mut guard = match FACTORY.write() {
        Ok(g) => g,
        Err(_) => return ERR_PANIC,
    };

    // Check if already initialized
    if guard.is_some() {
        return ERR_ALREADY_INITIALIZED;
    }

    // Parse configuration
    let config: ConfigOptions = match cobhan_buffer_to_json(config_json) {
        Ok(c) => c,
        Err(code) => {
            log::error!(
                "SetupJson: failed to parse config JSON (error code {})",
                code
            );
            return ERR_BAD_CONFIG;
        }
    };

    // Track intermediate key overhead (matching Go behavior)
    let product_id_len = config.product_id.as_ref().map_or(0, |s| s.len());
    let service_name_len = config.service_name.as_ref().map_or(0, |s| s.len());
    ESTIMATED_INTERMEDIATE_KEY_OVERHEAD.store(
        (product_id_len + service_name_len) as i32,
        Ordering::Relaxed,
    );

    // Apply configuration and create factory
    match asherah_config::factory_from_config(&config) {
        Ok((factory, applied)) => {
            // Upgrade to verbose sink if Verbose=true (debug+error to stderr)
            if applied.verbose {
                asherah::logging::set_sink(
                    "stderr",
                    Some(std::sync::Arc::new(StderrLogSink { verbose: true })),
                );
            }
            set_canaries_enabled(applied.enable_canaries);
            *guard = Some(factory);
            ERR_NONE
        }
        Err(e) => {
            log::error!("SetupJson failed: {:#}", e);
            ERR_BAD_CONFIG
        }
    }
}

/// Estimates the buffer size needed for encryption output.
/// Matches the Go implementation's formula exactly.
///
/// # Parameters
/// - `data_len`: Length of data to encrypt
/// - `partition_len`: Length of partition ID
///
/// # Returns
/// - Estimated buffer size in bytes
#[unsafe(no_mangle)]
pub extern "C" fn EstimateBuffer(data_len: i32, partition_len: i32) -> i32 {
    // Match Go formula:
    // estimatedDataLen := ((int(dataLen) + EstimatedEncryptionOverhead + 2) / 3) * 4
    // result := int32(BUFFER_HEADER_SIZE + EstimatedEnvelopeOverhead +
    //           EstimatedIntermediateKeyOverhead + int(partitionLen) + estimatedDataLen)
    let estimated_data_len = ((data_len as i64 + ESTIMATED_ENCRYPTION_OVERHEAD as i64 + 2) / 3) * 4;
    let intermediate_key_overhead =
        ESTIMATED_INTERMEDIATE_KEY_OVERHEAD.load(Ordering::Relaxed) as i64;

    let result = BUFFER_HEADER_SIZE as i64
        + ESTIMATED_ENVELOPE_OVERHEAD as i64
        + intermediate_key_overhead
        + partition_len as i64
        + estimated_data_len;
    if result > i32::MAX as i64 {
        i32::MAX // clamp to max representable; caller should check
    } else {
        result as i32
    }
}

/// Encrypts data and returns the components separately.
///
/// # Safety
/// All pointer parameters must point to valid Cobhan buffers with properly initialized headers.
/// Output buffers must have sufficient capacity for the results.
/// Scalar output buffers (created, parent_key_created) must be at least 8 bytes.
///
/// # Parameters
/// - `partition_id_ptr`: Cobhan buffer with partition ID string
/// - `data_ptr`: Cobhan buffer with data to encrypt
/// - `output_encrypted_data_ptr`: Output cobhan buffer for encrypted data (raw bytes)
/// - `output_encrypted_key_ptr`: Output cobhan buffer for encrypted key (raw bytes)
/// - `output_created_ptr`: Output buffer for created timestamp (raw i64, no header)
/// - `output_parent_key_id_ptr`: Output cobhan buffer for parent key ID string
/// - `output_parent_key_created_ptr`: Output buffer for parent key created timestamp (raw i64, no header)
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
    let guard = match FACTORY.read() {
        Ok(g) => g,
        Err(_) => return ERR_PANIC,
    };
    let factory = match guard.as_ref() {
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
        Err(e) => {
            log::error!("Encrypt failed: {e:#}");
            return ERR_ENCRYPT_FAILED;
        }
    };

    // Extract components from DataRowRecord
    let key_record = match drr.key {
        Some(k) => k,
        None => return ERR_ENCRYPT_FAILED,
    };

    // Write encrypted data (raw bytes, matching Go cobhan.BytesToBuffer)
    let result = cobhan_bytes_to_buffer(&drr.data, output_encrypted_data_ptr);
    if result != ERR_NONE {
        return result;
    }

    // Write encrypted key (raw bytes, matching Go cobhan.BytesToBuffer)
    let result = cobhan_bytes_to_buffer(&key_record.encrypted_key, output_encrypted_key_ptr);
    if result != ERR_NONE {
        return result;
    }

    // Write created timestamp (raw i64 at offset 0, matching Go cobhan.Int64ToBuffer)
    let result = cobhan_int64_to_buffer(key_record.created, output_created_ptr);
    if result != ERR_NONE {
        return result;
    }

    // Write parent key metadata
    if let Some(parent_meta) = &key_record.parent_key_meta {
        // Write parent key ID (matching Go cobhan.StringToBuffer)
        let result = cobhan_string_to_buffer(&parent_meta.id, output_parent_key_id_ptr);
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
/// # Safety
/// All pointer parameters must point to valid Cobhan buffers with properly initialized headers.
/// The output buffer must have sufficient capacity for the decrypted data.
///
/// # Parameters
/// - `partition_id_ptr`: Cobhan buffer with partition ID string
/// - `encrypted_data_ptr`: Cobhan buffer with encrypted data (raw bytes)
/// - `encrypted_key_ptr`: Cobhan buffer with encrypted key (raw bytes)
/// - `created`: Created timestamp (raw i64 value)
/// - `parent_key_id_ptr`: Cobhan buffer with parent key ID string
/// - `parent_key_created`: Parent key created timestamp (raw i64 value)
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
    let guard = match FACTORY.read() {
        Ok(g) => g,
        Err(_) => return ERR_PANIC,
    };
    let factory = match guard.as_ref() {
        Some(f) => f,
        None => return ERR_NOT_INITIALIZED,
    };

    // Read inputs - raw bytes, no base64 (matching Go cobhan.BufferToBytes)
    let partition_id = match cobhan_buffer_to_string(partition_id_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let encrypted_data = match cobhan_buffer_to_bytes(encrypted_data_ptr) {
        Ok(d) => d,
        Err(e) => return e,
    };

    let encrypted_key = match cobhan_buffer_to_bytes(encrypted_key_ptr) {
        Ok(k) => k,
        Err(e) => return e,
    };

    let parent_key_id = match cobhan_buffer_to_string(parent_key_id_ptr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Build parent key metadata
    let parent_key_meta = Some(KeyMeta {
        id: parent_key_id,
        created: parent_key_created,
    });

    // Build DataRowRecord
    let drr = DataRowRecord {
        data: encrypted_data,
        key: Some(EnvelopeKeyRecord {
            revoked: None,
            id: String::new(),
            created,
            encrypted_key,
            parent_key_meta,
        }),
    };

    // Get session and decrypt
    let session = factory.get_session(&partition_id);
    let plaintext = match session.decrypt(drr) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Decrypt failed: {e:#}");
            return ERR_DECRYPT_FAILED;
        }
    };

    // Write output
    cobhan_bytes_to_buffer(&plaintext, output_decrypted_data_ptr)
}

/// Encrypts data and returns the result as a JSON DataRowRecord.
///
/// # Safety
/// All pointer parameters must point to valid Cobhan buffers with properly initialized headers.
/// The output buffer must have sufficient capacity for the JSON result.
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
    let guard = match FACTORY.read() {
        Ok(g) => g,
        Err(_) => return ERR_PANIC,
    };
    let factory = match guard.as_ref() {
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
        Err(e) => {
            log::error!("EncryptToJson failed: {e:#}");
            return ERR_ENCRYPT_FAILED;
        }
    };

    // Serialize to JSON and write to output buffer
    cobhan_json_to_buffer(&drr, json_ptr)
}

/// Decrypts data from a JSON DataRowRecord.
///
/// # Safety
/// All pointer parameters must point to valid Cobhan buffers with properly initialized headers.
/// The output buffer must have sufficient capacity for the decrypted data.
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
    let guard = match FACTORY.read() {
        Ok(g) => g,
        Err(_) => return ERR_PANIC,
    };
    let factory = match guard.as_ref() {
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
        Err(e) => {
            log::error!("DecryptFromJson failed: {e:#}");
            return ERR_DECRYPT_FAILED;
        }
    };

    // Write output
    cobhan_bytes_to_buffer(&plaintext, data_ptr)
}

// ============================================================================
// Test Helpers (available for integration tests)
// ============================================================================

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::{canaries_enabled, canary_overhead, verify_canaries, write_canaries};

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
    pub const ERR_NOT_INITIALIZED: i32 = -100;
    pub const ERR_ALREADY_INITIALIZED: i32 = -101;
    pub const ERR_GET_SESSION_FAILED: i32 = -102;
    pub const ERR_ENCRYPT_FAILED: i32 = -103;
    pub const ERR_DECRYPT_FAILED: i32 = -104;
    pub const ERR_BAD_CONFIG: i32 = -105;
    pub const ERR_PANIC: i32 = -106;

    /// Creates a cobhan input buffer from bytes.
    /// Layout: [length:i32le][reserved:i32le=0][data...][canary1?][canary2?][padding?]
    pub fn create_input_buffer(data: &[u8]) -> Vec<u8> {
        let overhead = canary_overhead();
        let mut buf = vec![0u8; BUFFER_HEADER_SIZE as usize + data.len() + overhead];
        let len = data.len() as i32;
        buf[0..4].copy_from_slice(&len.to_le_bytes());
        buf[BUFFER_HEADER_SIZE as usize..BUFFER_HEADER_SIZE as usize + data.len()]
            .copy_from_slice(data);
        if canaries_enabled() {
            let canary_offset = BUFFER_HEADER_SIZE as usize + data.len();
            write_canaries(&mut buf, canary_offset);
        }
        buf
    }

    /// Creates a cobhan input buffer from a string.
    pub fn create_string_buffer(s: &str) -> Vec<u8> {
        create_input_buffer(s.as_bytes())
    }

    /// Creates a cobhan output buffer with the given capacity.
    /// Capacity is stored at bytes 0-3 (matching Go cobhan.AllocateBuffer).
    /// When canaries are enabled, canary values are placed after the capacity region.
    pub fn create_output_buffer(capacity: i32) -> Vec<u8> {
        let overhead = canary_overhead();
        let mut buf = vec![0u8; BUFFER_HEADER_SIZE as usize + capacity as usize + overhead];
        // Capacity in bytes 0-3 (Go convention: output buffer length = capacity)
        buf[0..4].copy_from_slice(&capacity.to_le_bytes());
        // Bytes 4-7 are reserved (zero)
        if canaries_enabled() {
            // Canaries go after the full capacity region
            let canary_offset = BUFFER_HEADER_SIZE as usize + capacity as usize;
            write_canaries(&mut buf, canary_offset);
        }
        buf
    }

    /// Creates a scalar buffer for int64 values (no header, just 8 bytes).
    /// Matches Go cobhan scalar buffer convention.
    pub fn create_scalar_buffer() -> Vec<u8> {
        vec![0u8; 8]
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

    /// Reads the data from a cobhan input buffer, verifying canaries if enabled.
    /// For input buffers, canaries are placed right after the data.
    pub fn get_input_buffer_data(buf: &[u8]) -> &[u8] {
        let len = get_buffer_length(buf) as usize;
        if canaries_enabled() {
            let canary_offset = BUFFER_HEADER_SIZE as usize + len;
            verify_canaries(buf, canary_offset);
        }
        &buf[BUFFER_HEADER_SIZE as usize..BUFFER_HEADER_SIZE as usize + len]
    }

    /// Verifies canaries on an output buffer that has been written to.
    /// For output buffers, canaries are placed after the full capacity region.
    /// Call this after an FFI function has written to the output buffer.
    pub fn verify_output_canaries(buf: &[u8], original_capacity: i32) {
        if canaries_enabled() {
            let canary_offset = BUFFER_HEADER_SIZE as usize + original_capacity as usize;
            verify_canaries(buf, canary_offset);
        }
    }

    /// Reads a string from a cobhan buffer.
    pub fn get_buffer_string(buf: &[u8]) -> String {
        String::from_utf8_lossy(get_buffer_data(buf)).to_string()
    }

    /// Reads an i64 directly from a scalar buffer (no header, offset 0).
    /// Matches Go cobhan.BufferToInt64 which reads raw value at offset 0.
    pub fn get_buffer_i64(buf: &[u8]) -> i64 {
        i64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ])
    }
}

// ============================================================================
// Unit Tests - Cobhan Buffer Format
// ============================================================================

#[cfg(test)]
mod tests {
    use super::test_helpers::{
        create_input_buffer, create_output_buffer, create_scalar_buffer, create_string_buffer,
        get_buffer_data, get_buffer_i64, get_buffer_length, get_buffer_string,
    };
    use super::*;

    // ========================================================================
    // Buffer Length Tests
    // ========================================================================

    #[test]
    fn test_buffer_length_positive() {
        let buf = create_input_buffer(b"hello");
        assert_eq!(get_buffer_length(&buf), 5);
    }

    #[test]
    fn test_buffer_length_set_and_get() {
        let mut buf = [0u8; 16];
        unsafe {
            cobhan_buffer_set_length(buf.as_mut_ptr().cast::<c_char>(), 42);
            let len = cobhan_buffer_get_length(buf.as_ptr().cast::<c_char>());
            assert_eq!(len, 42);
        }
    }

    #[test]
    fn test_buffer_length_max_positive() {
        let mut buf = [0u8; 16];
        unsafe {
            cobhan_buffer_set_length(buf.as_mut_ptr().cast::<c_char>(), i32::MAX);
            let len = cobhan_buffer_get_length(buf.as_ptr().cast::<c_char>());
            assert_eq!(len, i32::MAX);
        }
    }

    #[test]
    fn test_buffer_length_negative() {
        let mut buf = [0u8; 16];
        unsafe {
            cobhan_buffer_set_length(buf.as_mut_ptr().cast::<c_char>(), -1);
            let len = cobhan_buffer_get_length(buf.as_ptr().cast::<c_char>());
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
            cobhan_buffer_set_length(ptr::null_mut(), 42);
        }
    }

    // ========================================================================
    // Buffer Data Pointer Tests
    // ========================================================================

    #[test]
    fn test_buffer_data_ptr_offset() {
        let buf = create_input_buffer(b"test data");
        unsafe {
            let data_ptr = cobhan_buffer_get_data_ptr(buf.as_ptr().cast::<c_char>());
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
            let result = cobhan_buffer_to_bytes(buf.as_ptr().cast::<c_char>());
            assert!(result.is_ok());
            assert_eq!(result.expect("should be ok"), Vec::<u8>::new());
        }
    }

    #[test]
    fn test_buffer_to_bytes_simple() {
        let data = b"hello world";
        let buf = create_input_buffer(data);
        unsafe {
            let result = cobhan_buffer_to_bytes(buf.as_ptr().cast::<c_char>());
            assert!(result.is_ok());
            assert_eq!(result.expect("should be ok"), data.to_vec());
        }
    }

    #[test]
    fn test_buffer_to_bytes_binary_data() {
        let data: Vec<u8> = (0u8..=255).collect();
        let buf = create_input_buffer(&data);
        unsafe {
            let result = cobhan_buffer_to_bytes(buf.as_ptr().cast::<c_char>());
            assert!(result.is_ok());
            assert_eq!(result.expect("should be ok"), data);
        }
    }

    #[test]
    fn test_buffer_to_bytes_with_null_bytes() {
        let data = b"hello\0world\0test";
        let buf = create_input_buffer(data);
        unsafe {
            let result = cobhan_buffer_to_bytes(buf.as_ptr().cast::<c_char>());
            assert!(result.is_ok());
            assert_eq!(result.expect("should be ok"), data.to_vec());
        }
    }

    #[test]
    fn test_buffer_to_bytes_null_ptr() {
        unsafe {
            let result = cobhan_buffer_to_bytes(ptr::null());
            assert!(result.is_err());
            assert_eq!(result.expect_err("should be err"), ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_buffer_to_bytes_negative_length() {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&(-1_i32).to_le_bytes());
        unsafe {
            let result = cobhan_buffer_to_bytes(buf.as_ptr().cast::<c_char>());
            assert!(result.is_err());
            assert_eq!(result.expect_err("should be err"), ERR_BUFFER_TOO_LARGE);
        }
    }

    // ========================================================================
    // Buffer to String Tests
    // ========================================================================

    #[test]
    fn test_buffer_to_string_simple() {
        let buf = create_string_buffer("hello world");
        unsafe {
            let result = cobhan_buffer_to_string(buf.as_ptr().cast::<c_char>());
            assert!(result.is_ok());
            assert_eq!(result.expect("should be ok"), "hello world");
        }
    }

    #[test]
    fn test_buffer_to_string_empty() {
        let buf = create_string_buffer("");
        unsafe {
            let result = cobhan_buffer_to_string(buf.as_ptr().cast::<c_char>());
            assert!(result.is_ok());
            assert_eq!(result.expect("should be ok"), "");
        }
    }

    #[test]
    fn test_buffer_to_string_unicode() {
        let buf = create_string_buffer("Hello, 世界! 🦀");
        unsafe {
            let result = cobhan_buffer_to_string(buf.as_ptr().cast::<c_char>());
            assert!(result.is_ok());
            assert_eq!(result.expect("should be ok"), "Hello, 世界! 🦀");
        }
    }

    #[test]
    fn test_buffer_to_string_invalid_utf8() {
        let invalid_utf8 = vec![0xFF, 0xFE, 0x00, 0x01];
        let buf = create_input_buffer(&invalid_utf8);
        unsafe {
            let result = cobhan_buffer_to_string(buf.as_ptr().cast::<c_char>());
            assert!(result.is_err());
            assert_eq!(result.expect_err("should be err"), ERR_JSON_DECODE_FAILED);
        }
    }

    #[test]
    fn test_buffer_to_string_null_ptr() {
        unsafe {
            let result = cobhan_buffer_to_string(ptr::null());
            assert!(result.is_err());
            assert_eq!(result.expect_err("should be err"), ERR_NULL_PTR);
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
            let result = cobhan_bytes_to_buffer(data, buf.as_mut_ptr().cast::<c_char>());
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
            let result = cobhan_bytes_to_buffer(data, buf.as_mut_ptr().cast::<c_char>());
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_length(&buf), 0);
        }
    }

    #[test]
    fn test_bytes_to_buffer_exact_capacity() {
        let data = b"exactly fits";
        let mut buf = create_output_buffer(data.len() as i32);
        unsafe {
            let result = cobhan_bytes_to_buffer(data, buf.as_mut_ptr().cast::<c_char>());
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_data(&buf), data);
        }
    }

    #[test]
    fn test_bytes_to_buffer_insufficient_capacity() {
        let data = b"this is too long for the buffer";
        let mut buf = create_output_buffer(10);
        unsafe {
            let result = cobhan_bytes_to_buffer(data, buf.as_mut_ptr().cast::<c_char>());
            assert_eq!(result, ERR_BUFFER_TOO_SMALL);
        }
    }

    #[test]
    fn test_bytes_to_buffer_null_ptr() {
        let data = b"hello";
        unsafe {
            let result = cobhan_bytes_to_buffer(data, ptr::null_mut());
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_bytes_to_buffer_binary_data() {
        let data: Vec<u8> = (0u8..=255).collect();
        let mut buf = create_output_buffer(data.len() as i32);
        unsafe {
            let result = cobhan_bytes_to_buffer(&data, buf.as_mut_ptr().cast::<c_char>());
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
            let write_result = cobhan_bytes_to_buffer(data, buf.as_mut_ptr().cast::<c_char>());
            assert_eq!(write_result, ERR_NONE);

            let read_result = cobhan_buffer_to_bytes(buf.as_ptr().cast::<c_char>());
            assert!(read_result.is_ok());
            assert_eq!(read_result.expect("should be ok"), data.to_vec());
        }
    }

    #[test]
    fn test_bytes_roundtrip_large_data() {
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let mut buf = create_output_buffer(data.len() as i32);

        unsafe {
            let write_result = cobhan_bytes_to_buffer(&data, buf.as_mut_ptr().cast::<c_char>());
            assert_eq!(write_result, ERR_NONE);

            let read_result = cobhan_buffer_to_bytes(buf.as_ptr().cast::<c_char>());
            assert!(read_result.is_ok());
            assert_eq!(read_result.expect("should be ok"), data);
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
                cobhan_buffer_to_json(buf.as_ptr().cast::<c_char>());
            assert!(result.is_ok());
            let map = result.expect("should be ok");
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
            let result: Result<TestObj, i32> = cobhan_buffer_to_json(buf.as_ptr().cast::<c_char>());
            assert!(result.is_ok());
            let obj = result.expect("should be ok");
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
                cobhan_buffer_to_json(buf.as_ptr().cast::<c_char>());
            assert!(result.is_err());
            assert_eq!(result.expect_err("should be err"), ERR_JSON_DECODE_FAILED);
        }
    }

    #[test]
    fn test_buffer_to_json_null_ptr() {
        unsafe {
            let result: Result<HashMap<String, String>, i32> = cobhan_buffer_to_json(ptr::null());
            assert!(result.is_err());
            assert_eq!(result.expect_err("should be err"), ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_json_to_buffer_simple() {
        let map: HashMap<String, String> = [("key".to_string(), "value".to_string())]
            .into_iter()
            .collect();
        let mut buf = create_output_buffer(100);

        unsafe {
            let result = cobhan_json_to_buffer(&map, buf.as_mut_ptr().cast::<c_char>());
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
            let result = cobhan_json_to_buffer(&large_map, buf.as_mut_ptr().cast::<c_char>());
            assert_eq!(result, ERR_BUFFER_TOO_SMALL);
        }
    }

    // ========================================================================
    // Scalar Buffer Tests (int64/int32 - no header, raw value at offset 0)
    // ========================================================================

    #[test]
    fn test_int64_to_buffer_positive() {
        let mut buf = create_scalar_buffer();
        unsafe {
            let result =
                cobhan_int64_to_buffer(1234567890123_i64, buf.as_mut_ptr().cast::<c_char>());
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_i64(&buf), 1234567890123_i64);
        }
    }

    #[test]
    fn test_int64_to_buffer_negative() {
        let mut buf = create_scalar_buffer();
        unsafe {
            let result = cobhan_int64_to_buffer(-9876543210_i64, buf.as_mut_ptr().cast::<c_char>());
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_i64(&buf), -9876543210_i64);
        }
    }

    #[test]
    fn test_int64_to_buffer_zero() {
        let mut buf = create_scalar_buffer();
        unsafe {
            let result = cobhan_int64_to_buffer(0, buf.as_mut_ptr().cast::<c_char>());
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_i64(&buf), 0);
        }
    }

    #[test]
    fn test_int64_to_buffer_max() {
        let mut buf = create_scalar_buffer();
        unsafe {
            let result = cobhan_int64_to_buffer(i64::MAX, buf.as_mut_ptr().cast::<c_char>());
            assert_eq!(result, ERR_NONE);
            assert_eq!(get_buffer_i64(&buf), i64::MAX);
        }
    }

    #[test]
    fn test_int64_to_buffer_min() {
        let mut buf = create_scalar_buffer();
        unsafe {
            let result = cobhan_int64_to_buffer(i64::MIN, buf.as_mut_ptr().cast::<c_char>());
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

    #[test]
    fn test_int32_to_buffer_positive() {
        let mut buf = vec![0u8; 4];
        unsafe {
            let result = cobhan_int32_to_buffer(123456, buf.as_mut_ptr().cast::<c_char>());
            assert_eq!(result, ERR_NONE);
            let value = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            assert_eq!(value, 123456);
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
    }

    #[test]
    fn test_estimate_buffer_medium_data() {
        let estimate = EstimateBuffer(1000, 50);
        assert!(estimate > 1000, "Should be larger than data length");
    }

    #[test]
    fn test_estimate_buffer_large_data() {
        let estimate = EstimateBuffer(100_000, 100);
        assert!(estimate > 100_000, "Should handle large data");
    }

    #[test]
    fn test_estimate_buffer_zero_data() {
        let estimate = EstimateBuffer(0, 10);
        assert!(
            estimate > 0,
            "Should return positive estimate even for zero data"
        );
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
        let e1 = EstimateBuffer(500, 25);
        let e2 = EstimateBuffer(500, 25);
        assert_eq!(e1, e2, "EstimateBuffer should be deterministic");
    }

    #[test]
    fn test_estimate_buffer_monotonic_with_data() {
        let e1 = EstimateBuffer(100, 20);
        let e2 = EstimateBuffer(200, 20);
        let e3 = EstimateBuffer(300, 20);
        assert!(e2 >= e1, "Estimate should increase with data size");
        assert!(e3 >= e2, "Estimate should increase with data size");
    }

    // ========================================================================
    // SetEnv Tests
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
            let result = SetEnv(buf.as_ptr().cast::<c_char>());
            assert_eq!(result, ERR_JSON_DECODE_FAILED);
        }
    }

    #[test]
    fn test_set_env_empty_object() {
        let buf = create_string_buffer("{}");
        unsafe {
            let result = SetEnv(buf.as_ptr().cast::<c_char>());
            assert_eq!(result, ERR_NONE);
        }
    }

    #[test]
    fn test_set_env_sets_variables() {
        let unique_key = format!("ASHERAH_TEST_VAR_{}", std::process::id());
        let json = format!(r#"{{"{unique_key}": "test_value"}}"#);
        let buf = create_string_buffer(&json);

        std::env::remove_var(&unique_key);

        unsafe {
            let result = SetEnv(buf.as_ptr().cast::<c_char>());
            assert_eq!(result, ERR_NONE);
        }

        assert_eq!(
            std::env::var(&unique_key).ok(),
            Some("test_value".to_string())
        );

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
            let result = SetEnv(buf.as_ptr().cast::<c_char>());
            assert_eq!(result, ERR_NONE);
        }

        assert_eq!(std::env::var(&key1).ok(), Some("value1".to_string()));
        assert_eq!(std::env::var(&key2).ok(), Some("value2".to_string()));

        std::env::remove_var(&key1);
        std::env::remove_var(&key2);
    }

    // ========================================================================
    // SetupJson Tests
    // ========================================================================

    #[test]
    fn test_setup_json_null_pointer() {
        unsafe {
            let result = SetupJson(ptr::null());
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    // ========================================================================
    // Encrypt/Decrypt Null Pointer Tests
    // ========================================================================

    #[test]
    fn test_encrypt_null_partition_id() {
        let data = create_input_buffer(b"test");
        let mut out1 = create_output_buffer(1000);
        let mut out2 = create_output_buffer(1000);
        let mut out3 = create_scalar_buffer();
        let mut out4 = create_output_buffer(100);
        let mut out5 = create_scalar_buffer();

        unsafe {
            let result = Encrypt(
                ptr::null(),
                data.as_ptr().cast::<c_char>(),
                out1.as_mut_ptr().cast::<c_char>(),
                out2.as_mut_ptr().cast::<c_char>(),
                out3.as_mut_ptr().cast::<c_char>(),
                out4.as_mut_ptr().cast::<c_char>(),
                out5.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_encrypt_null_data() {
        let partition = create_string_buffer("partition");
        let mut out1 = create_output_buffer(1000);
        let mut out2 = create_output_buffer(1000);
        let mut out3 = create_scalar_buffer();
        let mut out4 = create_output_buffer(100);
        let mut out5 = create_scalar_buffer();

        unsafe {
            let result = Encrypt(
                partition.as_ptr().cast::<c_char>(),
                ptr::null(),
                out1.as_mut_ptr().cast::<c_char>(),
                out2.as_mut_ptr().cast::<c_char>(),
                out3.as_mut_ptr().cast::<c_char>(),
                out4.as_mut_ptr().cast::<c_char>(),
                out5.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(result, ERR_NULL_PTR);
        }
    }

    #[test]
    fn test_encrypt_null_outputs() {
        let partition = create_string_buffer("partition");
        let data = create_input_buffer(b"test");

        unsafe {
            let result = Encrypt(
                partition.as_ptr().cast::<c_char>(),
                data.as_ptr().cast::<c_char>(),
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
                partition.as_ptr().cast::<c_char>(),
                partition.as_ptr().cast::<c_char>(),
                0,
                partition.as_ptr().cast::<c_char>(),
                0,
                output.as_mut_ptr().cast::<c_char>(),
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
            let result = EncryptToJson(
                ptr::null(),
                data.as_ptr().cast::<c_char>(),
                output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(result, ERR_NULL_PTR);

            let result = EncryptToJson(
                partition.as_ptr().cast::<c_char>(),
                ptr::null(),
                output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(result, ERR_NULL_PTR);

            let result = EncryptToJson(
                partition.as_ptr().cast::<c_char>(),
                data.as_ptr().cast::<c_char>(),
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
            let result = DecryptFromJson(
                ptr::null(),
                json.as_ptr().cast::<c_char>(),
                output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(result, ERR_NULL_PTR);

            let result = DecryptFromJson(
                partition.as_ptr().cast::<c_char>(),
                ptr::null(),
                output.as_mut_ptr().cast::<c_char>(),
            );
            assert_eq!(result, ERR_NULL_PTR);

            let result = DecryptFromJson(
                partition.as_ptr().cast::<c_char>(),
                json.as_ptr().cast::<c_char>(),
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
        Shutdown();
        Shutdown();
        Shutdown();
    }
}
