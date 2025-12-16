# Asherah-Cobhan Interop Tests

This directory contains interoperability tests to verify that the Rust `asherah-cobhan`
implementation is binary compatible with the original Go `asherah-cobhan` library.

## Test Strategy

### 1. JSON Format Compatibility
The primary interop requirement is that the `DataRowRecord` JSON format is identical
between implementations. Both should produce and consume JSON in this format:

```json
{
  "Data": "<base64-encoded-ciphertext>",
  "Key": {
    "Created": <unix-timestamp>,
    "Key": "<base64-encoded-encrypted-key>",
    "ParentKeyMeta": {
      "KeyId": "<key-id-string>",
      "Created": <unix-timestamp>
    }
  }
}
```

### 2. Cobhan Buffer Format
Both implementations must use the same 8-byte header format:
- Bytes 0-3: int32 length (little-endian)
- Bytes 4-7: int32 capacity (little-endian, for output buffers)
- Bytes 8+: data payload

### 3. Function Signatures
All exported C functions must have identical signatures:
- `Shutdown()` - void
- `SetEnv(envJson *char) int32`
- `SetupJson(configJson *char) int32`
- `EstimateBuffer(dataLen int32, partitionLen int32) int32`
- `Encrypt(...)` - 7 pointer parameters
- `Decrypt(...)` - 5 pointers + 2 int64 parameters
- `EncryptToJson(partitionId, data, jsonOut *char) int32`
- `DecryptFromJson(partitionId, jsonIn, dataOut *char) int32`

### 4. Error Codes
Both implementations must return the same error codes:
- 0: Success (ERR_NONE)
- -1: Null pointer (ERR_NULL_PTR)
- -2: Buffer too large (ERR_BUFFER_TOO_LARGE)
- -3: Buffer too small (ERR_BUFFER_TOO_SMALL)
- -4: Copy failed (ERR_COPY_FAILED)
- -5: JSON decode failed (ERR_JSON_DECODE_FAILED)
- -6: JSON encode failed (ERR_JSON_ENCODE_FAILED)
- -100: Already initialized (ERR_ALREADY_INITIALIZED)
- -101: Bad config (ERR_BAD_CONFIG)
- -102: Not initialized (ERR_NOT_INITIALIZED)
- -103: Encrypt failed (ERR_ENCRYPT_FAILED)
- -104: Decrypt failed (ERR_DECRYPT_FAILED)

## Running Tests

### Using the Rust implementation only (format verification):
```bash
cargo test -p asherah-cobhan --test interop_tests
```

### Full cross-implementation test (requires both libraries):
```bash
./run_interop_tests.sh
```

## Test Vectors

Pre-generated test vectors are stored in `test_vectors/` directory. These vectors
were generated using known inputs and can be decrypted by any compatible implementation.
