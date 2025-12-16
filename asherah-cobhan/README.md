# Asherah-Cobhan

A Rust implementation of the Asherah encryption library with a C ABI using the Cobhan buffer format. This is a drop-in replacement for the original [Go asherah-cobhan](https://github.com/godaddy/asherah/tree/main/server/go/pkg/libasherah) library.

## Overview

Asherah-Cobhan provides application-layer encryption using the Asherah envelope encryption scheme, exposed through a C-compatible FFI interface. It uses the Cobhan buffer format for efficient cross-language data passing.

## Features

- **Binary Compatible**: Drop-in replacement for Go asherah-cobhan
- **C ABI**: Compatible with any language that can call C functions
- **Cobhan Buffer Format**: Efficient 8-byte header format for cross-language FFI
- **Multiple KMS Support**: Static, AWS KMS, and GCP KMS key management
- **Multiple Metastores**: In-memory, RDBMS (SQLite, MySQL, PostgreSQL), and DynamoDB

## Building

```bash
# Build the shared library
cargo build -p asherah-cobhan --release

# The library will be at:
# - macOS: target/release/libasherah_cobhan.dylib
# - Linux: target/release/libasherah_cobhan.so
# - Windows: target/release/asherah_cobhan.dll
```

## C API

### Function Signatures

```c
// Shutdown the Asherah factory and release resources
void Shutdown();

// Set environment variables from JSON
// Returns: 0 on success, negative error code on failure
int32_t SetEnv(char* envJson);

// Initialize Asherah with JSON configuration
// Returns: 0 on success, negative error code on failure
int32_t SetupJson(char* configJson);

// Estimate output buffer size for encryption
// Returns: Recommended buffer size in bytes
int32_t EstimateBuffer(int32_t dataLen, int32_t partitionLen);

// Encrypt data to separate components
// Returns: 0 on success, negative error code on failure
int32_t Encrypt(
    char* partitionId,
    char* data,
    char* encryptedData,      // output
    char* encryptedKey,       // output
    char* created,            // output (int64)
    char* parentKeyId,        // output
    char* parentKeyCreated    // output (int64)
);

// Decrypt data from separate components
// Returns: 0 on success, negative error code on failure
int32_t Decrypt(
    char* partitionId,
    char* encryptedData,
    char* encryptedKey,
    int64_t created,
    char* parentKeyId,
    int64_t parentKeyCreated,
    char* data                // output
);

// Encrypt data to JSON DataRowRecord format
// Returns: 0 on success, negative error code on failure
int32_t EncryptToJson(
    char* partitionId,
    char* data,
    char* jsonOutput          // output
);

// Decrypt data from JSON DataRowRecord format
// Returns: 0 on success, negative error code on failure
int32_t DecryptFromJson(
    char* partitionId,
    char* jsonInput,
    char* dataOutput          // output
);
```

### Cobhan Buffer Format

All buffer parameters use the Cobhan format:

```
Offset 0-3:  int32_t length (little-endian)
Offset 4-7:  int32_t capacity (little-endian, for output buffers)
Offset 8+:   data payload
```

**Input buffers**: Set `length` to the data size, `capacity` is ignored.

**Output buffers**: Set `length` to 0, `capacity` to the buffer size minus 8.

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | ERR_NONE | Success |
| -1 | ERR_NULL_PTR | Null pointer provided |
| -2 | ERR_BUFFER_TOO_LARGE | Buffer length exceeds maximum |
| -3 | ERR_BUFFER_TOO_SMALL | Destination buffer insufficient |
| -4 | ERR_COPY_FAILED | Copy operation incomplete |
| -5 | ERR_JSON_DECODE_FAILED | JSON unmarshaling error |
| -6 | ERR_JSON_ENCODE_FAILED | JSON marshaling error |
| -100 | ERR_ALREADY_INITIALIZED | Already initialized |
| -101 | ERR_BAD_CONFIG | Bad configuration |
| -102 | ERR_NOT_INITIALIZED | Not initialized |
| -103 | ERR_ENCRYPT_FAILED | Encryption failed |
| -104 | ERR_DECRYPT_FAILED | Decryption failed |

## Configuration

Initialize with `SetupJson` using a JSON configuration:

```json
{
  "ServiceName": "my-service",
  "ProductID": "my-product",
  "Metastore": "memory",
  "KMS": "static",
  "EnableSessionCaching": true
}
```

### Configuration Options

| Field | Type | Description |
|-------|------|-------------|
| `ServiceName` | string | Service identifier (required) |
| `ProductID` | string | Product identifier (required) |
| `Metastore` | string | `"memory"`, `"rdbms"`, or `"dynamodb"` |
| `KMS` | string | `"static"`, `"aws"`, or `"gcp"` |
| `EnableSessionCaching` | bool | Enable session key caching |
| `ExpireAfter` | duration | Session cache expiration |
| `CheckInterval` | duration | Session cache check interval |
| `ConnectionString` | string | RDBMS connection string |
| `DynamoDBEndpoint` | string | DynamoDB endpoint URL |
| `DynamoDBRegion` | string | DynamoDB region |
| `DynamoDBTableName` | string | DynamoDB table name |
| `RegionMap` | object | KMS region configuration |
| `PreferredRegion` | string | Preferred KMS region |

### KMS Configuration

**Static KMS** (for testing):
```bash
export STATIC_MASTER_KEY_HEX="<64-hex-chars>"
```

**AWS KMS**:
```json
{
  "KMS": "aws",
  "RegionMap": {
    "us-west-2": "arn:aws:kms:us-west-2:123456789:key/abc-123"
  },
  "PreferredRegion": "us-west-2"
}
```

**GCP KMS**:
```json
{
  "KMS": "gcp",
  "RegionMap": {
    "us-west1": "projects/my-project/locations/us-west1/keyRings/my-ring/cryptoKeys/my-key"
  },
  "PreferredRegion": "us-west1"
}
```

## JSON DataRowRecord Format

The `EncryptToJson` and `DecryptFromJson` functions use this JSON format:

```json
{
  "Data": "<base64-encoded-ciphertext>",
  "Key": {
    "Created": 1700000000000,
    "Key": "<base64-encoded-encrypted-key>",
    "ParentKeyMeta": {
      "KeyId": "_SK_service_product",
      "Created": 1700000000000
    }
  }
}
```

## Usage Example (C)

```c
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Create an input buffer
void* create_input_buffer(const char* data, int32_t len) {
    char* buf = malloc(8 + len);
    // Set length (little-endian)
    buf[0] = len & 0xFF;
    buf[1] = (len >> 8) & 0xFF;
    buf[2] = (len >> 16) & 0xFF;
    buf[3] = (len >> 24) & 0xFF;
    // Reserved/capacity
    buf[4] = buf[5] = buf[6] = buf[7] = 0;
    // Copy data
    memcpy(buf + 8, data, len);
    return buf;
}

// Create an output buffer
void* create_output_buffer(int32_t capacity) {
    char* buf = malloc(8 + capacity);
    // Set length to 0
    buf[0] = buf[1] = buf[2] = buf[3] = 0;
    // Set capacity (little-endian)
    buf[4] = capacity & 0xFF;
    buf[5] = (capacity >> 8) & 0xFF;
    buf[6] = (capacity >> 16) & 0xFF;
    buf[7] = (capacity >> 24) & 0xFF;
    return buf;
}

int main() {
    // Initialize
    const char* config = "{\"ServiceName\":\"test\",\"ProductID\":\"test\",\"Metastore\":\"memory\",\"KMS\":\"static\"}";
    void* config_buf = create_input_buffer(config, strlen(config));

    int32_t result = SetupJson(config_buf);
    if (result != 0) {
        // Handle error
        return 1;
    }

    // Encrypt
    const char* partition = "user-123";
    const char* plaintext = "sensitive data";
    void* partition_buf = create_input_buffer(partition, strlen(partition));
    void* data_buf = create_input_buffer(plaintext, strlen(plaintext));

    int32_t estimate = EstimateBuffer(strlen(plaintext), strlen(partition));
    void* json_out = create_output_buffer(estimate);

    result = EncryptToJson(partition_buf, data_buf, json_out);
    if (result != 0) {
        // Handle error
        return 1;
    }

    // Decrypt
    void* decrypted_out = create_output_buffer(strlen(plaintext) + 100);
    result = DecryptFromJson(partition_buf, json_out, decrypted_out);
    if (result != 0) {
        // Handle error
        return 1;
    }

    // Shutdown
    Shutdown();

    // Free buffers
    free(config_buf);
    free(partition_buf);
    free(data_buf);
    free(json_out);
    free(decrypted_out);

    return 0;
}
```

## Testing

```bash
# Run all tests
cargo test -p asherah-cobhan

# Run specific test suites
cargo test -p asherah-cobhan --lib              # Unit tests (66)
cargo test -p asherah-cobhan --test integration_tests  # Integration tests (6)
cargo test -p asherah-cobhan --test interop_tests      # Interop tests (13)

# Run full interop test suite
./interop/run_interop_tests.sh
```

## Interoperability

This implementation is verified to be binary compatible with the Go asherah-cobhan library:

- **JSON Format**: Produces semantically equivalent DataRowRecord JSON
- **Cobhan Buffer**: Uses identical 8-byte header format (little-endian)
- **Error Codes**: Returns the same error codes for equivalent conditions
- **Symbol Names**: Exports the same C function names

See the `interop/` directory for cross-implementation test tools.

## License

Apache-2.0
