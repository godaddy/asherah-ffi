# asherah

Python bindings for the [Asherah](https://github.com/godaddy/asherah-ffi) envelope encryption and automatic key rotation library.

Prebuilt wheels for Python 3.8+ (stable ABI): Linux x64/ARM64 (manylinux + musl), macOS universal2, Windows x64/ARM64.

## Installation

```bash
pip install asherah
```

## Quick Start (Static API)

The static API manages a global session factory internally. Call `setup()` once, then encrypt/decrypt with partition-scoped functions.

```python
import os
os.environ["STATIC_MASTER_KEY_HEX"] = "22" * 32  # testing only

import asherah

asherah.setup({
    "ServiceName": "my-service",
    "ProductID": "my-product",
    "Metastore": "memory",
    "KMS": "static",
    "EnableSessionCaching": True,
})

ciphertext = asherah.encrypt_string("partition-1", "sensitive data")
plaintext = asherah.decrypt_string("partition-1", ciphertext)
print(plaintext)  # "sensitive data"

asherah.shutdown()
```

## Session-Based API

The `SessionFactory` class reads configuration from environment variables (set them before construction). Each `Session` is scoped to a partition. Both support context managers.

```python
import os
os.environ["SERVICE_NAME"] = "my-service"
os.environ["PRODUCT_ID"] = "my-product"
os.environ["Metastore"] = "memory"
os.environ["KMS"] = "static"
os.environ["STATIC_MASTER_KEY_HEX"] = "22" * 32
os.environ["SESSION_CACHE"] = "1"

import asherah

with asherah.SessionFactory() as factory:
    with factory.get_session("partition-1") as session:
        ciphertext = session.encrypt_bytes(b"secret")
        plaintext = session.decrypt_bytes(ciphertext)
        print(plaintext)  # b"secret"

        # Text variants
        ct = session.encrypt_text("hello")
        pt = session.decrypt_text(ct)
        print(pt)  # "hello"
```

## Async API

Async wrappers dispatch to the default thread pool executor via `asyncio.run_in_executor`. The GIL is released during the native call.

```python
import asyncio
import os
os.environ["STATIC_MASTER_KEY_HEX"] = "22" * 32

import asherah

async def main():
    await asherah.setup_async({
        "ServiceName": "my-service",
        "ProductID": "my-product",
        "Metastore": "memory",
        "KMS": "static",
    })

    ciphertext = await asherah.encrypt_string_async("partition-1", "data")
    plaintext = await asherah.decrypt_string_async("partition-1", ciphertext)
    print(plaintext)  # "data"

    await asherah.shutdown_async()

asyncio.run(main())
```

### Async Behavior

- The event loop is **not** blocked -- work runs on a thread pool thread.
- The GIL is released during the native Rust call.
- Overhead: ~37 us vs ~1 us sync (hot cache, 64B payload).
- Best for: I/O-bound asyncio applications that need non-blocking encryption.

For CPU-bound batch encryption, use the sync API directly.

## Configuration

The `setup()` function accepts a dict (or any JSON-serializable object) with PascalCase keys matching the Go canonical API:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `ServiceName` | str | Yes | Service identifier for key hierarchy |
| `ProductID` | str | Yes | Product identifier for key hierarchy |
| `Metastore` | str | Yes | `"memory"`, `"sqlite"`, `"rdbms"`, or `"dynamodb"` |
| `KMS` | str | No | `"static"` (default) or `"aws"` |
| `ConnectionString` | str | Conditional | Required for `sqlite` and `rdbms` metastores |
| `RegionMap` | dict | Conditional | Required for `aws` KMS. Maps preferred region to ARN. |
| `PreferredRegion` | str | No | Preferred AWS region for KMS |
| `EnableRegionSuffix` | bool | No | Append region suffix to system key IDs |
| `EnableSessionCaching` | bool | No | Enable session caching (default: true) |
| `SessionCacheMaxSize` | int | No | Max cached sessions |
| `SessionCacheDuration` | int | No | Cache TTL in seconds |
| `ExpireAfter` | int | No | Key expiration in seconds |
| `CheckInterval` | int | No | Revocation check interval in seconds |
| `DynamoDBEndpoint` | str | No | Custom DynamoDB endpoint URL |
| `DynamoDBRegion` | str | No | DynamoDB region |
| `DynamoDBSigningRegion` | str | No | Signing region (overrides `DynamoDBRegion`) |
| `DynamoDBTableName` | str | No | DynamoDB table name |
| `ReplicaReadConsistency` | str | No | DynamoDB read consistency |
| `SQLMetastoreDBType` | str | No | `"mysql"` or `"postgres"` hint for rdbms |
| `Verbose` | bool | No | Enable verbose logging |
| `EnableCanaries` | bool | No | Enable canary buffer overflow detection |
| `NullDataCheck` | bool | No | Enable null data validation |
| `DisableZeroCopy` | bool | No | Disable zero-copy optimization |

### AWS KMS Example

```python
asherah.setup({
    "ServiceName": "my-service",
    "ProductID": "my-product",
    "Metastore": "dynamodb",
    "KMS": "aws",
    "RegionMap": {
        "us-west-2": "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123"
    },
    "PreferredRegion": "us-west-2",
    "DynamoDBTableName": "EncryptionKey",
    "EnableSessionCaching": True,
})
```

## Performance

Approximate latency on Apple M4 Max (hot cache, 64-byte payload):

| Operation | Latency |
|-----------|---------|
| Encrypt | ~1,049 ns |
| Decrypt | ~791 ns |

This Rust-backed implementation replaces the Go Cobhan-based canonical `asherah` PyPI package. Run `scripts/benchmark.sh` for head-to-head comparisons.

## API Reference

### Static Functions

| Function | Description |
|----------|-------------|
| `setup(config)` | Initialize the global session factory from a config dict |
| `shutdown()` | Shut down the global session factory and release resources |
| `get_setup_status()` | Returns `True` if `setup()` has been called |
| `encrypt_bytes(partition_id, data)` | Encrypt `bytes`, returns JSON `str` (DataRowRecord) |
| `encrypt_string(partition_id, text)` | Encrypt `str`, returns JSON `str` (DataRowRecord) |
| `decrypt_bytes(partition_id, drr)` | Decrypt JSON DataRowRecord, returns `bytes` |
| `decrypt_string(partition_id, drr)` | Decrypt JSON DataRowRecord, returns `str` |
| `setenv(env_dict)` | Set environment variables from a dict (both `os.environ` and Rust) |
| `set_metrics_hook(callback)` | Register a callback for metrics events, or `None` to clear |
| `set_log_hook(callback)` | Register a callback for log events, or `None` to clear |
| `version()` | Returns the native library version string |

### Async Functions

| Function | Description |
|----------|-------------|
| `setup_async(config)` | Async version of `setup()` |
| `shutdown_async()` | Async version of `shutdown()` |
| `encrypt_bytes_async(partition_id, data)` | Async version of `encrypt_bytes()` |
| `encrypt_string_async(partition_id, text)` | Async version of `encrypt_string()` |
| `decrypt_bytes_async(partition_id, drr)` | Async version of `decrypt_bytes()` |
| `decrypt_string_async(partition_id, drr)` | Async version of `decrypt_string()` |

### Classes

#### `SessionFactory`

Constructed from environment variables (not a config dict). Supports context manager protocol.

| Method | Description |
|--------|-------------|
| `SessionFactory()` | Create from env vars |
| `SessionFactory.from_env()` | Same as constructor |
| `get_session(partition_id)` | Create a `Session` for the given partition |
| `close()` | Release resources |

#### `Session`

Scoped to a single partition. Supports context manager protocol.

| Method | Description |
|--------|-------------|
| `encrypt_bytes(data)` | Encrypt `bytes`, returns JSON `str` |
| `encrypt_text(text)` | Encrypt `str`, returns JSON `str` |
| `decrypt_bytes(drr)` | Decrypt JSON DataRowRecord, returns `bytes` |
| `decrypt_text(drr)` | Decrypt JSON DataRowRecord, returns `str` |
| `close()` | Release resources |

### Hooks

#### Metrics Hook

```python
def on_metric(event):
    # event is a dict with "type" and additional fields
    # type: "encrypt", "decrypt", "store", "load" -> has "duration_ns"
    # type: "cache_hit", "cache_miss" -> has "name"
    print(event)

asherah.set_metrics_hook(on_metric)
asherah.set_metrics_hook(None)  # clear
```

#### Log Hook

```python
def on_log(record):
    # record is a dict with "level", "message", "target"
    print(f"[{record['level']}] {record['target']}: {record['message']}")

asherah.set_log_hook(on_log)
asherah.set_log_hook(None)  # clear
```

## Cross-Language Compatibility

Ciphertext produced by any Asherah implementation (Go, Node.js, Java, .NET, Ruby) can be decrypted by any other, as long as they share the same metastore and KMS configuration. The DataRowRecord JSON format is the interchange format.

## License

Licensed under the Apache License, Version 2.0.
