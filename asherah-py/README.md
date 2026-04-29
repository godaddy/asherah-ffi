# asherah

Python bindings for the Asherah envelope encryption and key rotation library.

Native Rust implementation via PyO3/maturin. Prebuilt wheels are published to
PyPI for Linux (x86_64 and aarch64, both glibc and musl), macOS (x86_64 and
arm64), and Windows (x86_64 and arm64).

## Installation

```bash
pip install asherah
```

Requires Python ≥ 3.8.

## Documentation

Task-oriented walkthroughs under [`docs/`](./docs/):

| Guide | When to read |
|---|---|
| [Getting started](./docs/getting-started.md) | First-time install through round-trip encrypt/decrypt. |
| [Framework integration](./docs/framework-integration.md) | FastAPI, Flask, Django, AWS Lambda, Celery. |
| [AWS production setup](./docs/aws-production-setup.md) | KMS keys, DynamoDB, IAM policy, region routing. |
| [Testing](./docs/testing.md) | pytest fixtures, Testcontainers, mocking patterns, asyncio test patterns. |
| [Troubleshooting](./docs/troubleshooting.md) | Common errors with what to check first. |

## Choosing an API style

Two API styles are exposed; both are fully supported and produce the same
wire format. New code should prefer the **Factory / Session API**.

| Style | When to use |
|---|---|
| **Static / module-level** (`asherah.setup`, `asherah.encrypt_bytes`, …) | Drop-in compatibility with the canonical `godaddy/asherah-python` package. Simplest call surface. Singleton lifecycle (`setup()` once, `shutdown()` once). |
| **Factory / Session** (`asherah.SessionFactory`, `factory.get_session(...)`) | Recommended for new code. Explicit lifecycle, no hidden singleton, multi-tenant isolation is obvious in code. Context-manager friendly. |

A complete runnable example exercising both styles plus async, log hook, and
metrics hook is in [`samples/python/sample.py`](../samples/python/sample.py).

## Quick start (static API)

```python
import os
import asherah

os.environ["STATIC_MASTER_KEY_HEX"] = "22" * 32  # testing only

asherah.setup({
    "ServiceName": "my-service",
    "ProductID":   "my-product",
    "Metastore":   "memory",   # testing only — use "rdbms" or "dynamodb" in production
    "KMS":         "static",   # testing only — use "aws" in production
})

ct = asherah.encrypt_string("user-42", "secret")
pt = asherah.decrypt_string("user-42", ct)
assert pt == "secret"

asherah.shutdown()
```

## Quick start (factory / session API)

```python
import asherah

with asherah.SessionFactory() as factory:
    with factory.get_session("user-42") as session:
        ct = session.encrypt_text("secret")
        pt = session.decrypt_text(ct)
        assert pt == "secret"
```

`SessionFactory` reads its config from environment variables. Set them with
`asherah.setenv({...})` or via `os.environ` before constructing the factory.

## Async API

There are two flavors of async to choose from depending on your call pattern:

- **Module-level async** (`encrypt_string_async`, `decrypt_string_async`,
  `setup_async`, `shutdown_async`) — wraps the sync calls with
  `loop.run_in_executor`. Lowest setup, but the sync work runs on the
  default thread pool executor.

- **Session-level async** (`session.encrypt_bytes_async`,
  `session.decrypt_bytes_async`) — true async PyO3 coroutines that run
  on the Rust tokio runtime. The asyncio event loop is not blocked, and
  there is no thread pool overhead.

```python
import asyncio
import asherah

async def main():
    # Module-level
    await asherah.setup_async({...})
    ct = await asherah.encrypt_string_async("user-42", "secret")
    pt = await asherah.decrypt_string_async("user-42", ct)
    await asherah.shutdown_async()

    # Session-level (true async)
    with asherah.SessionFactory() as factory:
        session = factory.get_session("user-42")
        ct = await session.encrypt_bytes_async(b"secret")
        pt = await session.decrypt_bytes_async(ct)

asyncio.run(main())
```

## Observability hooks

### Log hook

Receive every log event from the Rust core (encrypt/decrypt path,
metastore drivers, KMS clients).

```python
def on_log(event):
    # event = {"level": "trace"|"debug"|"info"|"warn"|"error",
    #          "message": str, "target": str}
    if event["level"] in ("warn", "error"):
        print(f"[asherah {event['level']}] {event['message']}")

asherah.set_log_hook(on_log)

# later, to deregister:
asherah.set_log_hook(None)
```

The callback may fire from any thread (Rust tokio worker threads, DB
driver threads). PyO3 acquires the GIL before invoking the callback, so
the callback runs single-threaded from Python's perspective.

### Metrics hook

Receive timing events for encrypt/decrypt/store/load and counter events
for cache hit/miss/stale.

```python
def on_metric(event):
    if event["type"] in ("encrypt", "decrypt", "store", "load"):
        # event = {"type": ..., "duration_ns": int}
        my_histogram.observe(event["type"], event["duration_ns"] / 1e6)
    else:
        # event = {"type": "cache_hit"|"cache_miss"|"cache_stale", "name": str}
        my_counter.inc(result=event["type"], cache=event["name"])

asherah.set_metrics_hook(on_metric)

# later:
asherah.set_metrics_hook(None)
```

Metrics collection is enabled automatically when a hook is installed and
disabled when cleared.

## Input contract

**Partition ID** (`None`, `""`): always rejected as programming errors
with `TypeError` (None) or `ValueError`/`Exception` ("partition id
cannot be empty"). No row is ever written to the metastore under a
degenerate partition ID.

**Plaintext** to encrypt:
- `None` → `TypeError` from PyO3 type conversion before any native call.
- Empty `str` (`""`) and empty `bytes` (`b""`) are **valid** plaintexts.
  `encrypt_string` / `encrypt_bytes` produce a real `DataRowRecord`
  envelope; `decrypt_string` / `decrypt_bytes` return exactly `""` or
  `b""`.

**Ciphertext** to decrypt:
- `None` → `TypeError`.
- Empty `str` / `bytes` → exception from JSON parse (not valid
  `DataRowRecord`).

**Do not short-circuit empty plaintext encryption in caller code** —
empty data is real data, encrypting it produces a genuine envelope, and
skipping encryption leaks the fact that the value was empty. See
[docs/input-contract.md](../docs/input-contract.md) for the full
rationale.

## Configuration

`setup()` accepts a dict (or any JSON-serializable object) using
PascalCase keys to match the canonical Go/Java/.NET API:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `ServiceName` | str | yes | Service identifier for the key hierarchy. |
| `ProductID` | str | yes | Product identifier for the key hierarchy. |
| `Metastore` | str | yes | `"memory"`, `"rdbms"`, or `"dynamodb"`. `"memory"` is testing-only. |
| `KMS` | str | | `"static"` (default; testing) or `"aws"`. |
| `ConnectionString` | str | | SQL connection string for `rdbms`. |
| `SQLMetastoreDBType` | str | | `"mysql"` or `"postgres"` (paired with `Metastore: "rdbms"`). |
| `EnableSessionCaching` | bool | | Cache `Session` objects by partition ID. Default `True`. |
| `SessionCacheMaxSize` | int | | Max cached sessions. Default 1000. |
| `SessionCacheDuration` | int | | Session cache TTL in seconds. |
| `RegionMap` | dict[str,str] | | AWS KMS multi-region key-ARN map. |
| `PreferredRegion` | str | | Preferred region from `RegionMap`. |
| `AwsProfileName` | str | | AWS shared-credentials profile name for KMS, DynamoDB, and Secrets Manager clients. |
| `EnableRegionSuffix` | bool | | Append AWS region suffix to key IDs. |
| `ExpireAfter` | int | | Intermediate-key expiration in seconds. Default 90 days. |
| `CheckInterval` | int | | Revoke-check interval in seconds. Default 60 minutes. |
| `DynamoDBEndpoint` | str | | DynamoDB endpoint URL (for local DynamoDB). |
| `DynamoDBRegion` | str | | AWS region for DynamoDB. |
| `DynamoDBTableName` | str | | DynamoDB table name. Default `EncryptionKey`. |
| `ReplicaReadConsistency` | str | | DynamoDB consistency. |
| `Verbose` | bool | | Emit verbose log events (use a log hook to consume). |
| `EnableCanaries` | bool | | Enable in-memory canary buffers around plaintexts. |

Both PascalCase and snake_case keys are accepted; PascalCase is
canonical.

### Environment variables

| Variable | Effect |
|---|---|
| `STATIC_MASTER_KEY_HEX` | 64 hex chars (32 bytes) for static KMS. **Testing only.** |
| `SERVICE_NAME` / `PRODUCT_ID` / `Metastore` / `KMS` | Read by `SessionFactory()` (no-config constructor). |

### AWS KMS example

```python
asherah.setup({
    "ServiceName": "payments-api",
    "ProductID": "acme-corp",
    "Metastore": "rdbms",
    "ConnectionString": "mysql://user:pass@host:3306/asherah",
    "SQLMetastoreDBType": "mysql",
    "KMS": "aws",
    "RegionMap": {"us-west-2": "arn:aws:kms:us-west-2:000:key/abc"},
    "PreferredRegion": "us-west-2",
    "EnableSessionCaching": True,
    "SessionCacheMaxSize": 1000,
})
```

## Performance

Native Rust implementation. Typical latencies on Apple M4 Max (in-memory
metastore, session caching enabled, 64-byte payload):

| Operation | Sync | Async (session-level, true async) |
|-----------|------|------------------------------------|
| Encrypt   | ~1 µs | ~37 µs |
| Decrypt   | ~1.2 µs | ~37 µs |

Async overhead is from the asyncio event loop dispatch + GIL handoff.
Use sync for CPU-bound batches; use async when you need non-blocking
behavior in an asyncio application.

## API Reference

> Full docstrings live in `asherah/_asherah.pyi` and `asherah/__init__.py`
> and surface in your IDE on hover. The tables below summarize each API;
> the type stubs are the source of truth.

### Static / module-level API (legacy compatibility)

#### Lifecycle

| Function | Description |
|---|---|
| `setup(config: dict)` | Initialize the global instance. Raises if already configured. |
| `setup_async(config: dict)` | Async wrapper. Returns a coroutine. |
| `shutdown()` | Tear down the global instance. Idempotent. |
| `shutdown_async()` | Async wrapper. |
| `get_setup_status() -> bool` | True iff `setup()` has been called and `shutdown()` has not. |
| `setenv(env: dict)` | Apply env vars before `setup()`. Values may be `None` to delete. |
| `version() -> str` | Package version string. |

#### Encrypt / decrypt

| Function | Param 1 | Param 2 | Returns |
|---|---|---|---|
| `encrypt_bytes(partition_id, data)` | `str` (non-empty) | `bytes` (empty OK) | `str` (DRR JSON) |
| `encrypt_string(partition_id, text)` | `str` | `str` (empty OK) | `str` (DRR JSON) |
| `decrypt_bytes(partition_id, drr)` | `str` | `str` | `bytes` |
| `decrypt_string(partition_id, drr)` | `str` | `str` | `str` |
| `encrypt_bytes_async(partition_id, data)` | `str` | `bytes` | `Awaitable[str]` |
| `decrypt_bytes_async(partition_id, drr)` | `str` | `str` or `bytes` | `Awaitable[bytes]` |
| `encrypt_string_async(partition_id, text)` | `str` | `str` | `Awaitable[str]` |
| `decrypt_string_async(partition_id, drr)` | `str` | `str` | `Awaitable[str]` |

#### Hooks

| Function | Description |
|---|---|
| `set_log_hook(callback)` | Register a `(event_dict) -> None` log callback. Pass `None` to deregister. |
| `set_metrics_hook(callback)` | Register a `(event_dict) -> None` metrics callback. Pass `None` to deregister. |

### Factory / Session API (recommended)

#### `class SessionFactory`

| Member | Description |
|---|---|
| `SessionFactory()` | Construct from environment variables. |
| `SessionFactory.from_env()` | Same as `SessionFactory()` — provided for SDK parity. |
| `factory.get_session(partition_id)` | Get a per-partition `Session`. Raises on null/empty partition. |
| `factory.close()` | Release native resources. |
| `with SessionFactory() as factory:` | Context manager — `close()` runs on exit. |

#### `class Session`

| Member | Description |
|---|---|
| `session.encrypt_bytes(data)` | `bytes` → DRR JSON `str`. Empty `bytes` is valid. |
| `session.encrypt_text(text)` | `str` → DRR JSON `str`. Empty string is valid. |
| `session.decrypt_bytes(drr)` | DRR JSON `str` → `bytes`. |
| `session.decrypt_text(drr)` | DRR JSON `str` → `str`. |
| `session.encrypt_bytes_async(data)` | `Awaitable[str]` — true async on tokio. |
| `session.decrypt_bytes_async(drr)` | `Awaitable[bytes]` — true async on tokio. |
| `session.close()` | Release native resources. |
| `with session as ...:` | Context manager — `close()` runs on exit. |

### Event dict shapes

```python
LogEvent = {
    "level": "trace" | "debug" | "info" | "warn" | "error",
    "message": str,
    "target": str,
}

# Metrics event for timing measurements:
TimingEvent = {
    "type": "encrypt" | "decrypt" | "store" | "load",
    "duration_ns": int,
}

# Metrics event for cache lifecycle:
CacheEvent = {
    "type": "cache_hit" | "cache_miss" | "cache_stale",
    "name": str,  # cache name, e.g. "session", "intermediate-key"
}
```

## Cross-language compatibility

Wire-format compatible with all other Asherah implementations:

- canonical `godaddy/asherah` (Go core via cobhan)
- canonical `godaddy/asherah-csharp`
- canonical `godaddy/asherah-java`
- this repo's other bindings: Node, .NET, Java, Ruby, Go

A `DataRowRecord` written by any of these can be decrypted by any other,
provided they share the same metastore and KMS configuration.

## License

Licensed under the Apache License, Version 2.0.
