# Getting started

Step-by-step walkthrough from `pip install` to a round-trip
encrypt/decrypt. After this guide, see:

- [`framework-integration.md`](./framework-integration.md) — FastAPI,
  Flask, Django, AWS Lambda, Celery worker integration.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  AWS KMS + DynamoDB.
- [`testing.md`](./testing.md) — pytest fixtures, in-memory metastore,
  mocking, integration tests against MySQL/Postgres.
- [`troubleshooting.md`](./troubleshooting.md) — common errors and
  fixes.

## 1. Install

```bash
pip install asherah
```

Python ≥ 3.8. Prebuilt wheels for Linux (x86_64/aarch64, glibc and
musl), macOS (x86_64/arm64), and Windows (x86_64/arm64) — the right
wheel is selected automatically.

## 2. Pick an API style

Two coexisting API surfaces — same wire format, same native core:

| Style | Entry points | Use when |
|---|---|---|
| Module-level | `asherah.setup()`, `asherah.encrypt_string()`, … | Configure once, encrypt/decrypt with a partition id. Drop-in compatible with the canonical `godaddy/asherah-python` API. |
| Factory / Session | `asherah.SessionFactory`, `factory.get_session(id)`, `session.encrypt_text(...)` | Explicit lifecycle, multi-tenant isolation in code, context-manager friendly (`with` blocks). |

The module-level API is a thin convenience wrapper over the
factory/session API. Pick by which one reads better at the call site.

## 3. Configure

Both styles use the same config dict (keys are PascalCase to match the
canonical Python SDK):

```python
import os
import asherah

# Testing-only static master key. Production must use AWS KMS;
# see aws-production-setup.md.
os.environ["STATIC_MASTER_KEY_HEX"] = "22" * 32

config = {
    "ServiceName": "my-service",
    "ProductID": "my-product",
    "Metastore": "memory",       # testing only — use "rdbms" or "dynamodb" in production
    "KMS": "static",             # testing only — use "aws" in production
    "EnableSessionCaching": True,
}
```

`ServiceName` and `ProductID` form the prefix for generated
intermediate-key IDs. Pick stable values — changing them later
orphans existing envelope keys.

For the complete option table, see the **Configuration** section of
the [main README](../README.md#configuration).

## 4. Encrypt and decrypt — module-level API

```python
asherah.setup(config)
try:
    ciphertext = asherah.encrypt_string("user-42", "secret")
    # Persist `ciphertext` (a JSON string) to your storage layer.

    # Later, after reading it back:
    plaintext = asherah.decrypt_string("user-42", ciphertext)
    print(plaintext)   # "secret"
finally:
    asherah.shutdown()
```

For binary payloads use `asherah.encrypt_bytes(partition_id, data)` /
`asherah.decrypt_bytes(partition_id, data)` — `data` and the return
are `bytes`.

## 5. Encrypt and decrypt — factory / session API

```python
import os, asherah

os.environ.update(
    SERVICE_NAME="my-service",
    PRODUCT_ID="my-product",
    METASTORE="memory",
    KMS="static",
)

with asherah.SessionFactory() as factory:
    with factory.get_session("user-42") as session:
        ciphertext = session.encrypt_text("secret")
        plaintext = session.decrypt_text(ciphertext)
        # session/factory closed automatically on context exit
```

Both `SessionFactory` and the session support the context-manager
protocol (`__enter__`/`__exit__`). Use `with` blocks for guaranteed
cleanup.

`SessionFactory()` (no arguments) reads config from environment
variables. To pass an explicit config dict, use the factory module:

```python
factory = asherah.SessionFactory.from_config(config)
```

## 6. Async API (asyncio)

```python
import asyncio, asherah

async def main():
    await asherah.setup_async(config)
    try:
        ciphertext = await asherah.encrypt_string_async("user-42", "secret")
        plaintext = await asherah.decrypt_string_async("user-42", ciphertext)
    finally:
        await asherah.shutdown_async()

asyncio.run(main())
```

The async methods run on the Rust tokio runtime — the asyncio event
loop is not blocked while metastore or KMS I/O is in flight.

> **Sync vs async:** prefer sync for Asherah's hot encrypt/decrypt
> paths. The native operation is sub-microsecond — async coroutine
> overhead is larger than the work itself for in-memory and warm
> cache scenarios. Use `*_async` in FastAPI handlers, async
> Django views, and asyncio-based workers where you're already on
> the event loop and the metastore I/O actually warrants yielding.

## 7. Wire up observability

```python
import asherah

def on_log(event):
    # event = {"level": "trace"|"debug"|"info"|"warn"|"error",
    #          "target": "asherah::session", "message": "..."}
    if event["level"] in ("warn", "error"):
        my_logger.log(event["level"], event["message"], extra={"asherah_target": event["target"]})

asherah.set_log_hook(on_log)

def on_metric(event):
    # event = {"type": "encrypt"|"decrypt"|"store"|"load"|"cache_hit"|...,
    #          "duration_ns": int, "name": str | None}
    if event["type"] in ("encrypt", "decrypt"):
        my_histogram.observe(event["type"], event["duration_ns"] / 1e6)

asherah.set_metrics_hook(on_metric)
```

Hooks are process-global. `set_log_hook(None)` / `set_metrics_hook(None)`
deregister.

`set_log_hook_sync` and `set_metrics_hook_sync` variants fire on the
encrypt/decrypt thread before the operation returns — pick those if
you need contextvars / OpenTelemetry trace context intact in the
callback or have verifiably non-blocking handlers.

## 8. Move to production

The example uses `Metastore: "memory"` and `KMS: "static"` — both
**testing only**. Memory metastore loses keys on process restart;
static KMS uses a hardcoded master key. For real deployments, follow
[`aws-production-setup.md`](./aws-production-setup.md).

## 9. Handle errors

Asherah surfaces errors via raised exceptions. The native side raises
generic `Exception` subclasses with descriptive messages; specific
shapes and what to check first are in
[`troubleshooting.md`](./troubleshooting.md).

Common shapes:
- `TypeError` — `None` where a value was required (programming error).
- `ValueError: partition id cannot be empty` — empty partition string.
- `Exception: decrypt_from_json: ...` — malformed envelope on decrypt.
- `Exception: factory_from_config: ...` — invalid config or
  KMS/metastore unreachable.

## What's next

- [`framework-integration.md`](./framework-integration.md) — FastAPI,
  Flask, Django, AWS Lambda, Celery.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  AWS config from KMS key creation through IAM policy.
- The complete [sample app](../../samples/python/sample.py) exercises
  every API style + async + log hook + metrics hook.
