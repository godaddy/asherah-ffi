# Testing your application code

Strategies for unit and integration tests of code that uses Asherah.
None of these require AWS or a database — Asherah ships with an
in-memory metastore and a static master-key mode for tests.

## In-memory + static-KMS pytest fixture

```python
# tests/conftest.py
import os
import pytest
import asherah

@pytest.fixture(scope="session")
def asherah_factory():
    """Session-scoped factory: built once per test session."""
    os.environ["STATIC_MASTER_KEY_HEX"] = "22" * 32
    factory = asherah.SessionFactory.from_config({
        "ServiceName": "test-svc",
        "ProductID": "test-prod",
        "Metastore": "memory",     # no DB, no AWS
        "KMS": "static",
    })
    yield factory
    factory.close()

@pytest.fixture
def asherah_session(asherah_factory):
    """Per-test session for a fixed test partition."""
    session = asherah_factory.get_session("test-partition")
    yield session
    session.close()
```

Use directly in tests:

```python
def test_round_trip(asherah_session):
    ct = asherah_session.encrypt_text("4242 4242 4242 4242")
    assert asherah_session.decrypt_text(ct) == "4242 4242 4242 4242"
```

For per-tenant testing, parameterize:

```python
@pytest.mark.parametrize("tenant_id", ["tenant-a", "tenant-b", "tenant-c"])
def test_isolation(asherah_factory, tenant_id):
    with asherah_factory.get_session(tenant_id) as s:
        ct = s.encrypt_text("payload")
        assert s.decrypt_text(ct) == "payload"
```

## Hook tests run serially

Hooks are process-global. Tests that exercise them must run serially —
parallel test runners (pytest-xdist) race on hook state.

```python
@pytest.mark.serial
def test_log_hook_fires(asherah_factory):
    events = []
    asherah.set_log_hook(events.append)
    try:
        with asherah_factory.get_session("p") as s:
            s.encrypt_text("hello")
        assert any(e["target"].startswith("asherah") for e in events)
    finally:
        asherah.set_log_hook(None)
```

Mark with `pytest.mark.serial` and run with `pytest -p no:xdist
-m serial` for the hook subset, or use `--dist no` to disable
parallelism for the whole suite.

## Mocking your wrapper, not Asherah

The cleanest pattern: build a thin wrapper around `SessionFactory` in
your application code, and mock the wrapper in unit tests. Don't try
to mock the native binding directly — `asherah.SessionFactory` is a
PyO3 extension type that doesn't compose cleanly with `unittest.mock`.

```python
# myapp/protector.py
import asherah

class Protector:
    def __init__(self, factory: asherah.SessionFactory):
        self.factory = factory

    def protect(self, partition_id: str, plaintext: str) -> str:
        with self.factory.get_session(partition_id) as session:
            return session.encrypt_text(plaintext)
```

```python
# tests/test_order_service.py
from unittest.mock import MagicMock
from myapp.order_service import OrderService

def test_create_calls_protect():
    protector = MagicMock()
    protector.protect.return_value = "ct-token"
    orders = OrderService(protector=protector)

    orders.create(partition_id="merchant-7", payload="card data")

    protector.protect.assert_called_once_with("merchant-7", "card data")
```

The integration test of `Protector` itself (in `test_protector.py`)
uses the real `asherah_factory` fixture; unit tests of consumers mock
`Protector` directly.

## Asserting envelope shape

```python
import json

def test_envelope_shape(asherah_session):
    json_str = asherah_session.encrypt_text("hello")
    env = json.loads(json_str)
    assert "Key" in env
    assert "Data" in env
    assert "ParentKeyMeta" in env["Key"]
    assert "Created" in env["Key"]
```

## Async test patterns

Use `pytest-asyncio`:

```python
import pytest

@pytest.mark.asyncio
async def test_async_round_trip(asherah_factory):
    with asherah_factory.get_session("p") as session:
        ct = await session.encrypt_text_async("hello")
        assert await session.decrypt_text_async(ct) == "hello"
```

For testing the module-level async API:

```python
@pytest.fixture
async def setup_module_api():
    await asherah.setup_async({"ServiceName": "test", "ProductID": "test",
                                "Metastore": "memory", "KMS": "static"})
    yield
    await asherah.shutdown_async()

@pytest.mark.asyncio
async def test_module_api_async(setup_module_api):
    ct = await asherah.encrypt_string_async("p", "hello")
    assert await asherah.decrypt_string_async("p", ct) == "hello"
```

## Testing with the SQL metastore (Testcontainers)

```python
import pytest
import asherah
from testcontainers.mysql import MySqlContainer

@pytest.fixture(scope="session")
def mysql_factory():
    with MySqlContainer("mysql:8.0") as mysql:
        os.environ["STATIC_MASTER_KEY_HEX"] = "22" * 32
        factory = asherah.SessionFactory.from_config({
            "ServiceName": "test-svc",
            "ProductID": "test-prod",
            "Metastore": "rdbms",
            "ConnectionString": mysql.get_connection_url(),
            "SQLMetastoreDBType": "mysql",
            "KMS": "static",
        })
        yield factory
        factory.close()
```

Asherah's RDBMS metastore creates the schema automatically on first
use; no Alembic / SQL migration step required.

## Determinism caveats

- **AES-GCM nonces are random per encrypt call.** The ciphertext is
  non-deterministic — `encrypt_text("x")` produces a different
  envelope on every call. Don't compare ciphertext bytes; round-trip
  through `decrypt_text` and compare plaintexts.
- **Session caching.** `factory.get_session("p")` returns a cached
  session by default. Tests asserting per-call behaviour (e.g. a
  metastore call count) should set `EnableSessionCaching: False`.
- **Hooks are process-global.** Use `pytest.mark.serial` and
  `pytest -p no:xdist` for hook tests.

## Native binary resolution in tests

The Python wheel ships with platform-specific native binaries. If
tests fail with `ImportError: ... no module named asherah._native`:

- Confirm your interpreter matches what `pip install` resolved against:
  `python -c "import platform; print(platform.machine(), platform.python_implementation())"`.
- For Alpine/musl: ensure your test environment has a musllinux-tagged
  wheel (the wheel filename should contain `musllinux`, not
  `manylinux`).
- For repo development: `pip install -e .` from `asherah-py/` builds
  against your local `cargo build` output.
