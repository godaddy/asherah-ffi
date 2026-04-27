"""Asherah for Python — application-layer envelope encryption with automatic
key rotation.

Two API styles, both fully supported and producing the same wire format:

1. **Static / module-level API** (legacy compatibility) — call :func:`setup`
   once at process start, then use :func:`encrypt_bytes` / :func:`decrypt_bytes`
   (or the string variants) with a partition ID. Mirrors the canonical
   ``godaddy/asherah-python`` API; easiest path for existing callers.

2. **Factory / Session API** (recommended for new code) — construct a
   :class:`SessionFactory`, get one or more :class:`Session` instances per
   partition, and call ``encrypt_bytes`` / ``decrypt_bytes`` on the session.
   Avoids the hidden-singleton lifecycle of the static API and makes
   per-partition isolation explicit.

Observability hooks are also exposed:

- :func:`set_log_hook` receives every log event from the Rust core.
- :func:`set_metrics_hook` receives encrypt/decrypt timings and key cache
  hit/miss/stale counters.

See ``samples/python/sample.py`` for a runnable example covering both API
styles plus async, log hook, and metrics hook usage.
"""
from asherah._asherah import (  # noqa: F401
    SessionFactory,
    Session,
    setup,
    shutdown,
    get_setup_status,
    encrypt_bytes,
    encrypt_string,
    decrypt_bytes,
    decrypt_string,
    encrypt_bytes_async,
    decrypt_bytes_async,
    setenv,
    set_metrics_hook,
    set_log_hook,
    version,
)

import asyncio as _asyncio

# encrypt_bytes_async and decrypt_bytes_async are native PyO3 coroutines
# that run on Rust's tokio runtime — no thread pool overhead.
# Session.encrypt_bytes_async and Session.decrypt_bytes_async are the same.

# setup/shutdown async wrappers still use run_in_executor because they are
# one-shot operations where thread pool overhead is irrelevant.


async def setup_async(config):
    """Async wrapper around :func:`setup`. Runs the synchronous setup on
    the default executor so it does not block the asyncio event loop."""
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, setup, config)


async def shutdown_async():
    """Async wrapper around :func:`shutdown`."""
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, shutdown)


async def encrypt_string_async(partition_id, text):
    """Async UTF-8 string encrypt at the module level. Wraps
    :func:`encrypt_bytes_async` with a UTF-8 encode."""
    result = await encrypt_bytes_async(partition_id, text.encode("utf-8"))
    return result


async def decrypt_string_async(partition_id, data_row_record):
    """Async UTF-8 string decrypt at the module level. Wraps
    :func:`decrypt_bytes_async` with a UTF-8 decode."""
    result = await decrypt_bytes_async(partition_id, data_row_record)
    return result.decode("utf-8") if isinstance(result, bytes) else result


__all__ = [
    # Classes (Factory/Session API — recommended)
    "SessionFactory",
    "Session",
    # Static / module-level API (legacy compatibility)
    "setup",
    "shutdown",
    "get_setup_status",
    "encrypt_bytes",
    "encrypt_string",
    "decrypt_bytes",
    "decrypt_string",
    "setenv",
    "version",
    # Observability hooks
    "set_metrics_hook",
    "set_log_hook",
    # Async (module-level)
    "setup_async",
    "shutdown_async",
    "encrypt_bytes_async",
    "encrypt_string_async",
    "decrypt_bytes_async",
    "decrypt_string_async",
]
