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
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, setup, config)


async def shutdown_async():
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, shutdown)


async def encrypt_string_async(partition_id, text):
    result = await encrypt_bytes_async(partition_id, text.encode("utf-8"))
    return result


async def decrypt_string_async(partition_id, data_row_record):
    result = await decrypt_bytes_async(partition_id, data_row_record)
    return result.decode("utf-8") if isinstance(result, bytes) else result


__all__ = [
    # Classes
    "SessionFactory",
    "Session",
    # Sync functions
    "setup",
    "shutdown",
    "get_setup_status",
    "encrypt_bytes",
    "encrypt_string",
    "decrypt_bytes",
    "decrypt_string",
    "setenv",
    "set_metrics_hook",
    "set_log_hook",
    "version",
    # Async functions
    "setup_async",
    "shutdown_async",
    "encrypt_bytes_async",
    "encrypt_string_async",
    "decrypt_bytes_async",
    "decrypt_string_async",
]
