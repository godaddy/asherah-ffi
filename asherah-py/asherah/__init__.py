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
    setenv,
    set_metrics_hook,
    set_log_hook,
    version,
)

import asyncio as _asyncio
import functools as _functools


async def setup_async(config):
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, setup, config)


async def shutdown_async():
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(None, shutdown)


async def encrypt_bytes_async(partition_id, data):
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _functools.partial(encrypt_bytes, partition_id, data)
    )


async def encrypt_string_async(partition_id, text):
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _functools.partial(encrypt_string, partition_id, text)
    )


async def decrypt_bytes_async(partition_id, data_row_record):
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _functools.partial(decrypt_bytes, partition_id, data_row_record)
    )


async def decrypt_string_async(partition_id, data_row_record):
    loop = _asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, _functools.partial(decrypt_string, partition_id, data_row_record)
    )


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
