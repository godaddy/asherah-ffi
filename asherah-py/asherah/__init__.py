from asherah._asherah import *  # noqa: F401,F403
from asherah._asherah import SessionFactory, Session  # noqa: F401
from asherah._asherah import (  # noqa: F401
    setup,
    shutdown,
    encrypt_bytes,
    encrypt_string,
    decrypt_bytes,
    decrypt_string,
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
