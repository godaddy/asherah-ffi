#!/usr/bin/env python3
"""Asherah Python FFI async benchmark."""

import asyncio
import os
import statistics
import time
import argparse
from itertools import count

import asherah

PARTITION = "bench-async-partition"
SIZES = [64, 1024, 8192]
ROUNDS = 10
ITERS_PER_ROUND = 5000
PARTITION_POOL_SIZE = int(os.environ.get("BENCH_PARTITION_POOL", "2048"))
WARM_SESSION_CACHE_MAX_SIZE = 4096


def parse_args():
    parser = argparse.ArgumentParser(description="Asherah Python async benchmark")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--memory", action="store_true")
    group.add_argument("--hot", action="store_true")
    group.add_argument("--warm", action="store_true")
    group.add_argument("--cold", action="store_true")
    parser.add_argument("--mysql-url", default=None)
    return parser.parse_args()


def resolve_mode(args):
    mode = os.environ.get("BENCH_MODE", "memory").strip().lower()
    if args.memory:
        mode = "memory"
    if args.hot:
        mode = "hot"
    if args.warm:
        mode = "warm"
    if args.cold:
        mode = "cold"
    if mode not in {"memory", "hot", "warm", "cold"}:
        raise ValueError(f"invalid BENCH_MODE '{mode}'")
    if mode in {"hot", "warm", "cold"}:
        mysql_url = args.mysql_url or os.environ.get("BENCH_MYSQL_URL") or os.environ.get("MYSQL_URL")
        if not mysql_url:
            raise ValueError(f"--{mode} requires --mysql-url or BENCH_MYSQL_URL/MYSQL_URL")
        return mode, mysql_url
    return mode, None


async def bench_async(func, iters):
    """Time `iters` sequential async calls, return total seconds."""
    t0 = time.perf_counter()
    for _ in range(iters):
        await func()
    return time.perf_counter() - t0


async def main():
    args = parse_args()
    mode, mysql_url = resolve_mode(args)

    os.environ.setdefault("STATIC_MASTER_KEY_HEX", "22" * 32)

    config = {
        "ServiceName": "bench-async-svc",
        "ProductID": "bench-async-prod",
        "KMS": "static",
        "EnableSessionCaching": True,
    }
    if mode == "hot":
        config["Metastore"] = "rdbms"
        config["ConnectionString"] = mysql_url
    elif mode == "warm":
        config["Metastore"] = "rdbms"
        config["ConnectionString"] = mysql_url
        config["SessionCacheMaxSize"] = WARM_SESSION_CACHE_MAX_SIZE
    elif mode == "cold":
        config["Metastore"] = "rdbms"
        config["ConnectionString"] = mysql_url
        config["EnableSessionCaching"] = False
    else:
        config["Metastore"] = "memory"

    await asherah.setup_async(config)

    print(f"  {'Size':>6}  {'Encrypt':>12}  {'± sd':>8}  {'Decrypt':>12}  {'± sd':>8}")
    print(f"  {'------':>6}  {'------------':>12}  {'--------':>8}  {'------------':>12}  {'--------':>8}")

    for size in SIZES:
        payload = os.urandom(size)
        if mode in ("warm", "cold"):
            partitions = [f"bench-async-{mode}-{size}-{i}" for i in range(PARTITION_POOL_SIZE)]
            ciphertexts = [asherah.encrypt_bytes(p, payload) for p in partitions]
            recovered = asherah.decrypt_bytes(partitions[0], ciphertexts[0])
            assert recovered == payload

            enc_counter = count()
            dec_counter = count()

            async def enc_call():
                idx = next(enc_counter) % PARTITION_POOL_SIZE
                return await asherah.encrypt_bytes_async(partitions[idx], payload)

            async def dec_call():
                idx = next(dec_counter) % PARTITION_POOL_SIZE
                return await asherah.decrypt_bytes_async(partitions[idx], ciphertexts[idx])
        else:
            ct = asherah.encrypt_bytes(PARTITION, payload)
            recovered = asherah.decrypt_bytes(PARTITION, ct)
            assert recovered == payload

            async def enc_call():
                return await asherah.encrypt_bytes_async(PARTITION, payload)

            async def dec_call():
                return await asherah.decrypt_bytes_async(PARTITION, ct)

        # Warmup
        for _ in range(1000):
            await enc_call()
            await dec_call()

        enc_ns_list = []
        for _ in range(ROUNDS):
            t = await bench_async(enc_call, ITERS_PER_ROUND)
            enc_ns_list.append(t / ITERS_PER_ROUND * 1e9)

        dec_ns_list = []
        for _ in range(ROUNDS):
            t = await bench_async(dec_call, ITERS_PER_ROUND)
            dec_ns_list.append(t / ITERS_PER_ROUND * 1e9)

        print(
            f"  {size:5}B  {statistics.mean(enc_ns_list):9.0f} ns  {statistics.stdev(enc_ns_list):5.0f} ns"
            f"  {statistics.mean(dec_ns_list):9.0f} ns  {statistics.stdev(dec_ns_list):5.0f} ns"
        )

    await asherah.shutdown_async()


if __name__ == "__main__":
    asyncio.run(main())
