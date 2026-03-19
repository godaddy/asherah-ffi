#!/usr/bin/env python3
"""Asherah Python FFI benchmark with statistical analysis."""

import os
import statistics
import timeit
import argparse
from itertools import count

import asherah

PARTITION = "bench-partition"
SIZES = [64, 1024, 8192]
ROUNDS = 10
ITERS_PER_ROUND = 5000
PARTITION_POOL_SIZE = int(os.environ.get("BENCH_PARTITION_POOL", "2048"))
WARM_SESSION_CACHE_MAX_SIZE = 4096
if PARTITION_POOL_SIZE < 1:
    raise ValueError("BENCH_PARTITION_POOL must be >= 1")


def parse_args():
    parser = argparse.ArgumentParser(description="Asherah Python benchmark")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--memory", action="store_true", help="in-memory metastore hot-cache mode")
    group.add_argument("--hot", action="store_true", help="MySQL hot-cache mode")
    group.add_argument("--warm", action="store_true", help="MySQL warm-cache mode (SK cached, IK miss path)")
    group.add_argument("--cold", action="store_true", help="MySQL cold-cache mode (SK-only cache)")
    parser.add_argument(
        "--mysql-url",
        default=None,
        help="MySQL DSN/URL for --hot/--warm/--cold (or use BENCH_MYSQL_URL/MYSQL_URL)",
    )
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
        raise ValueError(f"invalid BENCH_MODE '{mode}' (expected memory, hot, warm, or cold)")

    if mode in {"hot", "warm", "cold"}:
        mysql_url = args.mysql_url or os.environ.get("BENCH_MYSQL_URL") or os.environ.get("MYSQL_URL")
        if not mysql_url:
            raise ValueError(f"--{mode} requires --mysql-url or BENCH_MYSQL_URL/MYSQL_URL")
        return mode, mysql_url
    return mode, None


def main():
    args = parse_args()
    mode, mysql_url = resolve_mode(args)

    os.environ.setdefault(
        "STATIC_MASTER_KEY_HEX",
        "22" * 32,
    )

    config = {
        "ServiceName": "bench-svc",
        "ProductID": "bench-prod",
        "KMS": "static",
        "EnableSessionCaching": True,
    }
    if mode == "hot":
        config["Metastore"] = "rdbms"
        config["ConnectionString"] = mysql_url
        print("mode: hot (MySQL hot-cache)")
    elif mode == "warm":
        config["Metastore"] = "rdbms"
        config["ConnectionString"] = mysql_url
        config["SessionCacheMaxSize"] = WARM_SESSION_CACHE_MAX_SIZE
        print("mode: warm (MySQL, SK cached + IK miss)")
    elif mode == "cold":
        config["Metastore"] = "rdbms"
        config["ConnectionString"] = mysql_url
        config["EnableSessionCaching"] = False
        print("mode: cold (MySQL, SK-only cache)")
    else:
        config["Metastore"] = "memory"
        print("mode: memory (in-memory hot-cache)")
    asherah.setup(config)

    print("=== Python FFI Benchmark (timeit, {} rounds x {} iters) ===\n".format(ROUNDS, ITERS_PER_ROUND))
    print(f"  {'Size':>6}  {'Encrypt':>12}  {'± sd':>8}  {'Decrypt':>12}  {'± sd':>8}")
    print(f"  {'------':>6}  {'------------':>12}  {'--------':>8}  {'------------':>12}  {'--------':>8}")

    for size in SIZES:
        payload = os.urandom(size)
        if mode == "cold":
            partitions = [f"bench-{mode}-{size}-{i}" for i in range(PARTITION_POOL_SIZE)]
            ciphertexts = [asherah.encrypt_bytes(partition, payload) for partition in partitions]
            recovered = asherah.decrypt_bytes(partitions[0], ciphertexts[0])
            assert recovered == payload, f"Round-trip verification failed for {size}B"

            enc_counter = count()
            dec_counter = count()

            def enc_call():
                idx = next(enc_counter) % PARTITION_POOL_SIZE
                return asherah.encrypt_bytes(partitions[idx], payload)

            def dec_call():
                idx = next(dec_counter) % PARTITION_POOL_SIZE
                return asherah.decrypt_bytes(partitions[idx], ciphertexts[idx])
        else:
            ct = asherah.encrypt_bytes(PARTITION, payload)
            recovered = asherah.decrypt_bytes(PARTITION, ct)
            assert recovered == payload, f"Round-trip verification failed for {size}B"

            def enc_call():
                return asherah.encrypt_bytes(PARTITION, payload)

            def dec_call():
                return asherah.decrypt_bytes(PARTITION, ct)

        for _ in range(1000):
            enc_call()
            dec_call()

        enc_times = timeit.repeat(
            enc_call,
            number=ITERS_PER_ROUND,
            repeat=ROUNDS,
        )
        enc_ns = [t / ITERS_PER_ROUND * 1e9 for t in enc_times]

        dec_times = timeit.repeat(
            dec_call,
            number=ITERS_PER_ROUND,
            repeat=ROUNDS,
        )
        dec_ns = [t / ITERS_PER_ROUND * 1e9 for t in dec_times]

        print(
            f"  {size:5}B  {statistics.mean(enc_ns):9.0f} ns  {statistics.stdev(enc_ns):5.0f} ns"
            f"  {statistics.mean(dec_ns):9.0f} ns  {statistics.stdev(dec_ns):5.0f} ns"
        )

    asherah.shutdown()


if __name__ == "__main__":
    main()
