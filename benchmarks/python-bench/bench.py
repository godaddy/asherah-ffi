#!/usr/bin/env python3
"""Asherah Python FFI benchmark with statistical analysis."""

import os
import statistics
import timeit

import asherah_py as asherah

PARTITION = "bench-partition"
SIZES = [64, 1024, 8192]
ROUNDS = 10
ITERS_PER_ROUND = 5000


def main():
    os.environ.setdefault(
        "STATIC_MASTER_KEY_HEX",
        "22" * 32,
    )

    config = {
        "ServiceName": "bench-svc",
        "ProductID": "bench-prod",
        "Metastore": "memory",
        "KMS": "static",
        "EnableSessionCaching": True,
    }
    asherah.setup(config)

    print("=== Python FFI Benchmark (timeit, {} rounds x {} iters) ===\n".format(ROUNDS, ITERS_PER_ROUND))
    print(f"  {'Size':>6}  {'Encrypt':>12}  {'± sd':>8}  {'Decrypt':>12}  {'± sd':>8}")
    print(f"  {'------':>6}  {'------------':>12}  {'--------':>8}  {'------------':>12}  {'--------':>8}")

    for size in SIZES:
        payload = os.urandom(size)
        ct = asherah.encrypt_bytes(PARTITION, payload)

        # Verify round-trip correctness
        recovered = asherah.decrypt_bytes(PARTITION, ct)
        assert recovered == payload, f"Round-trip verification failed for {size}B"

        # Warmup
        for _ in range(1000):
            asherah.encrypt_bytes(PARTITION, payload)
            asherah.decrypt_bytes(PARTITION, ct)

        enc_times = timeit.repeat(
            lambda: asherah.encrypt_bytes(PARTITION, payload),
            number=ITERS_PER_ROUND,
            repeat=ROUNDS,
        )
        enc_ns = [t / ITERS_PER_ROUND * 1e9 for t in enc_times]

        dec_times = timeit.repeat(
            lambda: asherah.decrypt_bytes(PARTITION, ct),
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
