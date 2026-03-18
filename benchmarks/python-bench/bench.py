#!/usr/bin/env python3
"""Asherah Python FFI benchmark with statistical analysis."""

import os
import statistics
import timeit

import asherah

SIZES = [64, 1024, 8192]
ROUNDS = 10
ITERS_PER_ROUND = 5000


def main():
    os.environ.setdefault(
        "STATIC_MASTER_KEY_HEX",
        "746869734973415374617469634d61737465724b6579466f7254657374696e67",
    )

    cold = os.environ.get("BENCH_COLD") == "1"

    config = {
        "ServiceName": "bench-svc",
        "ProductID": "bench-prod",
        "Metastore": os.environ.get("BENCH_METASTORE", "memory"),
        "KMS": "static",
        "EnableSessionCaching": True,
    }
    conn = os.environ.get("BENCH_CONNECTION_STRING")
    if conn:
        config["ConnectionString"] = conn
    check = os.environ.get("BENCH_CHECK_INTERVAL")
    if check:
        config["CheckInterval"] = int(check)
    if cold:
        config["IntermediateKeyCacheMaxSize"] = 1
    asherah.setup(config)

    iters = 500 if cold else ITERS_PER_ROUND
    rounds = ROUNDS

    print("=== Python FFI Benchmark (timeit, {} rounds x {} iters{}) ===\n".format(
        rounds, iters, ", cold" if cold else ""))
    print(f"  {'Size':>6}  {'Encrypt':>12}  {'± sd':>8}  {'Decrypt':>12}  {'± sd':>8}")
    print(f"  {'------':>6}  {'------------':>12}  {'--------':>8}  {'------------':>12}  {'--------':>8}")

    for size in SIZES:
        payload = os.urandom(size)

        if cold:
            # Pre-encrypt on 2 partitions, alternate to force IK cache miss
            ct0 = asherah.encrypt_bytes("cold-0", payload)
            ct1 = asherah.encrypt_bytes("cold-1", payload)
            asherah.decrypt_bytes("cold-0", ct0)  # warm SK cache

            enc_ctr = [0]
            dec_ctr = [0]

            def cold_encrypt():
                enc_ctr[0] += 1
                asherah.encrypt_bytes(f"cold-enc-{enc_ctr[0]}", payload)

            def cold_decrypt():
                i = dec_ctr[0] % 2
                dec_ctr[0] += 1
                asherah.decrypt_bytes(f"cold-{i}", ct0 if i == 0 else ct1)

            enc_times = timeit.repeat(cold_encrypt, number=iters, repeat=rounds)
            dec_times = timeit.repeat(cold_decrypt, number=iters, repeat=rounds)
        else:
            partition = "bench-partition"
            ct = asherah.encrypt_bytes(partition, payload)
            recovered = asherah.decrypt_bytes(partition, ct)
            assert recovered == payload, f"Round-trip verification failed for {size}B"

            for _ in range(1000):
                asherah.encrypt_bytes(partition, payload)
                asherah.decrypt_bytes(partition, ct)

            enc_times = timeit.repeat(
                lambda: asherah.encrypt_bytes(partition, payload),
                number=iters, repeat=rounds,
            )
            dec_times = timeit.repeat(
                lambda: asherah.decrypt_bytes(partition, ct),
                number=iters, repeat=rounds,
            )

        enc_ns = [t / iters * 1e9 for t in enc_times]
        dec_ns = [t / iters * 1e9 for t in dec_times]

        print(
            f"  {size:5}B  {statistics.mean(enc_ns):9.0f} ns  {statistics.stdev(enc_ns):5.0f} ns"
            f"  {statistics.mean(dec_ns):9.0f} ns  {statistics.stdev(dec_ns):5.0f} ns"
        )

    asherah.shutdown()


if __name__ == "__main__":
    main()
