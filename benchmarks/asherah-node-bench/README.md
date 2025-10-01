# asherah-node Runtime Benchmarks

This project measures the `asherah-node` binding under two JavaScript runtimes—Node.js and Bun—using identical workloads. The harness exercises both binary and string APIs while targeting the in-memory metastore and static KMS configuration used in tests.

## Install

```
cd benchmarks/asherah-node-bench
npm install
```

The dependency on `asherah-node` points to the local repository via `file:` so `npm install` will build the native addon first.

## Run

```
# Node.js
npm run bench:node

# Bun (requires bun on PATH)
npm run bench:bun
```

Configuration knobs:

- `BENCH_ITERS` – iterations per benchmark (default `20000`)
- `BENCH_PAYLOAD` – payload size in bytes (default `4096`)
- `BENCH_SERVICE`, `BENCH_PRODUCT` – optional identifiers for the setup
- `STATIC_MASTER_KEY_HEX` – overrides the static KMS key (defaults to a test key)

Example output:

```
# asherah-node benchmark
runtime     : node v22.5.0
iterations  : 20000
payload size: 4096 bytes

encrypt(bytes)        6.58 µs |   303885 ops/s
decrypt(bytes)        2.86 µs |   699300 ops/s
encrypt(string)       8.12 µs |   246190 ops/s
decrypt(string)       3.11 µs |   642000 ops/s
```

Run the same command with Bun to compare throughput across runtimes.
