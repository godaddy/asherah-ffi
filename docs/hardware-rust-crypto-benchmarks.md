# Hardware Rust Crypto Benchmark Notes

Date: 2026-06-11
Platform: Darwin arm64, Apple M4 Max

This PR wires Asherah's default crypto backend to the published
`hardware-rust-crypto` crate:

```text
hardware-rust-crypto = "0.1.0"
```

This pass uses the allocation-free `HardwareAes256GcmKeyState` prepared-key
API.

The earlier slow benchmark table for this PR was discarded because it was
produced while Asherah was pinned to an older pre-stitched
`hardware-rust-crypto` branch, not the implementation published as
`hardware-rust-crypto` 0.1.0. The intermediate `f6c1e2a5` pass was superseded
by the crates.io release.

## Benchmark Commands

For fast crypto-iteration feedback, use only the focused backend benchmark:

```bash
cargo bench -p asherah-bench --bench crypto_backend -- --sample-size 30 --warm-up-time 1 --measurement-time 3
cargo bench -p asherah-bench --bench crypto_backend --no-default-features --features crypto-ring -- --sample-size 30 --warm-up-time 1 --measurement-time 3
```

For fast iteration, use Criterion's minimum sample size:

```bash
cargo bench -p asherah-bench --bench crypto_backend -- --sample-size 10 --warm-up-time 0.5 --measurement-time 1
cargo bench -p asherah-bench --bench crypto_backend --no-default-features --features crypto-ring -- --sample-size 10 --warm-up-time 0.5 --measurement-time 1
```

The full native benchmark script is useful for merge validation, not tight
primitive iteration:

```bash
CRITERION_EXTRA='-- --sample-size 30 --warm-up-time 1 --measurement-time 3' scripts/benchmark.sh --rust-only --memory --crypto-hardware-rust
CRITERION_EXTRA='-- --sample-size 30 --warm-up-time 1 --measurement-time 3' scripts/benchmark.sh --rust-only --memory --crypto-ring
```

## Focused Crypto Backend

Median Criterion estimates from the fast iteration pass, lower is better.

| Benchmark | Hardware 0.1.0 | Ring | Delta |
| --- | ---: | ---: | ---: |
| prepare key 32B | 109.20 ns | 108.57 ns | 1.01x slower |
| prepared encrypt 32B | 52.20 ns | 72.41 ns | 1.39x faster |
| prepared encrypt 64B | 52.82 ns | 74.12 ns | 1.40x faster |
| prepared encrypt 1KB | 166.96 ns | 205.42 ns | 1.23x faster |
| prepared encrypt 8KB | 982.77 ns | 1.150 us | 1.17x faster |
| prepared decrypt 32B | 43.21 ns | 52.25 ns | 1.21x faster |
| prepared decrypt 64B | 49.05 ns | 52.21 ns | 1.06x faster |
| prepared decrypt 1KB | 170.40 ns | 187.93 ns | 1.10x faster |
| prepared decrypt 8KB | 981.88 ns | 1.141 us | 1.16x faster |
| trait encrypt 32B | 150.90 ns | 152.60 ns | 1.01x faster |
| trait encrypt 64B | 154.79 ns | 153.87 ns | 1.01x slower |
| trait encrypt 1KB | 274.64 ns | 287.74 ns | 1.05x faster |
| trait encrypt 8KB | 1.094 us | 1.246 us | 1.14x faster |
| fast random 12B | 23.84 ns | 31.09 ns | 1.30x faster |
| fast random 32B | 27.59 ns | 55.15 ns | 2.00x faster |
| fast random 64B | 46.53 ns | 90.54 ns | 1.95x faster |

## Current Status

The current `hardware-rust-crypto` crates.io release is no longer showing
the large regression seen on the older branch. In this fast pass it beats
`ring` on every prepared encrypt, prepared decrypt, and random-generation row.
Prepared key setup is effectively tied with `ring` after switching from the
heap-backed `HardwareAes256Gcm` value to inline `HardwareAes256GcmKeyState`.
