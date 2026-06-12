# Asherah Performance Benchmarks

## Crypto Backend Comparison

Run the focused crypto backend benchmark once with the default hardware backend
and once with the explicit ring backend:

```bash
cargo bench -p asherah-bench --bench crypto_backend
cargo bench -p asherah-bench --bench crypto_backend --no-default-features --features crypto-ring
```

The end-to-end native benchmark can be compared the same way:

```bash
cargo bench -p asherah-bench --bench native
cargo bench -p asherah-bench --bench native --no-default-features --features crypto-ring
```

The repository benchmark script also supports backend selection for the Rust
native path:

```bash
scripts/benchmark.sh --rust-only --memory --crypto-hardware-rust
scripts/benchmark.sh --rust-only --memory --crypto-ring
```

This standalone Cargo project compares the performance of the native Rust
Asherah implementation (`asherah-ffi`) against the original Go
implementation. Both libraries are invoked through their C ABIs from the same
benchmark harness to keep the measurements comparable.

## Prerequisites

- Rust toolchain (matching the workspace version)
- Go 1.23 or newer (the build script sets `GOTOOLCHAIN=auto`, so Go will fetch
  the required toolchain automatically when using Go 1.21+)

## Layout

- `../go-wrapper` – small cgo wrapper that exposes Go Asherah through a stable
  C ABI. The wrapper builds an in-memory metastore and static KMS, mirroring
  the configuration used by the Rust benchmarks.
- `../go-asherah` – local clone of the original Go repository used by the
  wrapper via `replace` directives.
- `build.rs` – orchestrates building the Rust FFI library (`asherah-ffi`) in
  release mode and the Go shared library before the benchmarks execute.
- `benches/ffi.rs` – Criterion benchmark that measures encryption and
  decryption throughput for both implementations using 4&nbsp;KiB payloads.

## Running the Benchmarks

From this directory:

```bash
cargo bench
```

The build script will:

1. Compile `asherah-ffi` in release mode (outputs to `target/release`).
2. Build the Go wrapper as a `c-shared` library.
3. Expose the generated artifact paths to the benchmark harness via
   environment variables.

Criterion writes HTML reports under `target/criterion` for further analysis.

## Notes

- The Go benchmark path is configured to exercise only the fast smoke tests
  (Node.js and Python equivalents are skipped) to keep runtime reasonable when
  running under QEMU or other emulation environments.
- Environment variables `SERVICE_NAME`, `PRODUCT_ID`, and
  `STATIC_MASTER_KEY_HEX` are set by the benchmark harness before invoking the
  C ABIs, so no manual configuration is required.
