# Repository Guidelines

## Project Overview

Asherah is an envelope encryption library with automatic key rotation. This
repository contains the Rust implementation plus language bindings for Node.js,
Python, Java, .NET, Ruby, and Go.

## Directory Structure

- `asherah/` — Core Rust crate: encryption engine, key management, metastore adapters, memguard
- `asherah-config/` — Configuration types shared across crates
- `asherah-ffi/` — C ABI (cobhan buffer format) for language bindings
- `asherah-cobhan/` — Cobhan compatibility layer (drop-in for Go cobhan library)
- `asherah-server/` — gRPC sidecar server
- `asherah-node/` — Node.js bindings (napi-rs)
- `asherah-py/` — Python bindings (PyO3/maturin)
- `asherah-java/` — Java bindings (JNI)
- `asherah-dotnet/` — .NET bindings (P/Invoke)
- `asherah-ruby/` — Ruby bindings (FFI gem)
- `asherah-go/` — Go bindings (purego, no cgo)
- `benchmarks/` — Cross-language benchmarks
- `samples/` — Usage examples for each language
- `e2e/` — End-to-end tests against published packages
- `interop/` — Cross-language interoperability tests
- `scripts/` — CI and development scripts
- `docker/` — Dockerfiles for CI test environments
- `fuzz/` — Cargo-fuzz targets

## Build & Test

```bash
# Build workspace
cargo build

# Run all tests (unit, integration, bindings, lint)
scripts/test.sh --all

# Individual test modes
scripts/test.sh --unit
scripts/test.sh --integration    # requires Docker (MySQL, Postgres, DynamoDB)
scripts/test.sh --bindings       # requires language toolchains
scripts/test.sh --interop
scripts/test.sh --lint
scripts/test.sh --sanitizers     # Miri, AddressSanitizer, Valgrind
scripts/test.sh --fuzz           # requires nightly
```

### Feature-gated adapters

```bash
cargo test -p asherah --features sqlite
cargo test -p asherah --features mysql      # requires MYSQL_URL
cargo test -p asherah --features postgres   # requires POSTGRES_URL
cargo test -p asherah --features dynamodb   # requires AWS creds + DDB_TABLE
```

### Examples

```bash
cargo run -p asherah --example simple
cargo run -p asherah --features sqlite --example sqlite
KMS_KEY_ID=... AWS_REGION=... cargo run -p asherah --example aws_kms
```

## Coding Conventions

- Rust edition 2021; minimum supported version 1.88.0 (toolchain pinned to 1.91.1)
- Keep changes minimal and focused
- Use existing types and JSON field names in `types.rs` for cross-language compatibility
- Never log sensitive material; locked buffers scrub on free
- Async AWS SDK calls are behind an internal `tokio::runtime::Runtime` to present a sync API

## Testing Guidelines

- `memcall` / `memguard` modules: validate allocate/lock/protect/unlock/free cycles, buffer guards, canaries, enclave open/close
- Core: JSON shape tests, session roundtrips, region suffix precedence, cache behavior, metastore contract tests
- DB/AWS integration tests are opt-in via feature flags and environment variables; tests skip when config is absent
- All CI dry-run jobs must match publish workflow configuration exactly

## Security Notes

- All secret buffers use embedded memguard to lock/protect/wipe
- memguard attempts to disable core dumps on init
- Static master keys are for testing only — production must use AWS KMS

## PR Guidelines

- Concise, imperative commit messages
- Describe scope, rationale, and any behavioral changes
- Run `scripts/test.sh --lint` and `scripts/test.sh --unit` before pushing
- CI must pass before merge — no exceptions
