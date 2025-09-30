# Repository Guidelines

This repository contains:
- Go wrapper over the Rust FFI (`asherah-go/`)
- Rust ports:
  - `asherah`: primary Rust crate with Go-compatible JSON shapes, API, and KMS/metastore integrations
  - `asherah-ffi`: C ABI wrapper over `asherah` for language bindings
  - Language bindings under `asherah-node/`, `asherah-py/`, `asherah-java/`, `asherah-dotnet/`, and `asherah-ruby/`

## Project Structure & Module Organization
- Go memcall reference implementation now lives under `memcall-go/`.
- Go bindings targeting the Rust FFI live under `asherah-go/`.
- Rust crates:
  - `asherah/` (primary Rust crate)
  - `asherah-ffi/` (C ABI wrapper over `asherah`)
  - `asherah/` (workspace member)
    - Feature‑gated adapters: `sqlite`, `mysql`, `postgres`, `dynamodb`
    - Examples in `examples/`
    - Tests in `tests/`

## Build & Test
- Build all Rust crates:
- Build workspace: `cargo build`
- `cd asherah && cargo build`
- Run tests:
- Test workspace: `cargo test`
- `cd asherah && cargo test`
- Adapter features:
  - SQLite: `cargo test --features sqlite`
  - MySQL: `cargo test --features mysql` (requires `MYSQL_URL` env for integration tests)
  - Postgres: `cargo test --features postgres` (requires `POSTGRES_URL` env)
  - DynamoDB: `cargo test --features dynamodb` (requires AWS creds and `DDB_TABLE`, optionally `AWS_REGION`)

## Examples
- In‑memory + StaticKMS: `cd asherah && cargo run --example simple`
- SQLite metastore: `cargo run --features sqlite --example sqlite`
- AWS KMS: `KMS_KEY_ID=... AWS_REGION=... cargo run --example aws_kms`

## Coding Style & Conventions (Rust)
- Edition 2021; keep changes minimal and focused.
- Use existing types and JSON field names in `types.rs` for cross‑language compatibility.
- Avoid logging sensitive material; locked buffers scrub on free.
- Keep async AWS SDK calls behind an internal `tokio::runtime::Runtime` to present a sync KMS/Metastore API, mirroring Go.

## Testing Guidelines
- memcall‑rs: validate allocate/lock/protect/unlock/free cycles and flags.
- memguard‑rs: buffer guards (canary), freeze/melt/destroy, enclave open/close, streaming.
- appencryption: JSON shape tests, session roundtrips, region suffix precedence, cache behavior, and metastore contract tests.
- DB/AWS integration tests are opt‑in via feature flags and environment variables; tests will skip when config is absent.

## Security & Configuration Tips
- Treat all secret buffers as sensitive; rely on embedded `memguard` to lock/protect/wipe.
- Consider disabling core dumps at process start; embedded `memguard` attempts to do so on init.

## PR Guidelines
- Concise, imperative commit messages.
- Describe scope, rationale, and any behavioral changes.
- Ensure `cargo test` (with relevant features) passes.
