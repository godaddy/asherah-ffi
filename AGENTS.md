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

## CI/CD Architecture

### Release flow
1. Create a GitHub Release (tag like `v0.6.64`)
2. This triggers simultaneously: `release-cobhan.yml`, `publish-pypi.yml`, `publish-npm.yml`, `publish-server.yml`
3. `release-cobhan.yml` builds native FFI + JNI libraries for 6 platforms and uploads to the release
4. When release-cobhan completes, `workflow_run` triggers: `publish-rubygems.yml`, `publish-nuget.yml`, `publish-maven.yml`
5. These downstream workflows download pre-built binaries from the release and package them

### Publish dry-runs
CI runs 11 `publish-dry-run-*` jobs on every PR that replicate every unique compilation
path in the publish workflows. These MUST exactly match the publish workflows — if they
diverge, they won't catch failures. Specific rules:

- All PyPI dry-runs use `source scripts/maturin-before-script-linux.sh` — the same
  shared script as `publish-pypi.yml`. Never inline the logic.
- All npm musl dry-runs use `source "$GITHUB_WORKSPACE/scripts/download-musl-openssl.sh"` —
  same shared script as `publish-npm.yml`. Always use `$GITHUB_WORKSPACE` prefix since
  build steps may run with `working-directory: asherah-node`.
- The dry-run for a target must use the same `working-directory`, `env`, `docker-options`,
  and `before-script-linux` as the publish workflow. No shortcuts.

### Shared CI scripts (single source of truth)
- `scripts/maturin-before-script-linux.sh` — OpenSSL setup for maturin Docker builds
- `scripts/download-musl-openssl.sh` — Alpine OpenSSL packages for musl builds
- `scripts/install-sccache.sh` — sccache install for container jobs
- `scripts/set-pypi-version.sh` — version patching for PyPI builds

Changing any of these affects all publish workflows AND dry-runs simultaneously.
That's the point — they can't drift.

### Rust toolchain
- `rust-toolchain.toml` pins the workspace to 1.91.1 with Linux targets only
- `dtolnay/rust-toolchain` in CI MUST use the `@1.91.1` SHA (`32a995a99d743b9c19db6838def362cd715afeb6`),
  not `@stable`. Using `@stable` installs cross-compile targets for the wrong toolchain
  since `rust-toolchain.toml` overrides which toolchain cargo actually uses.
- arm64 container jobs use `rust:1.91-bookworm` image
- Fuzz and sanitizer jobs use `nightly` (independent of the pinned version)

## CI/CD Rules (hard-won, do not violate)

### OpenSSL configuration
- **Native manylinux (yum)**: install `openssl-devel`, export `OPENSSL_NO_VENDOR=1`
- **Native musllinux (apk)**: install `openssl-dev`, export `OPENSSL_NO_VENDOR=1`
- **Cross-compile glibc (apt-get, manylinux-cross)**: let openssl-sys vendor from source
- **Cross-compile musl (apt-get, rust-musl-cross)**: download Alpine OpenSSL packages via shared script
- **macOS**: let openssl-sys vendor (no `OPENSSL_NO_VENDOR` — it breaks x86_64 cross-compile)
- **Windows**: install via vcpkg, set `OPENSSL_DIR` + `OPENSSL_NO_VENDOR=1`
- **Windows arm64**: use `openssl:arm64-windows-static-md` triplet (NOT x64)
- NEVER set `OPENSSL_NO_VENDOR` globally via `env:` or `docker-options:` — it applies to
  platforms where system OpenSSL isn't available. Set it inside `before-script-linux` only.

### GitHub Actions workflow rules
- Every job MUST have `permissions:` block (top-level `contents: read` + per-job escalation)
- Publish workflow matrices MUST use `fail-fast: false`
- All publish workflows MUST have `concurrency:` groups to prevent races
- Pin tool versions everywhere: `maturin==1.9.4`, `sccache v0.8.1`, action SHAs
- Use `$GITHUB_WORKSPACE/scripts/` (absolute paths) for all shared script references
- Pip in Bookworm containers needs `--break-system-packages` — detect support first:
  `PIP_BSP=""; python3 -m pip install --break-system-packages --help &>/dev/null && PIP_BSP="--break-system-packages"`

### Cross-compilation gotchas
- macOS runners (`macos-latest`) are ARM64; x86_64 builds are cross-compiled
- arm64 Linux builds use cross-compilation containers (`manylinux-cross`, `rust-musl-cross`),
  NOT QEMU emulation. These are Debian-based (apt-get), not yum/apk.
- The `before-script-linux` in maturin-action handles 3 container types:
  yum (native manylinux), apk (native musllinux), apt-get (cross-compile)
- `docker/tests.Dockerfile` must use the same Debian version as build containers
  (currently bookworm) or binaries will fail with glibc version mismatch

## Performance Notes — DO NOT re-attempt hand-written JSON parsers

Hand-written JSON serializers/deserializers (`to_json_fast`, `from_json_fast`)
were removed after comprehensive benchmarking showed serde_json matches or
beats them at all payload sizes end-to-end, and is strictly faster for large
payloads (100MB+ email attachments) due to SIMD optimizations.

Microbenchmarks were misleading — they showed 19-24% wins for EKR parsing in
isolation, but end-to-end encrypt/decrypt benchmarks (both `--memory` and
`--warm`) showed zero improvement or slight regressions. The hot path is
dominated by AES-GCM and key hierarchy operations; JSON serialization is noise.

Additionally, every attempted Rust-level allocation optimization (thread-local
buffers, stack-allocated formatters, lazy `.with_context()`, `query_opt()`)
either showed no end-to-end improvement or actively regressed performance by
perturbing the compiler's inlining and code layout decisions.

**Rules:**
- Use serde_json for all JSON serialization/deserialization. Do not write
  hand-rolled parsers.
- Do not attempt allocation micro-optimizations in the encrypt/decrypt hot path.
- **ALL Rust code optimizations MUST be verified with
  `scripts/benchmark.sh --rust-only --memory` before and after the change.**
  This runs only the Criterion native benchmark (~30 seconds) and shows
  encrypt/decrypt ns/op for 64B, 1KB, 8KB payloads. If the numbers don't
  improve, revert. Do not rely on microbenchmarks alone.
- For metastore/DB-related changes, also run `scripts/benchmark.sh --rust-only --warm`.

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
