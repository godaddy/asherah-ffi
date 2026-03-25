# Scripts

Shared scripts used by CI workflows and local development.

## Test & Build

- **`test.sh`** — Unified test runner. Modes: `--unit`, `--integration`, `--bindings`, `--interop`, `--fuzz`, `--sanitizers`, `--lint`, `--e2e`, `--all`
- **`build-bindings.sh`** — Builds language binding artifacts for a given platform
- **`test-in-docker.sh`** — Runs binding tests inside Docker (used by arm64 CI jobs)
- **`benchmark.sh`** — Runs benchmarks across all language bindings

## CI Helpers (shared by workflows and dry-runs)

- **`maturin-before-script-linux.sh`** — Installs OpenSSL and build tools inside maturin Docker containers. Sourced by `publish-pypi.yml` and all PyPI CI dry-runs.
- **`download-musl-openssl.sh`** — Downloads musl-compatible OpenSSL from Alpine packages. Used by npm musl builds and maturin musl cross-compile.
- **`install-sccache.sh`** — Installs sccache in container environments where GitHub Actions aren't available.
- **`set-pypi-version.sh`** — Patches version in `asherah-py/pyproject.toml` and `Cargo.toml` for PyPI publishing.
