# Contributing

Thank you for your interest in improving the Asherah ecosystem. This repository
contains the Rust core encryption engine, native FFI layer, and language
bindings for Node.js, Python, .NET, Java, Ruby, and Go. The following
guidelines keep contributions consistent and easy to review.

## Getting Started

1. Install the Rust toolchain (1.91+ pinned via `rust-toolchain.toml`) with
   the `rustfmt` and `clippy` components.
2. Install language toolchains for the bindings you plan to touch:
   - Node.js 18+
   - Python 3.8+
   - .NET 8.0 or 10.0
   - Java 11+ (Maven)
   - Ruby 3.0+
   - Go 1.23+
3. Docker is required for integration tests (MySQL, Postgres, DynamoDB) and
   the full test suite: `scripts/test.sh --all`.

## Development Workflow

1. Create a feature branch from `main`.
2. Make focused commits with clear, imperative messages describing the change
   and why it is needed.
3. Keep changes minimal — avoid sweeping refactors unless required to fix a
   bug or implement a feature.
4. Open a pull request. CI runs automatically and must pass before merge.

## Building

```bash
# Rust workspace (all crates)
cargo build

# Individual binding
cargo build -p asherah-node    # Node.js (napi-rs)
cargo build -p asherah-py      # Python (PyO3/maturin)
cargo build -p asherah-java    # Java (JNI)
cargo build -p asherah-ffi     # C ABI (.NET, Ruby, Go)
```

## Testing

Run the tests for the areas you changed before opening a pull request.

```bash
# Rust unit tests
scripts/test.sh --unit

# Lint (rustfmt + clippy)
scripts/test.sh --lint

# All binding tests (requires language toolchains)
scripts/test.sh --bindings

# Integration tests (requires Docker)
scripts/test.sh --integration

# Everything
scripts/test.sh --all
```

Individual binding tests:

| Binding | Command |
|---------|---------|
| Node.js | `cd asherah-node && npm test` |
| Python | `maturin develop --manifest-path asherah-py/Cargo.toml && pytest asherah-py/tests/` |
| .NET | `dotnet test asherah-dotnet/GoDaddy.Asherah.Encryption.slnx --nologo -p:RestoreLockedMode=true` |
| Java | `cd asherah-java/java && mvn test` |
| Ruby | `ruby -Iasherah-ruby/lib -Iasherah-ruby/test asherah-ruby/test/round_trip_test.rb` |
| Go | `cd asherah-go && go test ./...` |

`.NET` tests need a locally built `asherah-ffi` native library. From the repo root: run `cargo build -p asherah-ffi`, then the `dotnet test` command above (tests default to `{repo}/target/debug` when `ASHERAH_DOTNET_NATIVE` is unset). For a **release** build, see [`asherah-dotnet/README.md`](asherah-dotnet/README.md) — use `ASHERAH_DOTNET_NATIVE="$(pwd)/target/release"`, not a bare `target/release` path.

## Formatting & Linting

- **Rust**: `cargo fmt` and `cargo clippy --workspace --all-targets` (enforced
  by pre-commit hooks and CI).
- **Go**: `go fmt ./...`
- **Ruby**: `rubocop` (configuration in `asherah-ruby/.rubocop.yml`)
- Use the repository `.editorconfig` to align editor settings across languages.

## Pull Request Checklist

- [ ] Code compiles and tests pass for the components you touched.
- [ ] `scripts/test.sh --lint` passes.
- [ ] Documentation is updated when behavior or configuration changes.
- [ ] No sensitive data (keys, credentials, tokens) is logged or committed.
- [ ] New features include tests.

## Security

Please do **not** open public issues for security vulnerabilities. Use the
GitHub Security Advisories feature (Security tab > "Report a vulnerability")
to contact maintainers privately. See [SECURITY.md](SECURITY.md) for details.

## Questions?

Open a draft pull request or start a discussion in
[Issues](https://github.com/godaddy/asherah-ffi/issues) before investing
significant effort. We're happy to help align on approach.
