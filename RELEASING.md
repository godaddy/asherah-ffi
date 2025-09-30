# Releasing

This document captures the workflow for cutting a release across the Rust core
crate and the associated language bindings.

## 1. Version Coordination

1. Choose a new semantic version for the Rust crates (`asherah`, `asherah-config`,
   `asherah-ffi`, `asherah-node`, `asherah-py`, `asherah-java`).
2. Update the version field in each `Cargo.toml`. Keep the workspace in sync by
   adjusting `Cargo.lock` with `cargo update -p <crate>@<version>`.
3. Propagate the version bump to language package manifests:
   - Node: update `asherah-node/package.json` and regenerate lockfiles.
   - Python: update `asherah-py/pyproject.toml` or `setup.cfg` as applicable.
   - Ruby: update gemspec in `asherah-ruby/`.
   - .NET: update the `.csproj` version in `asherah-dotnet/`.
   - Java: update the Maven POM version under `asherah-java/java/`.
   - Go: update any version constants or module tags in `asherah-go/`.

Record the changes in `CHANGELOG.md` under a new heading (e.g. `## [1.0.0] -
YYYY-MM-DD`).

## 2. Test Matrix

Run targeted tests before broader validation:

1. `cargo fmt --all` and `cargo clippy --all-targets --all-features`.
2. `cargo test` at the workspace root and again within `asherah/`.
3. Feature adapters (set the relevant environment values):
   - SQLite: `cargo test --features sqlite`.
   - MySQL: `MYSQL_URL=mysql://user:pass@host/db cargo test --features mysql`.
   - Postgres: `POSTGRES_URL=postgres://user:pass@host/db cargo test --features postgres`.
   - DynamoDB: `AWS_REGION=us-west-2 DDB_TABLE=asherah-tests cargo test --features dynamodb`.
4. Language bindings:
   - Node: `npm install && npm test` in `asherah-node/` for each supported
     platform (CI covers macOS, Linux, Windows).
   - Python: `maturin develop && python -m pytest asherah-py/tests` across the
     supported interpreter matrix.
   - Ruby: `bundle exec rake test` in `asherah-ruby/`.
   - Go: `ASHERAH_GO_NATIVE=<path/to/libasherah_ffi.so> go test ./...` in
     `asherah-go/`.
   - .NET: `dotnet test asherah-dotnet/AsherahDotNet.sln`.
   - Java: `mvn test` inside `asherah-java/java/`.

If any platform-specific artifacts are generated (e.g., prebuilt Node binaries),
confirm they pass smoke tests before publishing.

Finally, execute the full matrix script for parity with CI:

```bash
./scripts/test-in-docker.sh
```

## 3. Packaging & Publishing

1. Create release builds of the Rust crates using `cargo build --release`.
2. For Node, Python, Ruby, Go, .NET, and Java bindings, follow the packaging
   instructions in their respective directories. Typical commands:
   - Node: `npm run build && npm pack`.
   - Python: `maturin build --release`.
   - Ruby: `gem build asherah-ruby.gemspec`.
   - Go: ensure the FFI artifacts are available, then tag the module.
   - .NET: `dotnet pack -c Release`.
   - Java: `mvn -pl java -am package`.
3. Upload artifacts to their registries (crates.io, npm, PyPI, RubyGems, NuGet,
   Maven Central) once validation succeeds. Each workflow requires credentials
   configured via GitHub Actions secrets.

## 4. Tagging & Release Notes

1. Tag the repository using `git tag vX.Y.Z`.
2. Push the tag to GitHub (`git push origin vX.Y.Z`).
3. Create a GitHub release and populate the notes from the corresponding
   `CHANGELOG.md` entry.

## 5. Post-release Verification

1. Monitor crates.io and other registries to confirm artifacts are available.
2. Validate that documentation (e.g., https://docs.rs/asherah) has built
   successfully.
3. Update any downstream sample applications or integration tests to the new
   version.
