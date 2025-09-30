Asherah
-------

This repository hosts the Rust Asherah AppEncryption SDK along with multi-language bindings that mirror the established Go APIs.

Rust crates
- `asherah`: Rust port of Asherah AppEncryption with compatible JSON, API, and KMS/metastore integrations.
- `asherah-ffi`: C ABI wrapper consumed by the language bindings found in this repository.

Build & test
- Build + test whole workspace: `cargo build && cargo test`
- `cd asherah && cargo test`
- Python bindings: `python3 -m pytest asherah-py/tests`
- Node addon: `cd asherah-node && npm install && npm test`
- Java bindings: `cargo build -p asherah-java && cd asherah-java/java && mvn test`
- .NET bindings: `cargo build -p asherah-ffi && dotnet test asherah-dotnet/AsherahDotNet.sln`
- Ruby bindings: `ruby -Iasherah-ruby/lib -Iasherah-ruby/test asherah-ruby/test/round_trip_test.rb`
- Go bindings: `cd asherah-go && go test ./...` (requires `ASHERAH_GO_NATIVE` pointing to the native library path)
- Full matrix via Docker: `./scripts/test-in-docker.sh` (requires Docker engine)

Backends (feature‑gated)
- SQLite (`sqlite`), MySQL (`mysql`), Postgres (`postgres`), DynamoDB (`dynamodb`)

Examples
- `asherah/examples/` contains examples for in-memory, SQLite, MySQL, Postgres, and AWS KMS usage.

Docker-based test harness
- Build deterministic environment with Rust, Node, Python, Java, .NET, Ruby, Go: `./scripts/test-in-docker.sh`
- The script builds `docker/tests.Dockerfile`, mounts the repo, and runs all language-specific tests (`cargo test`, Python, Node, Ruby, Go, interop, Java, .NET).

.NET usage
- Managed wrapper lives under `asherah-dotnet/`
- Ensure the native Asherah library is on the search path (`ASHERAH_DOTNET_NATIVE=/path/to/target/debug`), then:
  - `dotnet add package` is not required—projects already reference the wrapper
  - Run tests via `dotnet test asherah-dotnet/AsherahDotNet.sln`
- The wrapper loads the native `asherah_ffi` library using `ASHERAH_DOTNET_NATIVE`, `AppContext` data, or OS search paths.

See `asherah/README.md` for full details.
- Python, Ruby, Java, .NET, and Go wrappers now expose `setup`/`shutdown` (plus async counterparts where idiomatic), session caching, and byte/string helpers mirroring the published `asherah-node` API, including environment bootstrap helpers to build factories from structured configuration objects.

Contributing & security
- Please read `CONTRIBUTING.md` for development workflow expectations.
- For vulnerability disclosures, consult `SECURITY.md`.
