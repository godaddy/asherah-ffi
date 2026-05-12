# Published Crates on crates.io

## Crate Hierarchy

### For Rust Consumers
- **asherah** - Main library for Rust applications using envelope encryption directly

### For FFI/Language Bindings
- **asherah-ffi** - C ABI for non-Rust language bindings (.NET, Ruby, Go)
- **asherah-cobhan** - Cobhan-compatible C ABI (drop-in replacement for Go asherah-cobhan)
- **asherah-config** - Shared configuration types used by FFI layers

### Language Binding Implementation (not for direct consumption)
These crates are build artifacts for language-specific packages. End users consume via:
- Node.js: npm `@godaddy/asherah`
- Python: PyPI `asherah`
- Java: Maven `com.godaddy:asherah`
- Ruby: RubyGems `asherah`
- Go: Go module `github.com/godaddy/asherah-ffi/asherah-go`
- .NET: NuGet `GoDaddy.Asherah`

## Published (2026-05-12)

- **asherah** v0.1.1 - Main Rust library
- **asherah-config** v0.1.1 - Configuration types
- **asherah-cobhan** v0.5.1 - Cobhan C ABI for FFI
- **asherah-ffi** v0.1.0 - C ABI for language bindings

## Pending (rate limited until 19:24 GMT)

- **asherah-node** v0.1.0 - Node.js native addon (napi-rs)
- **asherah-py** v0.1.0 - Python extension module (PyO3)
- **asherah-java** v0.1.0 - JNI bindings

## Namespace Reservation Candidates

These names are available for claiming to protect the asherah namespace:

- **asherah-server** - gRPC sidecar (currently `publish = false`)
- **asherah-ruby** - Ruby bindings (no Rust crate yet)
- **asherah-go** - Go bindings (no Rust crate yet)
- **asherah-dotnet** - .NET bindings (no Rust crate yet)

## Ownership

All crates owned by: jgowdy-godaddy (jgowdy@godaddy.com)

## Changes Made

All published and pending crates had their `Cargo.toml` updated to:
1. Add version requirements for internal dependencies (e.g., `asherah = { version = "0.1.1", path = "../asherah" }`)
2. Replace invalid category `"ffi"` with `"api-bindings"`
