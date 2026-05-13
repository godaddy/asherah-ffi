# Published Crates on crates.io

## Crate Hierarchy

### For Rust Consumers
- **asherah** - Main library for Rust applications using envelope encryption directly

### For FFI/Language Bindings
- **asherah-ffi** - C ABI for non-Rust language bindings (.NET, Ruby, Go)
- **asherah-cobhan** - Cobhan-compatible C ABI (drop-in replacement for Go asherah-cobhan)
- **asherah-config** - Shared configuration types used by FFI layers

### Language Bindings (NOT published to crates.io)
Language-specific packages are consumed through their native package managers:
- Node.js: npm `@godaddy/asherah`
- Python: PyPI `asherah`
- Java: Maven `com.godaddy:asherah`
- Ruby: RubyGems `asherah`
- Go: Go module `github.com/godaddy/asherah-ffi/asherah-go`
- .NET: NuGet `GoDaddy.Asherah`

The Rust crates (asherah-node, asherah-py, asherah-java) are build artifacts only, not intended for crates.io.

## Published to crates.io (2026-05-12)

- **asherah** v0.1.1 - Main Rust library
- **asherah-config** v0.1.1 - Configuration types
- **asherah-ffi** v0.1.0 - C ABI for language bindings
- **asherah-cobhan** v0.5.1 - Cobhan C ABI for FFI

## Namespace Protection Candidates

Optional placeholder crates to prevent namespace squatting:

- **asherah-server** - gRPC sidecar (currently `publish = false`)
- **asherah-node** - Node.js bindings (build artifact, but could claim namespace)
- **asherah-py** - Python bindings (build artifact, but could claim namespace)
- **asherah-java** - Java bindings (build artifact, but could claim namespace)
- **asherah-ruby** - Ruby bindings (no Rust crate yet)
- **asherah-go** - Go bindings (no Rust crate yet)
- **asherah-dotnet** - .NET bindings (no Rust crate yet)

## Ownership

All crates owned by: jgowdy-godaddy (jgowdy@godaddy.com)

## Changes Made

Published crates had their `Cargo.toml` updated to:
1. Add version requirements for internal dependencies (e.g., `asherah = { version = "0.1.1", path = "../asherah" }`)
2. Replace invalid category `"ffi"` with `"api-bindings"`
3. Mark language-binding build crates as `publish = false`
