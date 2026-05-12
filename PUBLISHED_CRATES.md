# Published Crates on crates.io

## Published (2026-05-12)

- **asherah** v0.1.1 - Core encryption library
- **asherah-config** v0.1.1 - Configuration types
- **asherah-cobhan** v0.5.1 - Cobhan C ABI
- **asherah-ffi** v0.1.0 - C ABI for language bindings

## Pending (rate limited until 19:24 GMT)

- **asherah-node** v0.1.0 - Node.js bindings
- **asherah-py** v0.1.0 - Python bindings
- **asherah-java** v0.1.0 - Java/JNI bindings

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
