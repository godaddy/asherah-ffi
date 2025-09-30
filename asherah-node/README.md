# asherah-node

`asherah-node` packages the Asherah AppEncryption runtime as a Node.js native
addon using `napi-rs`. The crate builds a `cdylib` that is published to npm via
the accompanying workflow.

## Features

- Provides synchronous and asynchronous session helpers mirroring the Go SDK.
- Shares configuration parsing through the `asherah-config` crate.
- Leverages the same Rust core (`asherah`) used by other language bindings.

## Building

Use `npm install` in `asherah-node/` to compile the addon locally. CI builds
and publishes prebuilt binaries for supported targets.

## License

Licensed under the Apache License, Version 2.0.
