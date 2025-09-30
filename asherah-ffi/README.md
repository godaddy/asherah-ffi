# asherah-ffi

`asherah-ffi` exposes the Asherah AppEncryption Rust APIs over a stable C ABI
for consumption by other language bindings in this repository. It links against
the core `asherah` crate and bundles configuration helpers required by the
wrappers.

## Crate Features

- Provides a C-friendly surface area for session management and envelope
  encryption flows.
- Builds a `cdylib` suitable for linking from Go, .NET, Python, Ruby, and Java
  bindings.

## License

Licensed under the Apache License, Version 2.0.
