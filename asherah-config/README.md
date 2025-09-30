# asherah-config

`asherah-config` centralizes the shared configuration schema used by the
language bindings to bootstrap Asherah sessions. The crate layers serde-based
parsing utilities over the core `asherah` types.

## Highlights

- Deserializes structured configuration (JSON, YAML, etc.) into strongly typed
  Rust structs.
- Supports feature-flagged datastore and KMS adapters via optional dependencies
  in the core crate.
- Keeps configuration logic consistent across Python, Node, Ruby, Go, Java, and
  .NET packages.

## License

Licensed under the Apache License, Version 2.0.
