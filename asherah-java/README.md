# asherah-java

`asherah-java` exposes the Asherah AppEncryption runtime to the JVM through a
JNI bridge. The crate compiles to a shared library that is loaded by the Java
wrapper in `asherah-java/java/`.

## Capabilities

- Provides helpers for initializing sessions, encrypting payloads, and handling
  envelope keys from Java.
- Reuses the `asherah-config` crate so the Java layer shares configuration with
  other language bindings.

## Building

Use `cargo build -p asherah-java` to compile the shared library. The Maven
project under `asherah-java/java/` includes tests that exercise the JNI bindings.

## License

Licensed under the Apache License, Version 2.0.
