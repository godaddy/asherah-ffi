# Asherah

Application-layer encryption with automatic key rotation. Rust implementation
with bindings for Node.js, Python, .NET, Java, Ruby, and Go.

## What is Asherah?

Asherah implements envelope encryption: data is encrypted with a random data key,
which is itself encrypted with an intermediate key, which is encrypted by a
master key held in a KMS. Keys rotate automatically based on configurable
intervals, and old keys remain accessible for decryption while new data is always
encrypted with fresh keys.

This design means application code never handles raw master keys, key rotation
happens transparently, and compromise of a single data key exposes only one
record.

**KMS backends:** AWS KMS, static (testing only)

**Metastores:** DynamoDB, MySQL, Postgres, SQLite, in-memory

## Language Bindings

| Language | Package | Install | README |
|----------|---------|---------|--------|
| Node.js | `asherah` (npm) | `npm install asherah` | [asherah-node/](asherah-node/) |
| Python | `asherah` (PyPI) | `pip install asherah` | [asherah-py/](asherah-py/) |
| .NET | `GoDaddy.Asherah.AppEncryption` (NuGet) | `dotnet add package GoDaddy.Asherah.AppEncryption` | [asherah-dotnet/](asherah-dotnet/) |
| Java | `com.godaddy.asherah:asherah-java` (Maven) | Maven/Gradle | [asherah-java/](asherah-java/) |
| Ruby | `asherah` (RubyGems) | `gem install asherah` | [asherah-ruby/](asherah-ruby/) |
| Go | `github.com/godaddy/asherah-go` | `go get github.com/godaddy/asherah-go` | [asherah-go/](asherah-go/) |

## Platform Support

| Platform | Architecture | Status |
|----------|-------------|--------|
| Linux | x86_64 (glibc) | Supported |
| Linux | x86_64 (musl) | Supported |
| Linux | ARM64 (glibc) | Supported |
| Linux | ARM64 (musl) | Supported |
| macOS | x86_64 | Supported |
| macOS | ARM64 (Apple Silicon) | Supported |
| Windows | x64 | Supported |
| Windows | ARM64 | Supported |

## Quick Start

```js
const asherah = require('asherah');

asherah.setup({
  serviceName: 'my-service',
  productId: 'my-product',
  metastore: 'memory',
  kms: 'static',
});

const ct = asherah.encryptString('partition', 'secret data');
const pt = asherah.decryptString('partition', ct);

asherah.shutdown();
```

See each binding's README for complete examples including async APIs,
session-based usage, and production configuration.

## Performance

The Rust core delivers sub-microsecond encrypt/decrypt operations. Binding
overhead varies by language but stays well under 2 microseconds in all cases.

| Implementation | Encrypt 64B (ns) | Decrypt 64B (ns) |
|---|---|---|
| Rust native | 397 | 306 |
| .NET | 693 | 618 |
| Node.js | 972 | 1,208 |
| Python | 1,049 | 791 |
| Go | 1,074 | 973 |
| Java | 1,118 | 974 |
| Ruby | 1,170 | 1,110 |

Apple M4 Max, memory metastore, hot cache. See each binding's README for
detailed benchmarks including async and comparison with canonical
implementations.

## Testing

- **127 Rust unit tests** covering core encryption engine, key management,
  metastore adapters, and memory protection
- **64 .NET tests** (34 core + 30 compatibility layer) across net8.0 and net10.0
- **49 Node.js tests** including async context, unicode, binary edge cases, and
  Factory/Session API
- **21 Go tests** covering Factory/Session API and compatibility layer
- **21 Python tests** including session-based and async APIs
- **16 Java tests** including JNI lifecycle and async CompletableFuture
- **74 Ruby tests** including thread safety, session lifecycle, and async
  callbacks
- **5 cross-language interop tests** verifying Python, Node.js, Rust, and Ruby
  encrypt/decrypt compatibility
- **6 fuzz targets** for Cargo-fuzz continuous fuzzing
- **Memory safety**: Miri (undefined behavior detection), AddressSanitizer, and
  Valgrind on every PR
- **12 publish dry-run jobs** that replicate every unique compilation path in the
  release pipeline
- **56+ CI jobs** on every pull request across x86_64 and ARM64

```bash
# Run all tests
scripts/test.sh --all

# Individual test modes
scripts/test.sh --unit
scripts/test.sh --integration    # requires Docker (MySQL, Postgres, DynamoDB)
scripts/test.sh --bindings       # requires language toolchains
scripts/test.sh --interop
scripts/test.sh --lint
scripts/test.sh --sanitizers     # Miri, AddressSanitizer, Valgrind
scripts/test.sh --fuzz           # requires nightly
```

## Project Structure

| Directory | Description |
|-----------|-------------|
| `asherah/` | Rust core library |
| `asherah-node/` | Node.js bindings |
| `asherah-py/` | Python bindings |
| `asherah-dotnet/` | .NET bindings |
| `asherah-java/` | Java bindings (JNI) |
| `asherah-ruby/` | Ruby bindings |
| `asherah-go/` | Go bindings (purego, no CGO) |
| `asherah-ffi/` | C ABI for language bindings |
| `asherah-server/` | gRPC sidecar server |
| `samples/` | Usage examples for each language |
| `benchmarks/` | Cross-language benchmark suite |

## Security

- All secret buffers use mlock'd memory with guard pages
- Automatic wipe-on-free for all key material
- Core dump protection enabled at initialization
- Static master keys are for testing only -- production must use AWS KMS

## License

[Apache-2.0](LICENSE)
