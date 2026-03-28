# asherah-go

Go bindings for [Asherah](https://github.com/godaddy/asherah-ffi) envelope encryption with automatic key rotation, using [purego](https://github.com/ebitengine/purego) (no CGO required).

## Installation

### 1. Add the module

```bash
go get github.com/godaddy/asherah-go
```

### 2. Install the native library

The binding requires the prebuilt native library for your platform. Run this from your project directory:

```bash
go run github.com/godaddy/asherah-go/cmd/install-native@latest
```

This downloads the correct binary for your OS/architecture from [GitHub Releases](https://github.com/godaddy/asherah-ffi/releases), verifies the SHA256 checksum, and places it in the current working directory. The loader finds it automatically -- no environment variables needed.

Options:

```
--version v0.6.24      # Pin to a specific release (default: latest)
--output /custom/path  # Custom output directory
--repo owner/repo      # Custom GitHub repository
```

Add the library to your `.gitignore`:

```
libasherah_ffi.*
asherah_ffi.dll
```

### Alternative: Build from source

```bash
git clone https://github.com/godaddy/asherah-ffi.git
cd asherah-ffi
cargo build --release -p asherah-ffi
export ASHERAH_GO_NATIVE=target/release
```

## Quick Start

The simplest way to use Asherah is the global API. Call `Setup` once at startup and `Shutdown` on exit:

```go
package main

import (
    "fmt"
    "log"

    asherah "github.com/godaddy/asherah-go"
)

func main() {
    err := asherah.Setup(asherah.Config{
        ServiceName: "my-service",
        ProductID:   "my-product",
        Metastore:   "memory",
        KMS:         "static",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer asherah.Shutdown()

    ciphertext, err := asherah.EncryptString("partition-id", "sensitive data")
    if err != nil {
        log.Fatal(err)
    }

    plaintext, err := asherah.DecryptString("partition-id", ciphertext)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(plaintext) // "sensitive data"
}
```

The global API manages a session cache internally. Sessions are created on first use per partition and reused for subsequent calls. When session caching is disabled, sessions are created and closed per call.

## Factory/Session API

For direct control over session lifecycle, use `Factory` and `Session`:

```go
factory, err := asherah.NewFactory(asherah.Config{
    ServiceName: "my-service",
    ProductID:   "my-product",
    Metastore:   "memory",
    KMS:         "static",
})
if err != nil {
    log.Fatal(err)
}
defer factory.Close()

session, err := factory.GetSession("partition-id")
if err != nil {
    log.Fatal(err)
}
defer session.Close()

ciphertext, err := session.Encrypt([]byte("sensitive data"))
if err != nil {
    log.Fatal(err)
}

plaintext, err := session.Decrypt(ciphertext)
if err != nil {
    log.Fatal(err)
}
```

### Canonical compatibility API

For code migrating from the canonical `appencryption` SDK, use `SessionFactory` and `CompatSession` which mirror the original API surface:

```go
sf := asherah.NewSessionFactory(
    &asherah.CanonicalConfig{
        Service: "my-service",
        Product: "my-product",
        Policy:  asherah.NewCryptoPolicy(),
    },
    &asherah.InMemoryMetastore{},
    asherah.NewStaticKMS("my-key"),
    nil, // AEAD (handled by native layer)
)
defer sf.Close()

session, err := sf.GetSession("partition-id")
if err != nil {
    log.Fatal(err)
}
defer session.Close()

drr, err := session.Encrypt(context.Background(), []byte("data"))
if err != nil {
    log.Fatal(err)
}

plaintext, err := session.Decrypt(context.Background(), *drr)
if err != nil {
    log.Fatal(err)
}
```

The `CompatSession` returns `*DataRowRecord` structs matching the canonical type, accepting `context.Context` parameters for API compatibility (the context is not used for cancellation).

## No Async API

Go's goroutine model makes a dedicated async API unnecessary. Goroutines are cheap and multiplexed onto OS threads by the Go runtime, so blocking sync calls are fine:

```go
// Just use goroutines
var wg sync.WaitGroup
for _, partition := range partitions {
    wg.Add(1)
    go func(p string) {
        defer wg.Done()
        ct, err := asherah.EncryptString(p, data)
        // ...
    }(partition)
}
wg.Wait()
```

## Migration from Canonical Go SDK

This replaces `github.com/godaddy/asherah/go/appencryption`. Key differences:

| | Canonical (`appencryption`) | This binding (`asherah-go`) |
|---|---|---|
| Implementation | Pure Go | Rust + purego FFI |
| CGO required | Yes (protectedmemory) or No (memguard) | No (purego) |
| Serialization | Protobuf | JSON |
| Memory protection | protectedmemory/memguard | Rust memguard (mlock + wipe) |
| Session model | `SessionFactory` | `Factory` / `Session` (+ compat layer) |
| Metastore format | Wire-compatible | Wire-compatible |

Migration steps:

1. Replace import `github.com/godaddy/asherah/go/appencryption` with `github.com/godaddy/asherah-go`
2. Install the native library via `install-native`
3. Either:
   - Use the new `Factory`/`Session` API directly, or
   - Use `SessionFactory`/`CompatSession` for a drop-in compatible API
4. Both read the same metastore tables -- no data migration required

## Performance

Benchmarked on Apple M4 Max, 64-byte payload, hot session cache:

| Operation | Latency |
|---|---|
| Encrypt | ~1,074 ns |
| Decrypt | ~973 ns |

## Supported Platforms

| OS | Architecture |
|---|---|
| Linux | x86_64, ARM64 |
| macOS | x86_64, ARM64 (Apple Silicon) |
| Windows | x86_64, ARM64 |

## Configuration

| Field | Type | Required | Description |
|---|---|---|---|
| `ServiceName` | `string` | Yes | Service identifier for key hierarchy |
| `ProductID` | `string` | Yes | Product identifier for key hierarchy |
| `Metastore` | `string` | Yes | `"memory"`, `"rdbms"`, or `"dynamodb"` |
| `KMS` | `string` | No | `"static"` (default) or `"aws"` |
| `ConnectionString` | `*string` | No | RDBMS connection string |
| `ReplicaReadConsistency` | `*string` | No | DynamoDB read consistency |
| `DynamoDBEndpoint` | `*string` | No | Custom DynamoDB endpoint |
| `DynamoDBRegion` | `*string` | No | DynamoDB region |
| `DynamoDBTableName` | `*string` | No | DynamoDB table name |
| `RegionMap` | `map[string]string` | No | AWS KMS region-to-ARN map |
| `PreferredRegion` | `*string` | No | Preferred AWS KMS region |
| `EnableRegionSuffix` | `*bool` | No | Append region suffix to key IDs |
| `EnableSessionCaching` | `*bool` | No | Enable session caching (default: true) |
| `SessionCacheMaxSize` | `*int` | No | Max cached sessions (default: 1000) |
| `SessionCacheDuration` | `*int64` | No | Cache TTL in milliseconds |
| `ExpireAfter` | `*int64` | No | Key expiration in milliseconds |
| `CheckInterval` | `*int64` | No | Key check interval in milliseconds |
| `Verbose` | `*bool` | No | Enable verbose logging |

You can also initialize from environment variables:

```go
err := asherah.SetupFromEnv()
// or
factory, err := asherah.NewFactoryFromEnv()
```

## Native Library Search Order

The loader searches for the native library in this order:

1. `ASHERAH_GO_NATIVE` environment variable (file or directory)
2. Current working directory (default `install-native` output)
3. `CARGO_TARGET_DIR` (for development builds)
4. Repo-relative `target/` directories (for development)
5. User cache directory (`~/.cache/asherah-go/` on Linux, `~/Library/Caches/asherah-go/` on macOS)
6. System library paths (via `dlopen`)

## API Reference

### Global API

| Function | Description |
|---|---|
| `Setup(cfg Config) error` | Initialize with a Config struct |
| `SetupFromEnv() error` | Initialize from environment variables |
| `Shutdown()` | Release all resources and cached sessions |
| `GetSetupStatus() bool` | Check if initialized |
| `Encrypt(partition, data)` | Encrypt `[]byte`, returns DRR JSON |
| `Decrypt(partition, drr)` | Decrypt DRR JSON to `[]byte` |
| `EncryptString(partition, data)` | String convenience wrapper |
| `DecryptString(partition, drr)` | String convenience wrapper |
| `SetEnvJSON(payload []byte) error` | Set env vars from JSON |
| `SetEnvMap(values map[string]*string)` | Set env vars from map |

### Factory

| Method | Description |
|---|---|
| `NewFactory(cfg Config) (*Factory, error)` | Create a factory from config |
| `NewFactoryFromEnv() (*Factory, error)` | Create a factory from env vars |
| `(*Factory).GetSession(partitionID)` | Create a session for a partition |
| `(*Factory).Close()` | Release the factory |

### Session

| Method | Description |
|---|---|
| `(*Session).Encrypt(plaintext)` | Encrypt `[]byte`, returns DRR JSON |
| `(*Session).EncryptString(plaintext)` | String convenience wrapper |
| `(*Session).Decrypt(drr)` | Decrypt DRR JSON to `[]byte` |
| `(*Session).DecryptString(drr)` | String convenience wrapper |
| `(*Session).Close()` | Release the session |

### Canonical Compatibility Layer

| Type/Function | Description |
|---|---|
| `NewSessionFactory(config, store, kms, ...)` | Create a canonical-compatible factory |
| `(*SessionFactory).GetSession(id)` | Get a canonical-compatible session |
| `(*SessionFactory).Close()` | Release the factory |
| `(*CompatSession).Encrypt(ctx, data)` | Encrypt, returns `*DataRowRecord` |
| `(*CompatSession).Decrypt(ctx, drr)` | Decrypt a `*DataRowRecord` |
| `(*CompatSession).Load(ctx, key, store)` | Load and decrypt from a store |
| `(*CompatSession).Store(ctx, data, store)` | Encrypt and store |
| `(*CompatSession).Close()` | Release the session |

## License

Licensed under the Apache License, Version 2.0.
