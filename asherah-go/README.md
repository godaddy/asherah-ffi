# asherah-go

Go binding for [Asherah](https://github.com/godaddy/asherah) application-layer encryption,
powered by the native Rust implementation via [purego](https://github.com/ebitengine/purego) (no CGO required).

## Installation

### 1. Add the module

```bash
go get github.com/godaddy/asherah-go
```

### 2. Install the native library

The binding requires the prebuilt native library for your platform. Run this
from your project directory:

```bash
go run github.com/godaddy/asherah-go/cmd/install-native@latest
```

This downloads the correct binary for your OS/architecture from
[GitHub Releases](https://github.com/godaddy/asherah-ffi/releases) into your
current working directory and verifies the SHA256 checksum. The loader finds
it automatically — no environment variables needed.

Options:

```
--version v0.6.24      # Pin to a specific release (default: latest)
--output /custom/path  # Custom output directory
--repo owner/repo      # Custom GitHub repository
```

> **Tip:** Add the library to your `.gitignore`:
> ```
> libasherah_ffi.*
> asherah_ffi.dll
> ```

### Alternative: Build from source

```bash
git clone https://github.com/godaddy/asherah-ffi.git
cd asherah-ffi
cargo build --release -p asherah-ffi
export ASHERAH_GO_NATIVE=target/release
```

## Usage

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
        Metastore:   "memory",  // or "rdbms", "dynamodb"
        KMS:         "static",  // or "aws"
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

## API

| Function | Description |
|---|---|
| `Setup(cfg Config) error` | Initialize with a Config struct |
| `SetupFromEnv() error` | Initialize from environment variables |
| `Shutdown()` | Release all resources |
| `GetSetupStatus() bool` | Check if initialized |
| `Encrypt(partition string, data []byte) ([]byte, error)` | Encrypt bytes, returns DRR JSON |
| `Decrypt(partition string, drr []byte) ([]byte, error)` | Decrypt DRR JSON to bytes |
| `EncryptString(partition, data string) (string, error)` | String convenience wrapper |
| `DecryptString(partition, drr string) (string, error)` | String convenience wrapper |
| `SetEnvJSON(payload []byte) error` | Set env vars from JSON |
| `SetEnvMap(values map[string]*string)` | Set env vars from map |

## Configuration

| Field | Type | Required | Description |
|---|---|---|---|
| `ServiceName` | `string` | Yes | Service identifier for key hierarchy |
| `ProductID` | `string` | Yes | Product identifier for key hierarchy |
| `Metastore` | `string` | Yes | `"memory"`, `"rdbms"`, or `"dynamodb"` |
| `KMS` | `string` | No | `"static"` (default) or `"aws"` |
| `ConnectionString` | `*string` | No | RDBMS connection string |
| `DynamoDBEndpoint` | `*string` | No | Custom DynamoDB endpoint |
| `DynamoDBRegion` | `*string` | No | DynamoDB region |
| `DynamoDBTableName` | `*string` | No | DynamoDB table name |
| `RegionMap` | `map[string]string` | No | AWS KMS region/ARN map |
| `PreferredRegion` | `*string` | No | Preferred AWS KMS region |
| `EnableSessionCaching` | `*bool` | No | Enable session caching (default: true) |
| `SessionCacheMaxSize` | `*int` | No | Max cached sessions |
| `SessionCacheDuration` | `*int64` | No | Cache TTL in milliseconds |
| `ExpireAfter` | `*int64` | No | Key expiration in milliseconds |
| `CheckInterval` | `*int64` | No | Key check interval in milliseconds |
| `Verbose` | `*bool` | No | Enable verbose logging |

## Native Library Search Order

The loader searches for the native library in this order:

1. `ASHERAH_GO_NATIVE` environment variable (file or directory)
2. Current working directory (default `install-native` output)
3. `CARGO_TARGET_DIR` (for development builds)
4. Repo-relative `target/` directories (for development)
5. User cache directory (`~/.cache/asherah-go/` on Linux, `~/Library/Caches/asherah-go/` on macOS)
6. System library paths (via `dlopen`)

## Supported Platforms

| OS | Architecture |
|---|---|
| Linux | x86_64, ARM64 |
| macOS | x86_64, ARM64 (Apple Silicon) |
| Windows | x86_64, ARM64 |
