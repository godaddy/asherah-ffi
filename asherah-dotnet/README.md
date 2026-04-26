# GoDaddy.Asherah.AppEncryption

.NET bindings for the [Asherah](https://github.com/godaddy/asherah) envelope encryption library with automatic key rotation. Powered by a native Rust implementation via P/Invoke.

## Installation

Published to [GitHub Packages](https://github.com/godaddy/asherah-ffi/packages). Add the GitHub NuGet source, then install:

```bash
dotnet nuget add source "https://nuget.pkg.github.com/godaddy/index.json" \
  --name godaddy --username YOUR_GITHUB_USERNAME --password YOUR_GITHUB_TOKEN
dotnet add package GoDaddy.Asherah.AppEncryption
```

For drop-in compatibility with the canonical GoDaddy Asherah .NET SDK (SessionFactory builder pattern, `Session<TP, TD>` generics, `Persistence<T>`, etc.):

```bash
dotnet add package GoDaddy.Asherah.AppEncryption.Compat
```

**Supported targets:** .NET 8.0 and .NET 10.0. Native libraries are bundled for Linux x64/ARM64, macOS x64/ARM64, and Windows x64/ARM64.

## Quick Start (Static API)

The simplest way to use Asherah -- configure once, encrypt/decrypt anywhere:

```csharp
using GoDaddy.Asherah;

var config = AsherahConfig.CreateBuilder()
    .WithServiceName("my-service")
    .WithProductId("my-product")
    .WithMetastore("memory")    // testing only
    .WithKms("static")          // testing only
    .WithEnableSessionCaching(true)
    .Build();

Asherah.Setup(config);
try
{
    var ct = Asherah.EncryptString("partition", "secret data");
    var pt = Asherah.DecryptString("partition", ct);
}
finally
{
    Asherah.Shutdown();
}
```

## Factory/Session API (preferred)

For explicit lifetime management and multiple concurrent partitions:

```csharp
using GoDaddy.Asherah;

var config = AsherahConfig.CreateBuilder()
    .WithServiceName("my-service")
    .WithProductId("my-product")
    .WithMetastore("memory")    // testing only
    .WithKms("static")          // testing only
    .Build();

using var factory = Asherah.FactoryFromConfig(config);
using var session = factory.GetSession("user-123");

byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("sensitive payload");
byte[] ciphertext = session.EncryptBytes(plaintext);
byte[] decrypted = session.DecryptBytes(ciphertext);
```

## Async API

All encrypt/decrypt operations have async counterparts:

```csharp
// Static API
var ct = await Asherah.EncryptStringAsync("partition", "data");
var pt = await Asherah.DecryptStringAsync("partition", ct);

// Session API
var ct = await session.EncryptBytesAsync(plaintext);
var pt = await session.DecryptBytesAsync(ct);
```

## Async Behavior

The .NET async methods use **true async callbacks** from the Rust tokio runtime. A `TaskCompletionSource` is completed from a tokio worker thread via an `[UnmanagedCallersOnly]` callback -- the .NET thread pool is NOT blocked while waiting for the native operation.

| Metastore | Async Pattern | Blocks ThreadPool? |
|-----------|--------------|-------------------|
| In-Memory | Tokio worker -> callback | No |
| DynamoDB | True async AWS SDK -> callback | No |
| MySQL | spawn_blocking -> callback | No |
| Postgres | spawn_blocking -> callback | No |

**Overhead:** ~9.8us async vs ~0.7us sync (64B payload, hot cache). Use async for ASP.NET Core request handlers; use sync for batch processing.

## Input contract

**Partition ID** (`null`, `""`, whitespace-only): `null` and `""` are
always rejected as programming errors with `ArgumentNullException` /
`InvalidOperationException`. No row is ever written to the metastore
under a degenerate partition ID. (Canonical `GoDaddy.Asherah.AppEncryption`
v0.11.0 accepts both silently and persists `_IK__service_product` rows;
this binding is deliberately stricter.)

**Plaintext** to encrypt:
- `null` → `ArgumentNullException` (sync) / rejected `Task` (async).
- Empty `string` (`""`) and empty `byte[]` (`Array.Empty<byte>()`) are
  **valid** plaintexts. `Encrypt(...)` produces a real `DataRowRecord`
  envelope; the matching `Decrypt(...)` returns exactly `""` or
  `Array.Empty<byte>()`.

**Ciphertext** to decrypt:
- `null` → `ArgumentNullException`.
- Empty `string` / `byte[]` → `AsherahException` (not valid
  `DataRowRecord` JSON).

**Do not short-circuit empty plaintext encryption in caller code** —
empty data is real data, encrypting it produces a genuine envelope, and
skipping encryption leaks the fact that the value was empty. See
[docs/input-contract.md](../docs/input-contract.md) for the full
rationale.

## Migration from Canonical (`GoDaddy.Asherah.AppEncryption` v0.2.x)

The `GoDaddy.Asherah.AppEncryption.Compat` NuGet package provides a drop-in compatible API surface matching the canonical C# SDK:

- `SessionFactory.NewBuilder("product", "service")` builder pattern
- `Session<JObject, JObject>` and `Session<byte[], byte[]>` generics
- `Persistence<T>` and `AdhocPersistence<T>`
- `Option<T>` (LanguageExt-compatible, bundled -- no extra dependency)
- `NeverExpiredCryptoPolicy`, `BasicExpiringCryptoPolicy`
- `StaticKeyManagementServiceImpl`, `AwsKeyManagementServiceImpl`
- `InMemoryMetastoreImpl`, `AdoMetastoreImpl`, `DynamoDbMetastoreImpl`

### Before (canonical SDK)

```csharp
using GoDaddy.Asherah.AppEncryption;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;

using var factory = SessionFactory.NewBuilder("product", "service")
    .WithInMemoryMetastore()
    .WithNeverExpiredCryptoPolicy()
    .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
    .Build();

using var session = factory.GetSessionBytes("partition");
byte[] encrypted = session.Encrypt(Encoding.UTF8.GetBytes("hello"));
byte[] decrypted = session.Decrypt(encrypted);
```

### After (this package -- same code, no changes needed)

```csharp
// Same code works. Just replace the NuGet package:
//   - GoDaddy.Asherah.AppEncryption (old canonical)
//   + GoDaddy.Asherah.AppEncryption.Compat (this Rust FFI binding)

using var factory = SessionFactory.NewBuilder("product", "service")
    .WithInMemoryMetastore()
    .WithNeverExpiredCryptoPolicy()
    .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
    .Build();

using var session = factory.GetSessionBytes("partition");
byte[] encrypted = session.Encrypt(Encoding.UTF8.GetBytes("hello"));
byte[] decrypted = session.Decrypt(encrypted);
```

## Performance vs Canonical

This Rust implementation delivers significantly better performance than the canonical C# SDK (v0.2.10):

- **Encrypt 64B:** ~693 ns (Rust FFI) -- see `scripts/benchmark.sh` for canonical comparison
- **Decrypt 64B:** ~618 ns (Rust FFI)
- .NET is the fastest FFI binding due to minimal P/Invoke overhead

## Configuration

`AsherahConfig` uses a fluent builder:

```csharp
var config = AsherahConfig.CreateBuilder()
    // Required
    .WithServiceName("my-service")
    .WithProductId("my-product")
    .WithMetastore("memory")             // "rdbms", "dynamodb", "memory" (testing)
    .WithKms("static")                   // "aws", "static" (testing)

    // Key rotation
    .WithExpireAfter(86400)              // Key expiration in seconds
    .WithCheckInterval(3600)             // Revoke check interval in seconds

    // RDBMS metastore
    .WithConnectionString("Server=...")  // MySQL or PostgreSQL connection string

    // DynamoDB metastore
    .WithDynamoDbEndpoint("http://localhost:8000")
    .WithDynamoDbRegion("us-west-2")
    .WithDynamoDbSigningRegion("us-west-2")
    .WithDynamoDbTableName("EncryptionKey")
    .WithReplicaReadConsistency("eventual")
    .WithEnableRegionSuffix(true)

    // AWS KMS
    .WithRegionMap(new Dictionary<string, string>
    {
        ["us-west-2"] = "arn:aws:kms:us-west-2:123456789:key/abc-123"
    })
    .WithPreferredRegion("us-west-2")

    // Session caching
    .WithEnableSessionCaching(true)      // Default: true
    .WithSessionCacheMaxSize(1000)
    .WithSessionCacheDuration(600)       // Seconds

    // Connection pool (RDBMS metastore)
    .WithPoolMaxOpen(10)                 // Max open connections (0 = unlimited)
    .WithPoolMaxIdle(2)                  // Max idle connections (default: 2)
    .WithPoolMaxLifetime(1800)           // Max connection lifetime in seconds (0 = unlimited)
    .WithPoolMaxIdleTime(600)            // Max idle time in seconds (0 = unlimited)

    // Diagnostics
    .WithVerbose(true)

    .Build();
```

### Metastore options

| Value | Description |
|-------|-------------|
| `"memory"` | In-memory, non-persistent (testing only) |
| `"rdbms"` | MySQL or PostgreSQL via `ConnectionString` |
| `"dynamodb"` | AWS DynamoDB |

### KMS options

| Value | Description |
|-------|-------------|
| `"static"` | Static master key (testing only). Set `STATIC_MASTER_KEY_HEX` env var. |
| `"aws"` | AWS KMS. Requires `RegionMap` and `PreferredRegion`. |

## API Reference

### `Asherah` (static class)

| Method | Description |
|--------|-------------|
| `FactoryFromConfig(AsherahConfig)` | Create a new `AsherahFactory` from config |
| `FactoryFromEnv()` | Create a new `AsherahFactory` from environment variables |
| `Setup(AsherahConfig)` | Initialize the shared global instance |
| `SetupAsync(AsherahConfig)` | Async version of `Setup` |
| `Shutdown()` | Tear down the shared global instance |
| `ShutdownAsync()` | Async version of `Shutdown` |
| `GetSetupStatus()` | Returns `true` if `Setup` has been called |
| `SetEnv(IDictionary<string, string?>)` | Set environment variables before setup |
| `Encrypt(string, byte[])` | Encrypt bytes for a partition |
| `EncryptString(string, string)` | Encrypt a UTF-8 string for a partition |
| `EncryptAsync(string, byte[])` | Async encrypt bytes |
| `EncryptStringAsync(string, string)` | Async encrypt string |
| `Decrypt(string, byte[])` | Decrypt bytes for a partition |
| `DecryptJson(string, string)` | Decrypt a JSON string, return raw bytes |
| `DecryptString(string, string)` | Decrypt a JSON string, return UTF-8 string |
| `DecryptAsync(string, byte[])` | Async decrypt bytes |
| `DecryptStringAsync(string, string)` | Async decrypt string |

### `AsherahFactory` : `IAsherahFactory`, `IDisposable`

| Method | Description |
|--------|-------------|
| `GetSession(string partitionId)` | Create a new `AsherahSession` for the given partition |
| `Dispose()` | Release the native factory handle |

### `AsherahSession` : `IAsherahSession`, `IDisposable`

| Method | Description |
|--------|-------------|
| `EncryptBytes(byte[])` | Encrypt plaintext bytes, returns ciphertext JSON bytes |
| `EncryptString(string)` | Encrypt a UTF-8 string, returns ciphertext JSON string |
| `EncryptBytesAsync(byte[])` | True async encrypt via tokio callback |
| `EncryptStringAsync(string)` | True async encrypt, string variant |
| `DecryptBytes(byte[])` | Decrypt ciphertext JSON bytes, returns plaintext bytes |
| `DecryptString(string)` | Decrypt ciphertext JSON string, returns plaintext string |
| `DecryptBytesAsync(byte[])` | True async decrypt via tokio callback |
| `DecryptStringAsync(string)` | True async decrypt, string variant |
| `Dispose()` | Release the native session handle |

### `AsherahConfig.Builder`

| Method | Description |
|--------|-------------|
| `WithServiceName(string)` | **Required.** Service name for key hierarchy |
| `WithProductId(string)` | **Required.** Product ID for key hierarchy |
| `WithMetastore(string)` | **Required.** `"rdbms"`, `"dynamodb"`, `"memory"` (testing) |
| `WithKms(string)` | KMS type: `"static"` (default) or `"aws"` |
| `WithExpireAfter(long?)` | Key expiration in seconds |
| `WithCheckInterval(long?)` | Revoke check interval in seconds |
| `WithConnectionString(string?)` | RDBMS connection string |
| `WithDynamoDbEndpoint(string?)` | DynamoDB endpoint URL |
| `WithDynamoDbRegion(string?)` | DynamoDB region |
| `WithDynamoDbSigningRegion(string?)` | DynamoDB signing region |
| `WithDynamoDbTableName(string?)` | DynamoDB table name |
| `WithReplicaReadConsistency(string?)` | DynamoDB read consistency |
| `WithRegionMap(IDictionary<string, string>?)` | AWS KMS region-to-ARN map |
| `WithPreferredRegion(string?)` | Preferred AWS region |
| `WithEnableRegionSuffix(bool?)` | Enable region suffix on key IDs |
| `WithEnableSessionCaching(bool?)` | Enable session caching (default: true) |
| `WithSessionCacheMaxSize(int?)` | Max cached sessions |
| `WithSessionCacheDuration(long?)` | Cache TTL in seconds |
| `WithVerbose(bool?)` | Enable verbose logging |
| `WithPoolMaxOpen(int?)` | Max open DB connections (default: 0 = unlimited) |
| `WithPoolMaxIdle(int?)` | Max idle connections to retain (default: 2) |
| `WithPoolMaxLifetime(long?)` | Max connection lifetime in seconds (default: 0 = unlimited) |
| `WithPoolMaxIdleTime(long?)` | Max idle time per connection in seconds (default: 0 = unlimited) |
| `Build()` | Build the immutable `AsherahConfig` |

## Building from Source

```bash
dotnet build asherah-dotnet/src/GoDaddy.Asherah.AppEncryption/
dotnet test asherah-dotnet/GoDaddy.Asherah.AppEncryption.slnx
```

## License

See the repository root for license information.
