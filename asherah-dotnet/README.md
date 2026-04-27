# GoDaddy.Asherah.AppEncryption

.NET bindings for the [Asherah](https://github.com/godaddy/asherah-ffi)
envelope encryption and key rotation library. Native Rust implementation via
P/Invoke; the native binary ships in NuGet for `linux-x64`, `linux-arm64`,
`osx-x64`, `osx-arm64`, `win-x64`, `win-arm64`.

## Installation

```bash
dotnet add package GoDaddy.Asherah.AppEncryption
```

Targets `net8.0` and `net10.0`.

## Choosing an API style

Two API styles are exposed; both are fully supported and produce the same
wire format. New code should prefer the **Factory / Session API**.

| Style | When to use |
|---|---|
| **Static** (`Asherah.Setup`, `Asherah.Encrypt`, …) | Drop-in compatibility with the canonical `GoDaddy.Asherah.AppEncryption` v0.x. Simplest call surface. Singleton lifecycle (`Setup()` once, `Shutdown()` once). |
| **Factory / Session** (`Asherah.FactoryFromConfig(...)`, `factory.GetSession(...)`) | Recommended for new code. Explicit lifecycle, no hidden singleton, `IDisposable` resource management, multi-tenant isolation is obvious in code. |

Also exposed via the `IAsherah` / `IAsherahFactory` / `IAsherahSession`
interfaces for DI. The `AsherahClient` class implements `IAsherah` over
the static API for callers who want to inject the static surface.

A complete runnable example exercising both styles plus async, log hook,
and metrics hook is in
[`samples/dotnet/Program.cs`](../samples/dotnet/Program.cs).

## Quick start (static API)

```csharp
using GoDaddy.Asherah;

Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX", new string('2', 64));

var config = AsherahConfig.CreateBuilder()
    .WithServiceName("my-service")
    .WithProductId("my-product")
    .WithMetastore("memory")  // testing only — use "rdbms" or "dynamodb" in production
    .WithKms("static")        // testing only — use "aws" in production
    .Build();

Asherah.Setup(config);
try
{
    var ct = Asherah.EncryptString("user-42", "secret");
    var pt = Asherah.DecryptString("user-42", ct);
}
finally
{
    Asherah.Shutdown();
}
```

## Quick start (factory / session API)

```csharp
using var factory = Asherah.FactoryFromConfig(config);
using var session = factory.GetSession("user-42");
var ct = session.EncryptString("secret");
var pt = session.DecryptString(ct);
```

## Async API

Every sync function has a `*Async` counterpart. The work runs on the Rust
tokio runtime and completes the `Task` via `[UnmanagedCallersOnly]`
callback — the .NET ThreadPool is not blocked.

```csharp
await Asherah.SetupAsync(config);
var ct = await Asherah.EncryptStringAsync("user-42", "secret");
var pt = await Asherah.DecryptStringAsync("user-42", ct);
await Asherah.ShutdownAsync();
```

| Metastore | Async pattern | Blocks ThreadPool? |
|-----------|--------------|-------------------|
| In-memory | tokio worker thread | No |
| DynamoDB  | true async AWS SDK calls on tokio | No |
| MySQL     | `spawn_blocking` (sync driver on tokio thread pool) | No |
| Postgres  | `spawn_blocking` (sync driver on tokio thread pool) | No |

Tradeoff: ~9.8 µs async vs ~0.7 µs sync per call (hot cache, 64 B
payload). Use sync in tight loops; use async for ASP.NET Core request
handlers.

## Observability hooks

### Log hook

Receive every log event from the Rust core (encrypt/decrypt path,
metastore drivers, KMS clients). Pass `null` to deregister.

```csharp
using GoDaddy.Asherah;

Asherah.SetLogHook(evt =>
{
    // evt = LogEvent(Level, Target, Message)
    if (evt.Level == LogLevel.Warn || evt.Level == LogLevel.Error)
    {
        Console.Error.WriteLine($"[asherah {evt.Level}] {evt.Message}");
    }
});

// later:
Asherah.SetLogHook(null);   // or Asherah.ClearLogHook();
```

Callbacks may fire from any thread (Rust tokio worker threads, DB
driver threads). The trampoline catches every exception thrown by your
callback so a faulty hook cannot crash the process — log it via your
own observability tooling.

**Async delivery + bounded queue.** Log and metrics events are buffered
in a process-wide MPSC channel (default capacity 4096) and delivered to
your callback by a dedicated worker thread. The encrypt/decrypt hot path
performs only a level check + non-blocking channel send, so a slow
callback never extends an encrypt's latency. When the queue is full,
events are dropped — `Asherah.LogDroppedCount` and
`Asherah.MetricsDroppedCount` expose the cumulative drop count. To tune
the queue size or filter to a minimum log level (e.g. only deliver
`Warn`+ to skip the verbose debug records), use the
`SetLogHook(callback, queueCapacity, minLevel)` overload.

### Metrics hook

Receive timing events for encrypt/decrypt/store/load and counter events
for cache hit/miss/stale.

```csharp
Asherah.SetMetricsHook(evt =>
{
    switch (evt.Type)
    {
        case MetricsEventType.Encrypt:
        case MetricsEventType.Decrypt:
        case MetricsEventType.Store:
        case MetricsEventType.Load:
            // evt.DurationNs holds the elapsed time in nanoseconds
            myHistogram.Observe(evt.Type.ToString(), evt.DurationNs / 1e6);
            break;
        case MetricsEventType.CacheHit:
        case MetricsEventType.CacheMiss:
        case MetricsEventType.CacheStale:
            // evt.Name holds the cache name
            myCounter.Inc(result: evt.Type.ToString(), cache: evt.Name);
            break;
    }
});

// later:
Asherah.SetMetricsHook(null);   // or Asherah.ClearMetricsHook();
```

Metrics collection is enabled automatically when a hook is installed
and disabled when cleared.

## Input contract

**Partition ID** (`null`, `""`): always rejected as programming errors
with `ArgumentNullException` / `InvalidOperationException`. No row is
ever written to the metastore under a degenerate partition ID.
(Canonical `GoDaddy.Asherah.AppEncryption` v0.11.0 accepts both
silently and persists `_IK__service_product` rows; this binding is
deliberately stricter.)

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

## Migration from canonical (`GoDaddy.Asherah.AppEncryption` v0.x)

Drop-in replacement for the canonical Java-style SDK. Key differences:

| | Canonical (`GoDaddy.Asherah.AppEncryption@0.x`) | This binding |
|---|---|---|
| Implementation | Pure C# / Bouncy Castle | Native Rust via P/Invoke |
| Performance | ~50 µs encrypt | ~0.7 µs encrypt |
| Async | Sync only | Native async via tokio callbacks |
| Hooks | Not exposed | `SetLogHook`, `SetMetricsHook` |
| Null partition | Silently accepted, persists `_IK__service_product` | `ArgumentNullException` (intentional hardening) |

```csharp
// Before (canonical SDK)
using var sessionFactory = SessionFactory.NewBuilder("product", "service")
    .WithInMemoryMetastore()
    .WithCryptoPolicy(policy)
    .WithKeyManagementService(kms)
    .Build();
using var session = sessionFactory.GetSessionBytes("partition-id");
var ct = session.Encrypt(payload);
var pt = session.Decrypt(ct);

// After (this binding — equivalent semantics)
using var factory = Asherah.FactoryFromConfig(
    AsherahConfig.CreateBuilder()
        .WithServiceName("service")
        .WithProductId("product")
        .WithMetastore("memory")
        .WithKms("static")
        .Build());
using var session = factory.GetSession("partition-id");
var ct = session.EncryptBytes(payload);
var pt = session.DecryptBytes(ct);
```

## Configuration

Build a config with the fluent `AsherahConfig.CreateBuilder()`. Pass it
to `Asherah.Setup()`, `Asherah.SetupAsync()`, or
`Asherah.FactoryFromConfig()`.

| Builder method | Description |
|---|---|
| `WithServiceName(string)` | **Required.** Service identifier for the key hierarchy. |
| `WithProductId(string)` | **Required.** Product identifier for the key hierarchy. |
| `WithMetastore(string)` | **Required.** `"memory"` (testing), `"rdbms"`, or `"dynamodb"`. |
| `WithKms(string)` | `"static"` (default; testing) or `"aws"`. |
| `WithConnectionString(string?)` | SQL connection string for `"rdbms"`. |
| `WithSqlMetastoreDbType(string?)` | `"mysql"` or `"postgres"`. |
| `WithEnableSessionCaching(bool?)` | Cache `AsherahSession` by partition. Default `true`. |
| `WithSessionCacheMaxSize(int?)` | Max cached sessions. Default 1000. |
| `WithSessionCacheDuration(long?)` | Session cache TTL in seconds. |
| `WithRegionMap(IDictionary<string,string>?)` | AWS KMS multi-region key-ARN map. |
| `WithPreferredRegion(string?)` | Preferred AWS region from `RegionMap`. |
| `WithEnableRegionSuffix(bool?)` | Append AWS region suffix to key IDs. |
| `WithExpireAfter(long?)` | Intermediate-key expiration in seconds. Default 90 days. |
| `WithCheckInterval(long?)` | Revoke-check interval in seconds. Default 60 minutes. |
| `WithDynamoDbEndpoint(string?)` | DynamoDB endpoint URL (for local DynamoDB). |
| `WithDynamoDbRegion(string?)` | AWS region for DynamoDB. |
| `WithDynamoDbSigningRegion(string?)` | Region used for SigV4 signing. |
| `WithDynamoDbTableName(string?)` | DynamoDB table name. |
| `WithReplicaReadConsistency(string?)` | DynamoDB consistency. |
| `WithVerbose(bool?)` | Emit verbose log events (use a log hook to consume). |
| `WithPoolMaxOpen(int?)` | Max open DB connections (0 = unlimited). |
| `WithPoolMaxIdle(int?)` | Max idle DB connections to retain. |
| `WithPoolMaxLifetime(long?)` | Max connection lifetime in seconds (0 = unlimited). |
| `WithPoolMaxIdleTime(long?)` | Max idle time in seconds per connection (0 = unlimited). |

### Environment variables

| Variable | Effect |
|---|---|
| `STATIC_MASTER_KEY_HEX` | 64 hex chars (32 bytes) for static KMS. **Testing only.** |
| `ASHERAH_DOTNET_NATIVE` | Override the native binary search path (used by tests). |

## Performance

Native Rust via P/Invoke. Typical latencies on Apple M4 Max (in-memory
metastore, session caching enabled, 64-byte payload):

| Operation | Sync | Async |
|-----------|------|-------|
| Encrypt   | ~0.7 µs | ~9.8 µs |
| Decrypt   | ~0.9 µs | ~9.8 µs |

See `scripts/benchmark.sh` for head-to-head comparisons with the
canonical pure-C# implementation.

## API Reference

> Full XML doc comments live on every public type and member. They
> surface in IntelliSense / IDE hover and in the generated XML doc file.
> The tables below summarize each API; the source XML docs are the
> source of truth.

### `Asherah` (static class — legacy compatibility)

#### Lifecycle

| Method | Description |
|---|---|
| `Setup(AsherahConfig)` | Initialize the global instance. Throws if already configured. |
| `SetupAsync(AsherahConfig)` | Async variant. Returns `Task`. |
| `Shutdown()` | Tear down the global instance. Idempotent. |
| `ShutdownAsync()` | Async variant. Returns `Task`. |
| `GetSetupStatus()` | `bool` — true after `Setup()` and before `Shutdown()`. |
| `SetEnv(IDictionary<string, string?>)` | Apply env vars before `Setup()`. |

#### Encrypt / decrypt

| Method | Param 1 | Param 2 | Returns |
|---|---|---|---|
| `Encrypt(partitionId, plaintext)` | `string` (non-empty) | `byte[]` (empty OK) | `byte[]` (DRR JSON bytes) |
| `EncryptAsync(partitionId, plaintext)` | `string` | `byte[]` | `Task<byte[]>` |
| `EncryptString(partitionId, plaintext)` | `string` | `string` (empty OK) | `string` (DRR JSON) |
| `EncryptStringAsync(partitionId, plaintext)` | `string` | `string` | `Task<string>` |
| `Decrypt(partitionId, drr)` | `string` | `byte[]` | `byte[]` |
| `DecryptJson(partitionId, drr)` | `string` | `string` | `byte[]` |
| `DecryptString(partitionId, drr)` | `string` | `string` | `string` |
| `DecryptAsync(partitionId, drr)` | `string` | `byte[]` | `Task<byte[]>` |
| `DecryptStringAsync(partitionId, drr)` | `string` | `string` | `Task<string>` |

#### Hooks

| Method | Description |
|---|---|
| `SetLogHook(Action<LogEvent>?)` | Register a structured-event log callback. Pass `null` to deregister. |
| `ClearLogHook()` | Convenience for `SetLogHook(null)`. |
| `SetMetricsHook(Action<MetricsEvent>?)` | Register a metrics callback. Pass `null` to deregister. |
| `ClearMetricsHook()` | Convenience for `SetMetricsHook(null)`. |

### Factory / Session API (recommended)

#### `AsherahFactory : IAsherahFactory, IDisposable`

| Member | Description |
|---|---|
| `Asherah.FactoryFromConfig(AsherahConfig)` | Construct a factory. |
| `Asherah.FactoryFromEnv()` | Construct from environment variables. |
| `factory.GetSession(string partitionId)` | Get a per-partition session. Throws on null/empty partition. |
| `factory.Dispose()` | Release native resources. After dispose, `GetSession()` throws. |

#### `AsherahSession : IAsherahSession, IDisposable`

| Member | Description |
|---|---|
| `EncryptBytes(byte[])` | `byte[]` → DRR JSON bytes. Empty `byte[]` is valid. |
| `EncryptString(string)` | `string` → DRR JSON string. Empty `string` is valid. |
| `EncryptBytesAsync(byte[])` / `EncryptStringAsync(string)` | True async via tokio callback. |
| `DecryptBytes(byte[])` / `DecryptString(string)` | DRR → plaintext. |
| `DecryptBytesAsync(...)` / `DecryptStringAsync(...)` | Async variants. |
| `Dispose()` | Release native resources. |

### Observability types

```csharp
public enum LogLevel { Trace, Debug, Info, Warn, Error }
public sealed record LogEvent(LogLevel Level, string Target, string Message);

public enum MetricsEventType
{
    Encrypt, Decrypt, Store, Load,
    CacheHit, CacheMiss, CacheStale,
}
public sealed record MetricsEvent(MetricsEventType Type, ulong DurationNs, string? Name);
```

### `IAsherah` / `AsherahClient`

`IAsherah` exposes the static-API surface for DI; `AsherahClient`
implements it by forwarding to the `Asherah` static class. Includes
`SetLogHook` / `SetMetricsHook` for parity.

## Building from Source

```bash
cargo build --release -p asherah-ffi
ASHERAH_DOTNET_NATIVE=target/release dotnet test asherah-dotnet/
```

## License

Licensed under the Apache License, Version 2.0.
