# GoDaddy.Asherah.Encryption

.NET bindings for the [Asherah](https://github.com/godaddy/asherah-ffi)
envelope encryption and key rotation library. Native Rust implementation via
P/Invoke; the native binary ships in NuGet for `linux-x64`, `linux-arm64`,
`linux-musl-x64`, `linux-musl-arm64` (Alpine), `osx-x64`, `osx-arm64`,
`win-x64`, `win-arm64`.

## Installation

```bash
dotnet add package GoDaddy.Asherah.Encryption
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

Asherah uses the standard `Microsoft.Extensions.Logging` types. The
fastest path is to hand the binding your host's `ILogger` (or
`ILoggerFactory`) and let it forward records as structured events:

```csharp
using GoDaddy.Asherah;
using Microsoft.Extensions.Logging;

// In ASP.NET Core / Worker Service / generic host:
public class Startup(ILoggerFactory loggers)
{
    public void Configure()
    {
        // One ILogger is created per Asherah target (e.g. "asherah::session"),
        // so host-side filter rules can match by category.
        Asherah.SetLogHook(loggers);
    }
}

// Or with a single ILogger:
Asherah.SetLogHook(myLogger);

// later:
Asherah.ClearLogHook();
```

The raw callback API is still available for cases that don't fit the
`ILogger` model (e.g. piping to a custom backend, low-level filtering):

```csharp
Asherah.SetLogHook(evt =>
{
    // evt = LogEvent(Level, Target, Message); Level is
    // Microsoft.Extensions.Logging.LogLevel — Trace, Debug, Information,
    // Warning, or Error.
    if (evt.Level >= LogLevel.Warning)
    {
        Console.Error.WriteLine($"[asherah {evt.Level}] {evt.Message}");
    }
});

// later:
Asherah.SetLogHook((Action<LogEvent>?)null);   // or Asherah.ClearLogHook();
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
events are dropped — `Asherah.LogDroppedCount()` and
`Asherah.MetricsDroppedCount()` expose the cumulative drop count.

**Default log level is `LogLevel.Warning`.** Verbose
`Trace`/`Debug`/`Information` records from the encrypt/decrypt hot path
are filtered out at the producer thread before any allocation, so
installing a hook never floods you with noise. Pass `LogLevel.Trace`
(or any other level from `Microsoft.Extensions.Logging.LogLevel`)
explicitly via the `SetLogHook(callback, queueCapacity, minLevel)`
overload (or the `SetLogHookSync` overload) when you want the verbose
records. `LogLevel.Critical` and `LogLevel.None` are valid filter
values and translate to "deliver nothing" — Asherah's Rust source
never produces records at those severities.

**Synchronous delivery (opt-in).** For diagnostics, single-threaded apps,
or when you need thread-local context (trace IDs, request scopes) intact
in the callback, use `Asherah.SetLogHookSync(callback, minLevel)` /
`Asherah.SetMetricsHookSync(callback)`. The callback fires **on the
encrypt/decrypt thread before the operation returns** — no queue, no
worker. Trade-off: a slow callback directly extends operation latency,
so make sure your handler is verifiably non-blocking before picking sync
mode in production.

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

| | Canonical (`GoDaddy.Asherah.AppEncryption@0.x`) | This repo (`GoDaddy.Asherah.Encryption`) |
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
| `WithAwsProfileName(string?)` | Optional AWS shared-credentials profile name for KMS/DynamoDB/Secrets Manager SDK clients. |
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

From the repository root:

**Debug FFI (simplest)** — test projects locate the workspace root and, when `ASHERAH_DOTNET_NATIVE` is unset, point it at `target/debug` automatically:

```bash
cargo build -p asherah-ffi
dotnet test asherah-dotnet/GoDaddy.Asherah.Encryption.slnx --nologo -p:RestoreLockedMode=true
```

**Release FFI** — use a **shell-expanded absolute path** for `ASHERAH_DOTNET_NATIVE`. A value like `target/release` alone is wrong: the binding resolves relative paths against the test process working directory, not the repo root.

```bash
cargo build --release -p asherah-ffi
ASHERAH_DOTNET_NATIVE="$(pwd)/target/release" dotnet test asherah-dotnet/GoDaddy.Asherah.Encryption.slnx --nologo -p:RestoreLockedMode=true
```

`ASHERAH_DOTNET_NATIVE` must refer to the directory containing `libasherah_ffi.dylib` / `libasherah_ffi.so` / `asherah_ffi.dll`. Without a correct path, the loader can bind a different `asherah_ffi` on `PATH` and tests may fail with missing entry points.

## License

Licensed under the Apache License, Version 2.0.
