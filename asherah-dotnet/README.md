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

Targets `net8.0` and `net10.0`. Namespace: `GoDaddy.Asherah.Encryption`.

For drop-in compatibility with the canonical pure-C# `GoDaddy.Asherah.AppEncryption`
SDK (the `SessionFactory.NewBuilder()` style), install the companion compat
package which preserves the original namespace and API surface:

```bash
dotnet add package GoDaddy.Asherah.Encryption.Compat
```

The compat package is documented separately and brings `Newtonsoft.Json` /
`LanguageExt.Option` along with it for source-level parity. Use it only when
migrating existing code; new code should target `GoDaddy.Asherah.Encryption`
directly.

## Documentation

This README covers the conceptual overview, full configuration
reference, and quick-start examples. Task-oriented walkthroughs live
under `[docs/](./docs/)`:


| Guide                                                  | When to read                                                                                      |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| [Getting started](./docs/getting-started.md)           | First-time install through round-trip encrypt/decrypt.                                            |
| [Dependency injection](./docs/dependency-injection.md) | Registering Asherah types in ASP.NET Core, Worker Service, Generic Host.                          |
| [AWS production setup](./docs/aws-production-setup.md) | End-to-end production config: KMS keys, DynamoDB, IAM policy, region routing.                     |
| [Testing](./docs/testing.md)                           | In-memory + static-KMS fixtures, mocking `IAsherahApi`, integration tests against MySQL/Postgres. |
| [Troubleshooting](./docs/troubleshooting.md)           | Common errors with what to check first. Search by exception type or message text.                 |


The runnable [sample app](../samples/dotnet/Program.cs) exercises
every API style plus async, log hook, and metrics hook in one
program.

## Choosing an API style

Two coexisting API styles are exposed in `GoDaddy.Asherah.Encryption`. Both
produce the same wire format and operate on the same native core; pick by
operational style, not by feature.


| Style                 | Entry point                                                      | When to use                                                                                                                                                                                     |
| --------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Single-shot**       | `AsherahApi.Setup` / `AsherahApi.Encrypt` / `AsherahApi.Decrypt` | Configure once, call encrypt/decrypt with a partition id. No factory or session lifecycle to manage. Simplest call surface.                                                                     |
| **Factory / Session** | `AsherahFactory.FromConfig(...)` / `factory.GetSession(...)`     | Explicit lifecycle, no hidden process-global singleton, `IDisposable` resource management, multi-tenant isolation is obvious in code, multiple factories with different configs in one process. |


Either style accepts the same `AsherahConfig` builder. Observability hooks
(`AsherahHooks.SetLogHook` / `SetMetricsHook`) are configured separately and
apply globally regardless of which style created the factory or session.

For DI scenarios:

- `IAsherahApi` + `AsherahApiClient` — instance-shaped wrapper for the
single-shot API.
- `IAsherahFactory` / `IAsherahSession` — interfaces on the factory/session
types.

A complete runnable example exercising both styles plus async, log hook,
and metrics hook is in
`[samples/dotnet/Program.cs](../samples/dotnet/Program.cs)`.

> **Sync vs async:** prefer sync for Asherah's hot encrypt/decrypt paths.
> The native operation is sub-microsecond — the async state-machine
> overhead (~9 µs) is larger than the work itself for in-memory and warm
> cache scenarios. Use `*Async` overloads for ASP.NET Core request
> handlers and any caller already on an async context that touches a
> network metastore (DynamoDB, MySQL, Postgres) where the I/O actually
> warrants yielding.

## Quick start (single-shot API)

```csharp
using GoDaddy.Asherah.Encryption;

Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX", new string('2', 64));

var config = AsherahConfig.CreateBuilder()
    .WithServiceName("my-service")
    .WithProductId("my-product")
    .WithMetastore("memory")  // testing only — use "rdbms" or "dynamodb" in production
    .WithKms("static")        // testing only — use "aws" in production
    .Build();

AsherahApi.Setup(config);
try
{
    var ct = AsherahApi.EncryptString("user-42", "secret");
    var pt = AsherahApi.DecryptString("user-42", ct);
}
finally
{
    AsherahApi.Shutdown();
}
```

## Quick start (factory / session API)

```csharp
using GoDaddy.Asherah.Encryption;

using var factory = AsherahFactory.FromConfig(config);
using var session = factory.GetSession("user-42");
var ct = session.EncryptString("secret");
var pt = session.DecryptString(ct);
```

`AsherahFactory.FromEnv()` is also available when configuration comes
exclusively from environment variables.

## Async API

Every sync function has a `*Async` counterpart. The work runs on the Rust
tokio runtime and completes the `Task` via `[UnmanagedCallersOnly]`
callback — the .NET ThreadPool is not blocked.

```csharp
await AsherahApi.SetupAsync(config);
var ct = await AsherahApi.EncryptStringAsync("user-42", "secret");
var pt = await AsherahApi.DecryptStringAsync("user-42", ct);
await AsherahApi.ShutdownAsync();
```


| Metastore | Async pattern                                       | Blocks ThreadPool? |
| --------- | --------------------------------------------------- | ------------------ |
| In-memory | tokio worker thread                                 | No                 |
| DynamoDB  | true async AWS SDK calls on tokio                   | No                 |
| MySQL     | `spawn_blocking` (sync driver on tokio thread pool) | No                 |
| Postgres  | `spawn_blocking` (sync driver on tokio thread pool) | No                 |


Tradeoff: ~9.8 µs async vs ~0.7 µs sync per call (hot cache, 64 B
payload). Use sync in tight loops; use async for ASP.NET Core request
handlers.

## Observability hooks

All hook registration lives on `AsherahHooks`. Hooks are process-global
and apply to every factory/session in the process regardless of which
API style (`AsherahApi` or explicit factory) created them.

### Log hook

Asherah uses the standard `Microsoft.Extensions.Logging` types. The
fastest path is to hand the binding your host's `ILogger` (or
`ILoggerFactory`) and let it forward records as structured events:

```csharp
using GoDaddy.Asherah.Encryption;
using Microsoft.Extensions.Logging;

// In ASP.NET Core / Worker Service / generic host:
public class Startup(ILoggerFactory loggers)
{
    public void Configure()
    {
        // One ILogger is created per Asherah target (e.g. "asherah::session"),
        // so host-side filter rules can match by category.
        AsherahHooks.SetLogHook(loggers);
    }
}

// Or with a single ILogger:
AsherahHooks.SetLogHook(myLogger);

// later:
AsherahHooks.ClearLogHook();
```

The raw callback API is still available for cases that don't fit the
`ILogger` model (e.g. piping to a custom backend, low-level filtering):

```csharp
AsherahHooks.SetLogHook(evt =>
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
AsherahHooks.SetLogHook((Action<LogEvent>?)null);   // or AsherahHooks.ClearLogHook();
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
events are dropped — `AsherahHooks.LogDroppedCount()` and
`AsherahHooks.MetricsDroppedCount()` expose the cumulative drop count.

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
in the callback, use `AsherahHooks.SetLogHookSync(callback, minLevel)` /
`AsherahHooks.SetMetricsHookSync(callback)`. The callback fires **on the
encrypt/decrypt thread before the operation returns** — no queue, no
worker. Trade-off: a slow callback directly extends operation latency,
so make sure your handler is verifiably non-blocking before picking sync
mode in production.

### Metrics hook

Receive timing events for encrypt/decrypt/store/load and counter events
for cache hit/miss/stale.

```csharp
AsherahHooks.SetMetricsHook(evt =>
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
AsherahHooks.SetMetricsHook(null);   // or AsherahHooks.ClearMetricsHook();
```

Metrics collection is enabled automatically when a hook is installed
and disabled when cleared.

`AsherahHooks.SetMetricsHook(Meter)` is also available — it creates
standard `System.Diagnostics.Metrics` instruments
(`asherah.encrypt.duration` etc.) on the supplied `Meter` for use with
OpenTelemetry / Prometheus / Application Insights exporters.

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

- `null` → `ArgumentNullException` (sync) / rejected `Task` (async).
- Empty `string` / `byte[]` → `AsherahException` with the message
`"decrypt: ciphertext is empty (expected a DataRowRecord JSON envelope)"`.
Rejected at the C# boundary before any FFI call so callers get a
clear, actionable error instead of the forwarded Rust serde
diagnostic. The async overloads surface the empty-input error as a
faulted `Task`.

**Do not short-circuit empty plaintext encryption in caller code** —
empty data is real data, encrypting it produces a genuine envelope, and
skipping encryption leaks the fact that the value was empty. See
[docs/input-contract.md](../docs/input-contract.md) for the full
rationale.

## Migration

### From canonical `GoDaddy.Asherah.AppEncryption` v0.x

The companion `GoDaddy.Asherah.Encryption.Compat` package preserves the
canonical namespace `GoDaddy.Asherah.AppEncryption` and the
`SessionFactory.NewBuilder()` builder API. Reference that package for
zero-code-change migration:

```csharp
// Existing canonical code — unchanged after switching the package reference:
using GoDaddy.Asherah.AppEncryption;

using var sessionFactory = SessionFactory.NewBuilder("product", "service")
    .WithInMemoryMetastore()
    .WithCryptoPolicy(policy)
    .WithKeyManagementService(kms)
    .Build();
using var session = sessionFactory.GetSessionBytes("partition-id");
var ct = session.Encrypt(payload);
var pt = session.Decrypt(ct);
```

For new code, target `GoDaddy.Asherah.Encryption` directly using either
the single-shot `AsherahApi` or the factory/session pattern above.


|                               | Canonical (`GoDaddy.Asherah.AppEncryption@0.x`)    | This repo (`GoDaddy.Asherah.Encryption`)                         |
| ----------------------------- | -------------------------------------------------- | ---------------------------------------------------------------- |
| Implementation                | Pure C# / Bouncy Castle                            | Native Rust via P/Invoke                                         |
| Performance                   | ~50 µs encrypt                                     | ~0.7 µs encrypt                                                  |
| Async                         | Sync only                                          | Native async via tokio callbacks                                 |
| Hooks                         | Not exposed                                        | `AsherahHooks.SetLogHook`, `SetMetricsHook`                      |
| Null partition                | Silently accepted, persists `_IK__service_product` | `ArgumentNullException` (intentional hardening)                  |
| Newtonsoft.Json / LanguageExt | Required                                           | Not required (only the `Compat` package transitively pulls them) |


### Earlier preview namespace `GoDaddy.Asherah`

Earlier preview builds of this package exposed types under namespace
`GoDaddy.Asherah` and a static class also named `Asherah`. Both moved:

```diff
-using GoDaddy.Asherah;
-Asherah.Setup(config);
-var ct = Asherah.EncryptString("user-42", "secret");
-Asherah.SetLogHook(myLogger);
-using var factory = Asherah.FactoryFromConfig(config);
+using GoDaddy.Asherah.Encryption;
+AsherahApi.Setup(config);
+var ct = AsherahApi.EncryptString("user-42", "secret");
+AsherahHooks.SetLogHook(myLogger);
+using var factory = AsherahFactory.FromConfig(config);
```

Map of preview names → current names:


| Preview                                                              | Current                                                           |
| -------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `GoDaddy.Asherah` (namespace)                                        | `GoDaddy.Asherah.Encryption`                                      |
| `Asherah.Setup` / `Shutdown` / `Encrypt` / `Decrypt` / `SetEnv` etc. | `AsherahApi.Setup` / `Shutdown` / `Encrypt` / …                   |
| `Asherah.FactoryFromConfig(config)`                                  | `AsherahFactory.FromConfig(config)`                               |
| `Asherah.FactoryFromEnv()`                                           | `AsherahFactory.FromEnv()`                                        |
| `Asherah.SetLogHook` / `SetMetricsHook` / `ClearLogHook` / …         | `AsherahHooks.SetLogHook` / `SetMetricsHook` / `ClearLogHook` / … |
| `IAsherah` / `AsherahClient`                                         | `IAsherahApi` / `AsherahApiClient`                                |


## Configuration

Build a config with the fluent `AsherahConfig.CreateBuilder()`. Pass it
to `AsherahApi.Setup()`, `AsherahApi.SetupAsync()`, or
`AsherahFactory.FromConfig()`.


| Builder method                               | Description                                                                                |
| -------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `WithServiceName(string)`                    | **Required.** Service identifier for the key hierarchy.                                    |
| `WithProductId(string)`                      | **Required.** Product identifier for the key hierarchy.                                    |
| `WithMetastore(string)`                      | **Required.** `"memory"` (testing), `"rdbms"`, or `"dynamodb"`.                            |
| `WithKms(string)`                            | `"static"` (default; testing) or `"aws"`.                                                  |
| `WithConnectionString(string?)`              | SQL connection string for `"rdbms"`.                                                       |
| `WithSqlMetastoreDbType(string?)`            | `"mysql"` or `"postgres"`.                                                                 |
| `WithEnableSessionCaching(bool?)`            | Cache `AsherahSession` by partition. Default `true`.                                       |
| `WithSessionCacheMaxSize(int?)`              | Max cached sessions. Default 1000.                                                         |
| `WithSessionCacheDuration(long?)`            | Session cache TTL in seconds.                                                              |
| `WithRegionMap(IDictionary<string,string>?)` | AWS KMS multi-region key-ARN map.                                                          |
| `WithPreferredRegion(string?)`               | Preferred AWS region from `RegionMap`.                                                     |
| `WithAwsProfileName(string?)`                | Optional AWS shared-credentials profile name for KMS/DynamoDB/Secrets Manager SDK clients. |
| `WithEnableRegionSuffix(bool?)`              | Append AWS region suffix to key IDs.                                                       |
| `WithExpireAfter(long?)`                     | Intermediate-key expiration in seconds. Default 90 days.                                   |
| `WithCheckInterval(long?)`                   | Revoke-check interval in seconds. Default 60 minutes.                                      |
| `WithDynamoDbEndpoint(string?)`              | DynamoDB endpoint URL (for local DynamoDB).                                                |
| `WithDynamoDbRegion(string?)`                | AWS region for DynamoDB.                                                                   |
| `WithDynamoDbSigningRegion(string?)`         | Region used for SigV4 signing.                                                             |
| `WithDynamoDbTableName(string?)`             | DynamoDB table name.                                                                       |
| `WithReplicaReadConsistency(string?)`        | Aurora MySQL replica consistency: `"eventual"`, `"global"`, or `"session"`.                |
| `WithVerbose(bool?)`                         | Emit verbose log events from the Rust core (use a log hook to consume).                    |
| `WithPoolMaxOpen(int?)`                      | Max open DB connections (0 = unlimited).                                                   |
| `WithPoolMaxIdle(int?)`                      | Max idle DB connections to retain.                                                         |
| `WithPoolMaxLifetime(long?)`                 | Max connection lifetime in seconds (0 = unlimited).                                        |
| `WithPoolMaxIdleTime(long?)`                 | Max idle time in seconds per connection (0 = unlimited).                                   |


### Environment variables


| Variable                | Effect                                                    |
| ----------------------- | --------------------------------------------------------- |
| `STATIC_MASTER_KEY_HEX` | 64 hex chars (32 bytes) for static KMS. **Testing only.** |
| `ASHERAH_DOTNET_NATIVE` | Override the native binary search path (used by tests).   |


### AWS credentials

The C# layer does not resolve AWS credentials. The Rust core uses the
[AWS SDK for Rust](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/credentials.html)
default credential chain: environment variables, shared config / credentials
files, AWS SSO, IAM roles for ECS tasks, EC2 instance metadata. SSO profiles
configured via `aws sso login` are picked up automatically — no additional
.NET-side configuration is required.

## Performance

Native Rust via P/Invoke. Typical latencies on Apple M4 Max (in-memory
metastore, session caching enabled, 64-byte payload):


| Operation | Sync    | Async   |
| --------- | ------- | ------- |
| Encrypt   | ~0.7 µs | ~9.8 µs |
| Decrypt   | ~0.9 µs | ~9.8 µs |


See `scripts/benchmark.sh` for head-to-head comparisons with the
canonical pure-C# implementation.

## API Reference

> Full XML doc comments live on every public type and member. They
> surface in IntelliSense / IDE hover and in the generated XML doc file.
> The tables below summarize each API; the source XML docs are the
> source of truth.

### `AsherahApi` (static class — single-shot convenience)

#### Lifecycle


| Method                                 | Description                                                           |
| -------------------------------------- | --------------------------------------------------------------------- |
| `Setup(AsherahConfig)`                 | Initialize the process-global instance. Throws if already configured. |
| `SetupAsync(AsherahConfig)`            | Async variant. Returns `Task`.                                        |
| `Shutdown()`                           | Tear down the process-global instance. Idempotent.                    |
| `ShutdownAsync()`                      | Async variant. Returns `Task`.                                        |
| `GetSetupStatus()`                     | `bool` — true after `Setup()` and before `Shutdown()`.                |
| `SetEnv(IDictionary<string, string?>)` | Apply env vars before `Setup()`.                                      |


#### Encrypt / decrypt


| Method                                       | Param 1              | Param 2             | Returns                   |
| -------------------------------------------- | -------------------- | ------------------- | ------------------------- |
| `Encrypt(partitionId, plaintext)`            | `string` (non-empty) | `byte[]` (empty OK) | `byte[]` (DRR JSON bytes) |
| `EncryptAsync(partitionId, plaintext)`       | `string`             | `byte[]`            | `Task<byte[]>`            |
| `EncryptString(partitionId, plaintext)`      | `string`             | `string` (empty OK) | `string` (DRR JSON)       |
| `EncryptStringAsync(partitionId, plaintext)` | `string`             | `string`            | `Task<string>`            |
| `Decrypt(partitionId, drr)`                  | `string`             | `byte[]`            | `byte[]`                  |
| `DecryptJson(partitionId, drr)`              | `string`             | `string`            | `byte[]`                  |
| `DecryptString(partitionId, drr)`            | `string`             | `string`            | `string`                  |
| `DecryptAsync(partitionId, drr)`             | `string`             | `byte[]`            | `Task<byte[]>`            |
| `DecryptStringAsync(partitionId, drr)`       | `string`             | `string`            | `Task<string>`            |


### Factory / Session API

#### `AsherahFactory : IAsherahFactory, IDisposable`


| Member                                            | Description                                                     |
| ------------------------------------------------- | --------------------------------------------------------------- |
| `static AsherahFactory.FromConfig(AsherahConfig)` | Construct a factory from an explicit config.                    |
| `static AsherahFactory.FromEnv()`                 | Construct a factory from environment variables.                 |
| `factory.GetSession(string partitionId)`          | Get a per-partition session. Throws on null/empty partition.    |
| `factory.Dispose()`                               | Release native resources. After dispose, `GetSession()` throws. |


#### `AsherahSession : IAsherahSession, IDisposable`


| Member                                                     | Description                                          |
| ---------------------------------------------------------- | ---------------------------------------------------- |
| `EncryptBytes(byte[])`                                     | `byte[]` → DRR JSON bytes. Empty `byte[]` is valid.  |
| `EncryptString(string)`                                    | `string` → DRR JSON string. Empty `string` is valid. |
| `EncryptBytesAsync(byte[])` / `EncryptStringAsync(string)` | True async via tokio callback.                       |
| `DecryptBytes(byte[])` / `DecryptString(string)`           | DRR → plaintext.                                     |
| `DecryptBytesAsync(...)` / `DecryptStringAsync(...)`       | Async variants.                                      |
| `Dispose()`                                                | Release native resources.                            |


### `AsherahHooks` (static class — observability)


| Method                                                                           | Description                                                            |
| -------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `SetLogHook(Action<LogEvent>?)`                                                  | Register a structured-event log callback. Pass `null` to deregister.   |
| `SetLogHook(Action<LogEvent>?, int queueCapacity, LogLevel minLevel)`            | Configurable variant: queue size + producer-side level filter.         |
| `SetLogHook(ILogger)` / `SetLogHook(ILoggerFactory)`                             | Bridge to `Microsoft.Extensions.Logging`.                              |
| `SetLogHookSync(Action<LogEvent>?, LogLevel minLevel = Warning)`                 | Synchronous variant; fires on the encrypt/decrypt thread.              |
| `SetLogHookSync(ILogger, LogLevel)` / `SetLogHookSync(ILoggerFactory, LogLevel)` | Sync `ILogger` bridges.                                                |
| `ClearLogHook()`                                                                 | Convenience for `SetLogHook(null)`.                                    |
| `LogDroppedCount()`                                                              | Cumulative count of log records dropped due to a full queue.           |
| `SetMetricsHook(Action<MetricsEvent>?)`                                          | Register a metrics callback. Pass `null` to deregister.                |
| `SetMetricsHook(Action<MetricsEvent>?, int queueCapacity)`                       | Configurable variant.                                                  |
| `SetMetricsHook(Meter)`                                                          | Bridge to `System.Diagnostics.Metrics` — creates standard instruments. |
| `SetMetricsHookSync(Action<MetricsEvent>?)` / `SetMetricsHookSync(Meter)`        | Synchronous variants.                                                  |
| `ClearMetricsHook()`                                                             | Convenience for `SetMetricsHook(null)`.                                |
| `MetricsDroppedCount()`                                                          | Cumulative count of metrics events dropped due to a full queue.        |


### Observability types

```csharp
// Microsoft.Extensions.Logging.LogLevel is reused directly.
public sealed record LogEvent(LogLevel Level, string Target, string Message);

public enum MetricsEventType
{
    Encrypt, Decrypt, Store, Load,
    CacheHit, CacheMiss, CacheStale,
}
public sealed record MetricsEvent(MetricsEventType Type, ulong DurationNs, string? Name);
```

### `IAsherahApi` / `AsherahApiClient`

`IAsherahApi` exposes the single-shot API surface as an instance
interface for DI; `AsherahApiClient` implements it by forwarding to the
`AsherahApi` static class. Includes `SetLogHook` / `SetMetricsHook` for
parity (those forward to `AsherahHooks` internally).

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