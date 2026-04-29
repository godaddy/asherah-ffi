# Getting started

Step-by-step walkthrough from `dotnet add package` to a round-trip
encrypt/decrypt. After this guide, see:

- [`dependency-injection.md`](./dependency-injection.md) — DI patterns
  for ASP.NET Core / Worker Service / Generic Host.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  configuration with AWS KMS and DynamoDB.
- [`testing.md`](./testing.md) — testing strategies (in-memory
  metastore, static KMS, fixtures, mocking `IAsherahApi`).
- [`troubleshooting.md`](./troubleshooting.md) — common errors and
  fixes.

## 1. Install the package

```bash
dotnet add package GoDaddy.Asherah.Encryption
```

Targets `net8.0` and `net10.0`. Native binaries for Linux x64/arm64
(glibc + musl), macOS x64/arm64, and Windows x64/arm64 ship with the
package.

## 2. Pick an API style

Two coexisting API surfaces — same wire format, same native core:

| Style | Class | Use when |
|---|---|---|
| Single-shot | `AsherahApi` | Configure once, encrypt/decrypt with a partition id. No factory or session lifecycle to manage. |
| Factory / Session | `AsherahFactory` + `AsherahSession` | Explicit lifecycle, multiple factories with different configs in one process, `IDisposable` ownership. |

There's no functional difference — the single-shot API is a thin
convenience wrapper over the factory/session API. Pick by which one
reads better at your call sites.

## 3. Build a configuration

Both styles take an `AsherahConfig`:

```csharp
using GoDaddy.Asherah.Encryption;

// Testing-only static master key. Production must use AWS KMS;
// see aws-production-setup.md.
Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX",
    new string('2', 64));

var config = AsherahConfig.CreateBuilder()
    .WithServiceName("my-service")
    .WithProductId("my-product")
    .WithMetastore(MetastoreKind.Memory)  // testing only
    .WithKms(KmsKind.Static)              // testing only
    .Build();
```

`ServiceName` and `ProductId` form the prefix for generated
intermediate-key IDs. Pick values that uniquely identify your
application — changing them later orphans existing envelope keys (the
old keys remain in the metastore but can no longer be looked up).

For a complete table of every builder option with descriptions, see
the **Configuration** section of the [main README](../README.md#configuration).

## 4. Encrypt and decrypt — single-shot API

```csharp
AsherahApi.Setup(config);
try
{
    var ciphertext = AsherahApi.EncryptString("user-42", "secret");
    // Persist `ciphertext` to your storage layer (database column,
    // queue payload, file, etc.).

    // Later, after reading `ciphertext` back:
    var plaintext = AsherahApi.DecryptString("user-42", ciphertext);
    Console.WriteLine(plaintext);   // "secret"
}
finally
{
    AsherahApi.Shutdown();
}
```

`Setup` configures the process-global instance — call it once at
startup. `Shutdown` releases resources — call it once at shutdown.
Sessions are cached internally per partition id; the cache is sized
by `WithSessionCacheMaxSize` (default 1000) and flushed on `Shutdown`.

## 5. Encrypt and decrypt — factory / session API

```csharp
using var factory = AsherahFactory.FromConfig(config);
using var session = factory.GetSession("user-42");

var ciphertext = session.EncryptString("secret");
var plaintext = session.DecryptString(ciphertext);
```

The factory is `IDisposable` and owns native resources. Sessions are
also `IDisposable` and shareable across threads. Session caching is
on by default — `factory.GetSession("user-42")` returns the same
session instance until it's evicted by LRU pressure or the cache is
flushed.

## 6. Async API

Every sync method has a `*Async` counterpart that runs on the Rust
tokio runtime — the .NET ThreadPool is not blocked while the
metastore or KMS is I/O-bound:

```csharp
await AsherahApi.SetupAsync(config);

var ciphertext = await AsherahApi.EncryptStringAsync("user-42", "secret");
var plaintext = await AsherahApi.DecryptStringAsync("user-42", ciphertext);

await AsherahApi.ShutdownAsync();
```

> **Sync vs async:** prefer sync for Asherah's hot encrypt/decrypt
> paths. The native operation is sub-microsecond — async state-machine
> overhead (~9 µs) is larger than the work itself for in-memory and
> warm cache scenarios. Use `*Async` for ASP.NET Core request handlers
> and any caller already on an async context that touches a network
> metastore (DynamoDB, MySQL, Postgres) where the I/O actually
> warrants yielding.

## 7. Wire up observability

`AsherahHooks` exposes log and metrics hooks that apply globally
regardless of which API style you used:

```csharp
using Microsoft.Extensions.Logging;
using System.Diagnostics.Metrics;

// Log records → Microsoft.Extensions.Logging.
AsherahHooks.SetLogHook(myLoggerFactory);

// Metrics events → System.Diagnostics.Metrics.Meter.
var meter = new Meter("MyApp.Asherah");
AsherahHooks.SetMetricsHook(meter);
```

Wire `myLoggerFactory` and `meter` into your existing observability
stack (Serilog, OpenTelemetry, Application Insights, Prometheus —
anything that consumes those .NET interfaces).

The metrics bridge creates standard instruments
(`asherah.encrypt.duration`, `asherah.decrypt.duration`,
`asherah.cache.hits`, etc.) on the `Meter` automatically — no
hand-written instrument registration.

## 8. Move to production

The example above uses `MetastoreKind.Memory` and `KmsKind.Static` —
both **testing only**. Memory metastore loses keys on process restart;
static KMS uses a hardcoded master key. For real deployments, follow
[`aws-production-setup.md`](./aws-production-setup.md).

## 9. Handle errors

Asherah surfaces three exception types from public APIs:

| Exception | When |
|---|---|
| `ArgumentNullException` | `null` passed where a value is required. Programming error. |
| `InvalidOperationException` | Lifecycle violation (`Setup` called twice, ops before `Setup`, empty partition id). |
| `AsherahException` | Wraps errors from the native core: KMS failures, metastore errors, decrypt failures, malformed envelopes. |

Specific error shapes and what to check first are in
[`troubleshooting.md`](./troubleshooting.md).

## What's next

- [`dependency-injection.md`](./dependency-injection.md) — register
  Asherah types in your host's DI container.
- [`aws-production-setup.md`](./aws-production-setup.md) — production
  config from KMS key creation through IAM policy.
- The complete [sample app](../../samples/dotnet/Program.cs) exercises
  every API style + async + log hook + metrics hook in one runnable
  program.
