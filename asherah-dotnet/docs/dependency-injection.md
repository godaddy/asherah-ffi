# Dependency injection

How to register Asherah types in ASP.NET Core, Worker Service, and the
.NET Generic Host. Pick one of the two API styles documented in the
[main README](../README.md#choosing-an-api-style):

- **Single-shot** (`AsherahApi`) — process-global, configured once at
  startup. Inject `IAsherahApi` if you want a mock-able handle.
- **Factory / Session** (`AsherahFactory` + `AsherahSession`) — explicit
  ownership and disposal. Register the factory as a singleton; resolve
  sessions per-request or per-tenant.

Observability hooks (`AsherahHooks.SetLogHook` /
`AsherahHooks.SetMetricsHook`) are process-global and configured once
during startup regardless of which API style you choose.

## ASP.NET Core (Generic Host) — single-shot API

```csharp
using GoDaddy.Asherah.Encryption;
using Microsoft.Extensions.Logging;

var builder = WebApplication.CreateBuilder(args);

// Read config from appsettings / env (see "Production AWS setup").
var asherahConfig = AsherahConfig.CreateBuilder()
    .WithServiceName(builder.Configuration["Asherah:ServiceName"]!)
    .WithProductId(builder.Configuration["Asherah:ProductId"]!)
    .WithMetastore(MetastoreKind.DynamoDb)
    .WithDynamoDbTableName(builder.Configuration["Asherah:DynamoDbTable"]!)
    .WithDynamoDbRegion(builder.Configuration["Asherah:Region"]!)
    .WithKms(KmsKind.Aws)
    .WithRegionMap(builder.Configuration
        .GetSection("Asherah:RegionMap")
        .Get<Dictionary<string, string>>()!)
    .WithPreferredRegion(builder.Configuration["Asherah:Region"]!)
    .Build();

// Register the DI-friendly wrapper. AsherahApiClient forwards every
// call to the AsherahApi static class.
builder.Services.AddSingleton<IAsherahApi, AsherahApiClient>();

// Configure the process-global instance and observability hooks.
// AsherahApi.Setup() must be called before any IAsherahApi method is
// resolved — IHostedService.StartAsync runs before request handling.
builder.Services.AddHostedService<AsherahLifecycleHost>();

var app = builder.Build();
app.Run();

internal sealed class AsherahLifecycleHost(
    AsherahConfig config,
    ILoggerFactory loggers,
    IHostApplicationLifetime lifetime) : IHostedService
{
    public Task StartAsync(CancellationToken ct)
    {
        AsherahHooks.SetLogHook(loggers);
        AsherahApi.Setup(config);
        lifetime.ApplicationStopping.Register(AsherahApi.Shutdown);
        return Task.CompletedTask;
    }
    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
```

Inject `IAsherahApi` into your services:

```csharp
public class UserRepository(IAsherahApi asherah)
{
    public string ProtectField(string userId, string plaintext) =>
        asherah.EncryptString(userId, plaintext);

    public string UnprotectField(string userId, string ciphertextJson) =>
        asherah.DecryptString(userId, ciphertextJson);
}
```

## ASP.NET Core (Generic Host) — factory / session API

The factory is a singleton; sessions are short-lived and `IDisposable`.
Resolve sessions ad-hoc with the factory injected as a singleton:

```csharp
builder.Services.AddSingleton<AsherahFactory>(sp =>
{
    var loggers = sp.GetRequiredService<ILoggerFactory>();
    AsherahHooks.SetLogHook(loggers);
    return AsherahFactory.FromConfig(asherahConfig);
});

// Dispose the factory on shutdown.
builder.Services.AddSingleton<IHostedService, AsherahFactoryLifecycleHost>();

internal sealed class AsherahFactoryLifecycleHost(
    AsherahFactory factory,
    IHostApplicationLifetime lifetime) : IHostedService
{
    public Task StartAsync(CancellationToken ct)
    {
        lifetime.ApplicationStopping.Register(factory.Dispose);
        return Task.CompletedTask;
    }
    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
```

In services, resolve the factory and `using` a session per operation
(or per request, if the partition is request-scoped):

```csharp
public class TenantRepository(AsherahFactory factory)
{
    public string ProtectField(string tenantId, string plaintext)
    {
        using var session = factory.GetSession(tenantId);
        return session.EncryptString(plaintext);
    }
}
```

> **Session caching is on by default.** `factory.GetSession("tenant-42")`
> returns a cached session if one exists for that partition, so the
> `using var session = ...` cost is amortized to the first call per
> partition. Disable via `WithEnableSessionCaching(false)` if you need
> tests to observe per-call session creation.

## Per-request session injection

If your partition ID maps to the HTTP request (e.g. one tenant per
request), register a scoped session resolver:

```csharp
builder.Services.AddScoped<AsherahSession>(sp =>
{
    var factory = sp.GetRequiredService<AsherahFactory>();
    var http = sp.GetRequiredService<IHttpContextAccessor>();
    var tenantId = http.HttpContext?.Request.Headers["X-Tenant-Id"]
        .ToString() ?? throw new InvalidOperationException("Missing X-Tenant-Id");
    return factory.GetSession(tenantId);
});

// Don't forget to register IHttpContextAccessor.
builder.Services.AddHttpContextAccessor();
```

Then constructor-inject `AsherahSession` directly:

```csharp
public class CardController(AsherahSession session) : ControllerBase
{
    [HttpPost]
    public IActionResult Protect([FromBody] CardRequest req) =>
        Ok(new { Token = session.EncryptString(req.Pan) });
}
```

The scope's `Dispose` will dispose the session at the end of the
request — the underlying factory's session cache reuses the session on
subsequent requests for the same tenant, so this isn't a per-request
allocation in the steady state.

## Worker Service (background processing)

Same pattern as ASP.NET Core; `IHostedService` setup runs before any
worker starts. Factory/session API is preferred for workers because
each job typically runs against a single partition and exits — explicit
disposal is cleaner than the singleton lifecycle.

```csharp
public class EnvelopeWorker(AsherahFactory factory, ILogger<EnvelopeWorker> log)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var job = await DequeueJobAsync(ct);
            using var session = factory.GetSession(job.TenantId);
            var ct = await session.EncryptStringAsync(job.Payload);
            await PublishAsync(job.Id, ct);
        }
    }
}
```

## Mocking for tests

Inject `IAsherahApi` (single-shot) or build wrappers around
`AsherahFactory` for tests. See [testing.md](./testing.md) for the
in-memory + static-KMS configuration that lets tests run with no
external dependencies.

```csharp
public class UserRepositoryTests
{
    [Fact]
    public void ProtectField_RoundTripsThroughAsherah()
    {
        var asherah = Substitute.For<IAsherahApi>();
        asherah.EncryptString("user-1", "secret").Returns("ciphertext-token");
        var repo = new UserRepository(asherah);

        Assert.Equal("ciphertext-token", repo.ProtectField("user-1", "secret"));
        asherah.Received(1).EncryptString("user-1", "secret");
    }
}
```
