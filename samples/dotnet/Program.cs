using System.Text;
using GoDaddy.Asherah;
using GoDaddy.Asherah.Encryption;
using Microsoft.Extensions.Logging;

// Testing only — production must use AWS KMS.
Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX",
    "2222222222222222222222222222222222222222222222222222222222222222");

var config = AsherahConfig.CreateBuilder()
    .WithServiceName("sample-service")
    .WithProductId("sample-product")
    .WithMetastore(MetastoreKind.Memory)   // testing only — use MetastoreKind.Rdbms + connection string etc. in production
    .WithKms(KmsKind.Static)               // testing only — use KmsKind.Aws with RegionMap in production
    .WithEnableSessionCaching(true)
    .Build();

// --- 1. Static API (simplest, manages sessions internally) ---

AsherahApi.Setup(config);
try
{
    // String encrypt/decrypt
    var cipher = AsherahApi.EncryptString("partition-1", "Hello from .NET!");
    Console.WriteLine($"Static string:  {AsherahApi.DecryptString("partition-1", cipher)}");

    // Byte encrypt/decrypt
    var cipherBytes = AsherahApi.Encrypt("partition-1", Encoding.UTF8.GetBytes("byte payload"));
    Console.WriteLine($"Static bytes:   {Encoding.UTF8.GetString(AsherahApi.Decrypt("partition-1", cipherBytes))}");
}
finally
{
    AsherahApi.Shutdown();
}

// --- 2. Factory/Session API (recommended — explicit session lifecycle) ---

using (var factory = AsherahFactory.FromConfig(config))
{
    using (var session = factory.GetSession("partition-2"))
    {
        var encrypted = session.EncryptString("Factory/Session example");
        Console.WriteLine($"Session string: {session.DecryptString(encrypted)}");

        var encBytes = session.EncryptBytes(Encoding.UTF8.GetBytes("session bytes"));
        Console.WriteLine($"Session bytes:  {Encoding.UTF8.GetString(session.DecryptBytes(encBytes))}");
    }
}

// --- 3. Async API (true async via Rust tokio — does not block .NET thread pool) ---

await RunAsyncExample();

static async Task RunAsyncExample()
{
    var cfg = AsherahConfig.CreateBuilder()
        .WithServiceName("sample-service")
        .WithProductId("sample-product")
        .WithMetastore(MetastoreKind.Memory)
        .WithKms(KmsKind.Static)
        .WithEnableSessionCaching(true)
        .Build();

    // Static async
    AsherahApi.Setup(cfg);
    try
    {
        var cipher = await AsherahApi.EncryptStringAsync("partition-3", "async static");
        Console.WriteLine($"Async static:   {await AsherahApi.DecryptStringAsync("partition-3", cipher)}");
    }
    finally
    {
        AsherahApi.Shutdown();
    }

    // Session async
    using var factory = AsherahFactory.FromConfig(cfg);
    using var session = factory.GetSession("partition-4");
    var enc = await session.EncryptBytesAsync(Encoding.UTF8.GetBytes("async session"));
    Console.WriteLine($"Async session:  {Encoding.UTF8.GetString(await session.DecryptBytesAsync(enc))}");
}

// --- 4. Log hook (observability) ---
// Receives every log event from the Rust core. Use with verbose: true to
// see info/debug-level setup messages, or always-on for warn/error.

var logEvents = new System.Collections.Concurrent.ConcurrentBag<LogEvent>();
AsherahHooks.SetLogHook(e =>
{
    if (e.Level == LogLevel.Warning || e.Level == LogLevel.Error)
    {
        Console.WriteLine($"[log] {e.Level}: {e.Message}");
    }
    logEvents.Add(e);
});

var verboseConfig = AsherahConfig.CreateBuilder()
    .WithServiceName("sample-service")
    .WithProductId("sample-product")
    .WithMetastore(MetastoreKind.Memory)
    .WithKms(KmsKind.Static)
    .WithVerbose(true)
    .Build();

AsherahApi.Setup(verboseConfig);
AsherahApi.EncryptString("partition-5", "with-log-hook");
AsherahApi.Shutdown();
Console.WriteLine($"[log] received {logEvents.Count} log events total");
AsherahHooks.SetLogHook((Action<LogEvent>?)null);

// --- 5. Metrics hook (observability) ---
// Receives encrypt/decrypt/store/load timings plus key cache hit/miss/stale.

var metricCounts = new System.Collections.Concurrent.ConcurrentDictionary<MetricsEventType, int>();
AsherahHooks.SetMetricsHook(e =>
{
    metricCounts.AddOrUpdate(e.Type, 1, (_, c) => c + 1);
});

AsherahApi.Setup(config);
for (int i = 0; i < 5; i++)
{
    var ct = AsherahApi.EncryptString("metrics-test", $"payload-{i}");
    AsherahApi.DecryptString("metrics-test", ct);
}
AsherahApi.Shutdown();
Console.WriteLine($"[metrics] {string.Join(", ", metricCounts.Select(kv => $"{kv.Key}={kv.Value}"))}");
AsherahHooks.SetMetricsHook((Action<MetricsEvent>?)null);

// --- 6. Production config (uncomment and fill in real values) ---
//
// var prodConfig = AsherahConfig.CreateBuilder()
//     .WithServiceName("my-service")
//     .WithProductId("my-product")
//     .WithMetastore(MetastoreKind.Rdbms)
//     .WithConnectionString("server=db.example.com;database=asherah;user=app;password=secret")
//     .WithKms(KmsKind.Aws)
//     .WithRegionMap(new Dictionary<string, string>
//     {
//         ["us-west-2"] = "arn:aws:kms:us-west-2:111122223333:key/example-key-id",
//     })
//     .WithPreferredRegion("us-west-2")
//     .WithEnableSessionCaching(true)
//     .WithSessionCacheMaxSize(1000)
//     .WithSessionCacheDuration(TimeSpan.FromSeconds(120))
//     .Build();
