using System;
using System.Diagnostics;
using System.Text;
using GoDaddy.Asherah.AppEncryption;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.Crypto;
using Newtonsoft.Json.Linq;

const string StaticMasterKey = "thisIsAStaticMasterKeyForTesting";
const string ServiceName = "bench-service";
const string ProductId = "bench-product";
const string PartitionId = "bench-partition";

int[] payloadSizes = [64, 1024, 8192];
int warmupIterations = 500;
int benchIterations = 5000;

// ── Setup both implementations ──────────────────────────────────────

var factory = SessionFactory
    .NewBuilder(ProductId, ServiceName)
    .WithInMemoryMetastore()
    .WithNeverExpiredCryptoPolicy()
    .WithStaticKeyManagementService(StaticMasterKey)
    .Build();

var config = GoDaddy.Asherah.AsherahConfig.CreateBuilder()
    .WithServiceName(ServiceName)
    .WithProductId(ProductId)
    .WithMetastore("memory")
    .WithKms("static")
    .WithEnableSessionCaching(true)
    .Build();

Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX",
    "2222222222222222222222222222222222222222222222222222222222222222");

GoDaddy.Asherah.Asherah.Setup(config);

// ── Collect results in a single pass ────────────────────────────────

var results = new List<(int size, double canonEnc, double canonDec, double rustEnc, double rustDec)>();

foreach (var size in payloadSizes)
{
    var payload = new byte[size];
    Random.Shared.NextBytes(payload);

    // ─── Canonical ───
    using var session = factory.GetSessionBytes(PartitionId);
    for (int i = 0; i < warmupIterations; i++)
    {
        var e = session.Encrypt(payload);
        session.Decrypt(e);
    }

    var sw = Stopwatch.StartNew();
    byte[] canonicalEnc = null!;
    for (int i = 0; i < benchIterations; i++)
        canonicalEnc = session.Encrypt(payload);
    sw.Stop();
    double canonEncUs = sw.Elapsed.TotalMicroseconds / benchIterations;

    sw.Restart();
    for (int i = 0; i < benchIterations; i++)
        session.Decrypt(canonicalEnc);
    sw.Stop();
    double canonDecUs = sw.Elapsed.TotalMicroseconds / benchIterations;

    // ─── Rust FFI ───
    for (int i = 0; i < warmupIterations; i++)
    {
        var e = GoDaddy.Asherah.Asherah.Encrypt(PartitionId, payload);
        GoDaddy.Asherah.Asherah.Decrypt(PartitionId, e);
    }

    sw.Restart();
    byte[] rustEnc = null!;
    for (int i = 0; i < benchIterations; i++)
        rustEnc = GoDaddy.Asherah.Asherah.Encrypt(PartitionId, payload);
    sw.Stop();
    double rustEncUs = sw.Elapsed.TotalMicroseconds / benchIterations;

    sw.Restart();
    for (int i = 0; i < benchIterations; i++)
        GoDaddy.Asherah.Asherah.Decrypt(PartitionId, rustEnc);
    sw.Stop();
    double rustDecUs = sw.Elapsed.TotalMicroseconds / benchIterations;

    results.Add((size, canonEncUs, canonDecUs, rustEncUs, rustDecUs));
}

factory.Dispose();
GoDaddy.Asherah.Asherah.Shutdown();

// ── Display results ─────────────────────────────────────────────────

Console.WriteLine("=== .NET Benchmark: Canonical C# (NuGet v0.2.10) vs Rust FFI Binding ===\n");

Console.WriteLine($"  {"Size",6} | {"Canonical Enc",14} | {"Rust FFI Enc",14} | {"Speedup",8} | {"Canonical Dec",14} | {"Rust FFI Dec",14} | {"Speedup",8}");
Console.WriteLine($"  {new string('-', 6)} | {new string('-', 14)} | {new string('-', 14)} | {new string('-', 8)} | {new string('-', 14)} | {new string('-', 14)} | {new string('-', 8)}");

foreach (var (size, canonEnc, canonDec, rustEnc, rustDec) in results)
{
    double encSpeedup = canonEnc / rustEnc;
    double decSpeedup = canonDec / rustDec;
    Console.WriteLine($"  {size,5}B | {canonEnc,11:F2} µs | {rustEnc,11:F2} µs | {encSpeedup,6:F1}x  | {canonDec,11:F2} µs | {rustDec,11:F2} µs | {decSpeedup,6:F1}x");
}

Console.WriteLine();
Console.WriteLine($"  Warmup: {warmupIterations} iterations, Benchmark: {benchIterations} iterations per operation");
