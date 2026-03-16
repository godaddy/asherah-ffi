using System;
using System.Diagnostics;
using GoDaddy.Asherah.AppEncryption.Core;
using GoDaddy.Asherah.AppEncryption.PlugIns.Testing.Kms;
using GoDaddy.Asherah.AppEncryption.PlugIns.Testing.Metastore;
using GoDaddy.Asherah.Crypto;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

const string StaticMasterKey = "thisIsAStaticMasterKeyForTesting";
const string ServiceName = "bench-service";
const string ProductId = "bench-product";
const string PartitionId = "bench-partition";

int[] payloadSizes = [64, 1024, 8192];
int warmupIterations = 500;
int benchIterations = 5000;

var factory = (SessionFactory)SessionFactory
    .NewBuilder(ProductId, ServiceName)
    .WithKeyMetastore(new InMemoryKeyMetastore())
    .WithCryptoPolicy(new NeverExpiredCryptoPolicy())
    .WithKeyManagementService(new StaticKeyManagementService(StaticMasterKey))
    .WithLogger(NullLogger.Instance)
    .Build();

var results = new List<(int size, double encUs, double decUs)>();

foreach (var size in payloadSizes)
{
    var payload = new byte[size];
    Random.Shared.NextBytes(payload);

    using var session = factory.GetSession(PartitionId);
    for (int i = 0; i < warmupIterations; i++)
    {
        var e = session.Encrypt(payload);
        session.Decrypt(e);
    }

    var sw = Stopwatch.StartNew();
    byte[] enc = null!;
    for (int i = 0; i < benchIterations; i++)
        enc = session.Encrypt(payload);
    sw.Stop();
    double encUs = sw.Elapsed.TotalMicroseconds / benchIterations;

    sw.Restart();
    for (int i = 0; i < benchIterations; i++)
        session.Decrypt(enc);
    sw.Stop();
    double decUs = sw.Elapsed.TotalMicroseconds / benchIterations;

    results.Add((size, encUs, decUs));
}

factory.Dispose();

Console.WriteLine("=== .NET Benchmark: Canonical C# new-metastore (chief-micco/asherah) ===\n");

Console.WriteLine($"  {"Size",6} | {"Encrypt",14} | {"Decrypt",14}");
Console.WriteLine($"  {new string('-', 6)} | {new string('-', 14)} | {new string('-', 14)}");

foreach (var (size, encUs, decUs) in results)
{
    Console.WriteLine($"  {size,5}B | {encUs,11:F2} µs | {decUs,11:F2} µs");
}

Console.WriteLine();
Console.WriteLine($"  Warmup: {warmupIterations} iterations, Benchmark: {benchIterations} iterations per operation");
