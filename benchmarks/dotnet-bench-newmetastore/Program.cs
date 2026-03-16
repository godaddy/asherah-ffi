using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using GoDaddy.Asherah.AppEncryption.Core;
using GoDaddy.Asherah.AppEncryption.PlugIns.Testing.Kms;
using GoDaddy.Asherah.AppEncryption.PlugIns.Testing.Metastore;
using GoDaddy.Asherah.Crypto;
using Microsoft.Extensions.Logging.Abstractions;

BenchmarkRunner.Run<NewMetastoreBenchmark>(
    DefaultConfig.Instance
        .AddColumn(StatisticColumn.Median)
        .WithOptions(ConfigOptions.DisableOptimizationsValidator));

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80, warmupCount: 3, iterationCount: 10)]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
public class NewMetastoreBenchmark
{
    private const string StaticMasterKey = "thisIsAStaticMasterKeyForTesting";
    private const string ServiceName = "bench-service";
    private const string ProductId = "bench-product";
    private const string PartitionId = "bench-partition";

    private SessionFactory _factory = null!;
    private IEncryptionSession _session = null!;
    private byte[] _payload = null!;
    private byte[] _ciphertext = null!;

    [Params(64, 1024, 8192)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _factory = (SessionFactory)SessionFactory
            .NewBuilder(ProductId, ServiceName)
            .WithKeyMetastore(new InMemoryKeyMetastore())
            .WithCryptoPolicy(new NeverExpiredCryptoPolicy())
            .WithKeyManagementService(new StaticKeyManagementService(StaticMasterKey))
            .WithLogger(NullLogger.Instance)
            .Build();
        _session = _factory.GetSession(PartitionId);

        _payload = new byte[PayloadSize];
        Random.Shared.NextBytes(_payload);
        _ciphertext = _session.Encrypt(_payload);

        // Verify round-trip correctness before benchmarking
        var decrypted = _session.Decrypt(_ciphertext);
        if (!decrypted.AsSpan().SequenceEqual(_payload))
            throw new Exception($"Round-trip verification failed for {PayloadSize}B");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _session?.Dispose();
        _factory?.Dispose();
    }

    // BenchmarkDotNet consumes the return value, preventing DCE.

    [Benchmark(Description = "C# new-metastore"), BenchmarkCategory("Encrypt")]
    public byte[] Encrypt() => _session.Encrypt(_payload);

    [Benchmark(Description = "C# new-metastore"), BenchmarkCategory("Decrypt")]
    public byte[] Decrypt() => _session.Decrypt(_ciphertext);
}
