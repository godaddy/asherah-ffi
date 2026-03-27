using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using GoDaddy.Asherah.AppEncryption;

BenchmarkRunner.Run<CanonicalBenchmark>(
    DefaultConfig.Instance
        .AddColumn(StatisticColumn.Median)
        .WithOptions(ConfigOptions.DisableOptimizationsValidator));

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80, warmupCount: 3, iterationCount: 10)]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
public class CanonicalBenchmark
{
    private const string StaticMasterKey = "thisIsAStaticMasterKeyForTesting";
    private const string ServiceName = "bench-service";
    private const string ProductId = "bench-product";
    private const string PartitionId = "bench-partition";

    private SessionFactory _factory = null!;
    private Session<byte[], byte[]> _session = null!;
    private byte[] _payload = null!;
    private byte[] _ciphertext = null!;

    [Params(64, 1024, 8192)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _factory = SessionFactory
            .NewBuilder(ProductId, ServiceName)
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService(StaticMasterKey)
            .Build();
        _session = _factory.GetSessionBytes(PartitionId);

        _payload = new byte[PayloadSize];
        Random.Shared.NextBytes(_payload);
        _ciphertext = _session.Encrypt(_payload);

        var decrypted = _session.Decrypt(_ciphertext);
        if (!decrypted.AsSpan().SequenceEqual(_payload))
            throw new Exception($"Canonical C# round-trip verification failed for {PayloadSize}B");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _session?.Dispose();
        _factory?.Dispose();
    }

    [Benchmark(Description = "Canonical C# v0.2.10"), BenchmarkCategory("Encrypt")]
    public byte[] CanonicalEncrypt() => _session.Encrypt(_payload);

    [Benchmark(Description = "Canonical C# v0.2.10"), BenchmarkCategory("Decrypt")]
    public byte[] CanonicalDecrypt() => _session.Decrypt(_ciphertext);
}
