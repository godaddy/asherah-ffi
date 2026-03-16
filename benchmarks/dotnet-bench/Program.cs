using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using GoDaddy.Asherah.AppEncryption;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.Crypto;

BenchmarkRunner.Run<AsherahBenchmark>(
    DefaultConfig.Instance
        .AddColumn(StatisticColumn.Median)
        .WithOptions(ConfigOptions.DisableOptimizationsValidator));

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80, warmupCount: 3, iterationCount: 10)]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
public class AsherahBenchmark
{
    private const string StaticMasterKey = "thisIsAStaticMasterKeyForTesting";
    private const string ServiceName = "bench-service";
    private const string ProductId = "bench-product";
    private const string PartitionId = "bench-partition";

    private SessionFactory _canonicalFactory = null!;
    private Session<byte[], byte[]> _canonicalSession = null!;
    private byte[] _payload = null!;
    private byte[] _canonicalCiphertext = null!;
    private byte[] _ffiCiphertext = null!;

    [Params(64, 1024, 8192)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        // Canonical C# (NuGet v0.2.10)
        _canonicalFactory = SessionFactory
            .NewBuilder(ProductId, ServiceName)
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService(StaticMasterKey)
            .Build();
        _canonicalSession = _canonicalFactory.GetSessionBytes(PartitionId);

        // Rust FFI binding — resolve native library path for BenchmarkDotNet subprocess
        var nativePath = Environment.GetEnvironmentVariable("ASHERAH_DOTNET_NATIVE");
        if (!string.IsNullOrEmpty(nativePath) && !Path.IsPathRooted(nativePath))
        {
            foreach (var candidate in new[]
            {
                Path.GetFullPath(nativePath),
                Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..", nativePath),
            })
            {
                if (Directory.Exists(candidate))
                {
                    Environment.SetEnvironmentVariable("ASHERAH_DOTNET_NATIVE", candidate);
                    break;
                }
            }
        }

        Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX",
            "2222222222222222222222222222222222222222222222222222222222222222");
        var config = GoDaddy.Asherah.AsherahConfig.CreateBuilder()
            .WithServiceName(ServiceName)
            .WithProductId(ProductId)
            .WithMetastore("memory")
            .WithKms("static")
            .WithEnableSessionCaching(true)
            .Build();
        GoDaddy.Asherah.Asherah.Setup(config);

        // Generate payload and pre-encrypt for decrypt benchmarks
        _payload = new byte[PayloadSize];
        Random.Shared.NextBytes(_payload);
        _canonicalCiphertext = _canonicalSession.Encrypt(_payload);
        _ffiCiphertext = GoDaddy.Asherah.Asherah.Encrypt(PartitionId, _payload);

        // Verify round-trip correctness before benchmarking
        var canonicalDecrypted = _canonicalSession.Decrypt(_canonicalCiphertext);
        if (!canonicalDecrypted.AsSpan().SequenceEqual(_payload))
            throw new Exception($"Canonical C# round-trip verification failed for {PayloadSize}B");
        var ffiDecrypted = GoDaddy.Asherah.Asherah.Decrypt(PartitionId, _ffiCiphertext);
        if (!ffiDecrypted.AsSpan().SequenceEqual(_payload))
            throw new Exception($"Rust FFI round-trip verification failed for {PayloadSize}B");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _canonicalSession?.Dispose();
        _canonicalFactory?.Dispose();
        GoDaddy.Asherah.Asherah.Shutdown();
    }

    // BenchmarkDotNet consumes the return value, preventing DCE.

    [Benchmark(Description = "Canonical C# v0.2.10"), BenchmarkCategory("Encrypt")]
    public byte[] CanonicalEncrypt() => _canonicalSession.Encrypt(_payload);

    [Benchmark(Description = "Rust FFI"), BenchmarkCategory("Encrypt")]
    public byte[] RustFfiEncrypt() => GoDaddy.Asherah.Asherah.Encrypt(PartitionId, _payload);

    [Benchmark(Description = "Canonical C# v0.2.10"), BenchmarkCategory("Decrypt")]
    public byte[] CanonicalDecrypt() => _canonicalSession.Decrypt(_canonicalCiphertext);

    [Benchmark(Description = "Rust FFI"), BenchmarkCategory("Decrypt")]
    public byte[] RustFfiDecrypt() => GoDaddy.Asherah.Asherah.Decrypt(PartitionId, _ffiCiphertext);
}
