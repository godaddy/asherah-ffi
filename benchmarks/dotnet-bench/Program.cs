using System;
using System.IO;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
using GoDaddy.Asherah.AppEncryption;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.Crypto;
using GoDaddy.Asherah.Crypto.Engine.BouncyCastle;

BenchmarkRunner.Run<AsherahBenchmark>(
    DefaultConfig.Instance
        .WithOptions(ConfigOptions.JoinSummary)
        .AddColumn(new BenchmarkDotNet.Columns.CategoriesColumn()));

[CategoriesColumn]
[GroupBenchmarksBy(BenchmarkDotNet.Configs.BenchmarkLogicalGroupRule.ByCategory)]
[IterationCount(10)]
[WarmupCount(3)]
public class AsherahBenchmark
{
    private const string StaticMasterKey = "thisIsAStaticMasterKeyForTesting";
    private const string ServiceName = "bench-svc";
    private const string ProductId = "bench-prod";
    private const string PartitionId = "bench-partition";

    private SessionFactory _canonicalFactory = null!;
    private Session<byte[], byte[]> _canonicalSession = null!;
    private byte[] _payload = null!;
    private byte[] _canonicalCiphertext = null!;
    private byte[] _ffiCiphertext = null!;
    private bool _cold;
    private byte[]? _coldCt0;
    private byte[]? _coldCt1;
    private int _encCtr;
    private int _decCtr;

    [Params(64, 1024, 8192)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _cold = Environment.GetEnvironmentVariable("BENCH_COLD") == "1";

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
            Environment.GetEnvironmentVariable("STATIC_MASTER_KEY_HEX")
            ?? "746869734973415374617469634d61737465724b6579466f7254657374696e67");
        var metastore = Environment.GetEnvironmentVariable("BENCH_METASTORE") ?? "memory";
        var builder = GoDaddy.Asherah.AsherahConfig.CreateBuilder()
            .WithServiceName(ServiceName)
            .WithProductId(ProductId)
            .WithMetastore(metastore)
            .WithKms("static")
            .WithEnableSessionCaching(true);
        var connStr = Environment.GetEnvironmentVariable("BENCH_CONNECTION_STRING");
        if (connStr != null)
            builder.WithConnectionString(connStr);
        var checkInterval = Environment.GetEnvironmentVariable("BENCH_CHECK_INTERVAL");
        if (checkInterval != null)
            builder.WithCheckInterval(long.Parse(checkInterval));
        GoDaddy.Asherah.Asherah.Setup(builder.Build());

        // Generate payload and pre-encrypt for decrypt benchmarks
        _payload = new byte[PayloadSize];
        Random.Shared.NextBytes(_payload);

        if (_cold)
        {
            _coldCt0 = GoDaddy.Asherah.Asherah.Encrypt("cold-0", _payload);
            _coldCt1 = GoDaddy.Asherah.Asherah.Encrypt("cold-1", _payload);
            GoDaddy.Asherah.Asherah.Decrypt("cold-0", _coldCt0); // warm SK cache
        }
        else
        {
            _canonicalCiphertext = _canonicalSession.Encrypt(_payload);
            _ffiCiphertext = GoDaddy.Asherah.Asherah.Encrypt(PartitionId, _payload);

            var canonicalDecrypted = _canonicalSession.Decrypt(_canonicalCiphertext);
            if (!canonicalDecrypted.AsSpan().SequenceEqual(_payload))
                throw new Exception($"Canonical C# round-trip verification failed for {PayloadSize}B");
            var ffiDecrypted = GoDaddy.Asherah.Asherah.Decrypt(PartitionId, _ffiCiphertext);
            if (!ffiDecrypted.AsSpan().SequenceEqual(_payload))
                throw new Exception($"Rust FFI round-trip verification failed for {PayloadSize}B");
        }
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _canonicalSession?.Dispose();
        _canonicalFactory?.Dispose();
        GoDaddy.Asherah.Asherah.Shutdown();
    }

    [Benchmark(Description = "Canonical C# v0.2.10"), BenchmarkCategory("Encrypt")]
    public byte[] CanonicalEncrypt() => _canonicalSession.Encrypt(_payload);

    [Benchmark(Description = "Rust FFI"), BenchmarkCategory("Encrypt")]
    public byte[] RustFfiEncrypt()
    {
        if (_cold)
        {
            _encCtr++;
            return GoDaddy.Asherah.Asherah.Encrypt("cold-enc-" + _encCtr, _payload);
        }
        return GoDaddy.Asherah.Asherah.Encrypt(PartitionId, _payload);
    }

    [Benchmark(Description = "Canonical C# v0.2.10"), BenchmarkCategory("Decrypt")]
    public byte[] CanonicalDecrypt() => _canonicalSession.Decrypt(_canonicalCiphertext);

    [Benchmark(Description = "Rust FFI"), BenchmarkCategory("Decrypt")]
    public byte[] RustFfiDecrypt()
    {
        if (_cold)
        {
            var i = _decCtr++ % 2;
            return GoDaddy.Asherah.Asherah.Decrypt("cold-" + i, i == 0 ? _coldCt0! : _coldCt1!);
        }
        return GoDaddy.Asherah.Asherah.Decrypt(PartitionId, _ffiCiphertext);
    }
}
