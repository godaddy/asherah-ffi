using GoDaddy.Asherah;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;

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
    private const string ServiceName = "bench-service";
    private const string ProductId = "bench-product";
    private const string PartitionId = "bench-partition";
    private const int DefaultPartitionPoolSize = 2048;
    private const int DefaultWarmSessionCacheMaxSize = 4096;

    private byte[] _payload = null!;
    private byte[] _ffiCiphertext = null!;
    private string _mode = "memory";
    private string[] _ffiPartitionPool = Array.Empty<string>();
    private byte[][] _ffiCiphertextPool = Array.Empty<byte[]>();
    private int _ffiEncryptPoolIndex;
    private int _ffiDecryptPoolIndex;

    [Params(64, 1024, 8192)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _mode = ResolveMode();

        // Resolve native library path for BenchmarkDotNet subprocess
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
        var ffiBuilder = GoDaddy.Asherah.Encryption.AsherahConfig.CreateBuilder()
            .WithServiceName(ServiceName)
            .WithProductId(ProductId)
            .WithKms(KmsKind.Static)
            .WithEnableSessionCaching(_mode != "cold");

        if (_mode == "memory")
        {
            ffiBuilder.WithMetastore(MetastoreKind.Memory);
        }
        else
        {
            var mysqlUrl = ResolveMysqlUrl();
            ffiBuilder
                .WithMetastore(MetastoreKind.Rdbms)
                .WithConnectionString(mysqlUrl);
            if (_mode == "warm")
            {
                ffiBuilder.WithSessionCacheMaxSize(ReadIntWithFallback(
                    "BENCH_WARM_SESSION_CACHE_MAX",
                    DefaultWarmSessionCacheMaxSize));
            }
        }
        var config = ffiBuilder.Build();
        GoDaddy.Asherah.Encryption.AsherahApi.Setup(config);

        _payload = new byte[PayloadSize];
        Random.Shared.NextBytes(_payload);
        if (_mode is "memory" or "hot")
        {
            _ffiCiphertext = GoDaddy.Asherah.Encryption.AsherahApi.Encrypt(PartitionId, _payload);
            _ffiPartitionPool = Array.Empty<string>();
            _ffiCiphertextPool = Array.Empty<byte[]>();
        }
        else
        {
            var poolSize = ReadIntWithFallback("BENCH_PARTITION_POOL", DefaultPartitionPoolSize);
            _ffiPartitionPool = new string[poolSize];
            _ffiCiphertextPool = new byte[poolSize][];
            for (var i = 0; i < poolSize; i++)
            {
                var partition = $"bench-{_mode}-{PayloadSize}-{i}";
                _ffiPartitionPool[i] = partition;
                _ffiCiphertextPool[i] = GoDaddy.Asherah.Encryption.AsherahApi.Encrypt(partition, _payload);
            }
            _ffiCiphertext = _ffiCiphertextPool[0];
            _ffiEncryptPoolIndex = 0;
            _ffiDecryptPoolIndex = 0;
        }

        // Verify round-trip correctness
        var ffiDecrypted = _mode is "memory" or "hot"
            ? GoDaddy.Asherah.Encryption.AsherahApi.Decrypt(PartitionId, _ffiCiphertext)
            : GoDaddy.Asherah.Encryption.AsherahApi.Decrypt(_ffiPartitionPool[0], _ffiCiphertextPool[0]);
        if (!ffiDecrypted.AsSpan().SequenceEqual(_payload))
            throw new Exception($"Rust FFI round-trip verification failed for {PayloadSize}B");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        GoDaddy.Asherah.Encryption.AsherahApi.Shutdown();
    }

    [Benchmark(Description = "Rust FFI (sync)"), BenchmarkCategory("Encrypt")]
    public byte[] RustFfiEncrypt()
    {
        if (_mode is "memory" or "hot")
            return GoDaddy.Asherah.Encryption.AsherahApi.Encrypt(PartitionId, _payload);

        var idx = _ffiEncryptPoolIndex;
        _ffiEncryptPoolIndex = (_ffiEncryptPoolIndex + 1) % _ffiPartitionPool.Length;
        return GoDaddy.Asherah.Encryption.AsherahApi.Encrypt(_ffiPartitionPool[idx], _payload);
    }

    [Benchmark(Description = "Rust FFI (async)"), BenchmarkCategory("Encrypt")]
    public async Task<byte[]> RustFfiEncryptAsync()
    {
        if (_mode is "memory" or "hot")
            return await GoDaddy.Asherah.Encryption.AsherahApi.EncryptAsync(PartitionId, _payload);

        var idx = _ffiEncryptPoolIndex;
        _ffiEncryptPoolIndex = (_ffiEncryptPoolIndex + 1) % _ffiPartitionPool.Length;
        return await GoDaddy.Asherah.Encryption.AsherahApi.EncryptAsync(_ffiPartitionPool[idx], _payload);
    }

    [Benchmark(Description = "Rust FFI (sync)"), BenchmarkCategory("Decrypt")]
    public byte[] RustFfiDecrypt()
    {
        if (_mode is "memory" or "hot")
            return GoDaddy.Asherah.Encryption.AsherahApi.Decrypt(PartitionId, _ffiCiphertext);

        var idx = _ffiDecryptPoolIndex;
        _ffiDecryptPoolIndex = (_ffiDecryptPoolIndex + 1) % _ffiPartitionPool.Length;
        return GoDaddy.Asherah.Encryption.AsherahApi.Decrypt(_ffiPartitionPool[idx], _ffiCiphertextPool[idx]);
    }

    [Benchmark(Description = "Rust FFI (async)"), BenchmarkCategory("Decrypt")]
    public async Task<byte[]> RustFfiDecryptAsync()
    {
        if (_mode is "memory" or "hot")
            return await GoDaddy.Asherah.Encryption.AsherahApi.DecryptAsync(PartitionId, _ffiCiphertext);

        var idx = _ffiDecryptPoolIndex;
        _ffiDecryptPoolIndex = (_ffiDecryptPoolIndex + 1) % _ffiPartitionPool.Length;
        return await GoDaddy.Asherah.Encryption.AsherahApi.DecryptAsync(_ffiPartitionPool[idx], _ffiCiphertextPool[idx]);
    }

    private static string ResolveMode()
    {
        var mode = Environment.GetEnvironmentVariable("BENCH_MODE")?.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(mode)) mode = "memory";
        if (mode is not ("memory" or "hot" or "warm" or "cold"))
            throw new InvalidOperationException($"Invalid BENCH_MODE '{mode}'");
        return mode;
    }

    private static string ResolveMysqlUrl()
    {
        var url = Environment.GetEnvironmentVariable("BENCH_MYSQL_URL")
            ?? Environment.GetEnvironmentVariable("MYSQL_URL");
        if (string.IsNullOrWhiteSpace(url))
            throw new InvalidOperationException("non-memory modes require BENCH_MYSQL_URL or MYSQL_URL");
        return url;
    }

    private static int ReadIntWithFallback(string envKey, int defaultValue)
    {
        var value = Environment.GetEnvironmentVariable(envKey);
        if (string.IsNullOrWhiteSpace(value)) return defaultValue;
        if (!int.TryParse(value, out var parsed) || parsed < 1)
            throw new InvalidOperationException($"{envKey} must be a positive integer");
        return parsed;
    }
}
