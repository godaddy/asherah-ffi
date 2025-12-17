using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;

namespace GoDaddy.Asherah;

public static class Asherah
{
    private static readonly object SyncRoot = new();
    private static AsherahFactory? _sharedFactory;
    private static MemoryCache? _sessionCache;
    private static bool _sessionCachingEnabled = true;
    private static TimeSpan _sessionCacheDuration = TimeSpan.FromHours(2);

    public static AsherahFactory FactoryFromEnv()
    {
        var ptr = NativeMethods.asherah_factory_new_from_env();
        if (ptr == IntPtr.Zero)
        {
            throw NativeError.Create("factory_from_env");
        }

        return new AsherahFactory(new SafeFactoryHandle(ptr));
    }

    public static AsherahFactory FactoryFromConfig(AsherahConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        using var json = new Utf8String(config.ToJson());
        var ptr = NativeMethods.asherah_factory_new_with_config(json.Pointer);
        if (ptr == IntPtr.Zero)
        {
            throw NativeError.Create("factory_from_config");
        }

        return new AsherahFactory(new SafeFactoryHandle(ptr));
    }

    public static void Setup(AsherahConfig config)
    {
        var factory = FactoryFromConfig(config);
        lock (SyncRoot)
        {
            if (_sharedFactory is not null)
            {
                factory.Dispose();
                throw new InvalidOperationException("Asherah is already configured; call Shutdown() first");
            }

            _sharedFactory = factory;
            _sessionCachingEnabled = config.SessionCachingEnabled;
            _sessionCacheDuration = TimeSpan.FromSeconds(config.SessionCacheDuration ?? 2 * 60 * 60);

            _sessionCache?.Dispose();
            _sessionCache = _sessionCachingEnabled
                ? new MemoryCache(new MemoryCacheOptions())
                : null;
        }
    }

    public static Task SetupAsync(AsherahConfig config) => Task.Run(() => Setup(config));

    public static void Shutdown()
    {
        lock (SyncRoot)
        {
            if (_sharedFactory is null)
            {
                return;
            }

            _sessionCache?.Dispose();
            _sessionCache = null;
            _sharedFactory.Dispose();
            _sharedFactory = null;
        }
    }

    public static Task ShutdownAsync() => Task.Run(Shutdown);

    public static bool GetSetupStatus()
    {
        return _sharedFactory is not null;
    }

    public static void SetEnv(IDictionary<string, string?> env)
    {
        ArgumentNullException.ThrowIfNull(env);
        foreach (var pair in env)
        {
            Environment.SetEnvironmentVariable(pair.Key, pair.Value);
        }
    }

    public static byte[] Encrypt(string partitionId, byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(partitionId);
        ArgumentNullException.ThrowIfNull(plaintext);

        using var session = GetSession(partitionId);
        return session.EncryptBytes(plaintext);
    }

    public static string EncryptString(string partitionId, string plaintext)
    {
        var ciphertext = Encrypt(partitionId, Encoding.UTF8.GetBytes(plaintext));
        return Encoding.UTF8.GetString(ciphertext);
    }

    public static Task<byte[]> EncryptAsync(string partitionId, byte[] plaintext) =>
        Task.Run(() => Encrypt(partitionId, plaintext));

    public static Task<string> EncryptStringAsync(string partitionId, string plaintext) =>
        Task.Run(() => EncryptString(partitionId, plaintext));

    public static byte[] Decrypt(string partitionId, byte[] dataRowRecordJson)
    {
        ArgumentNullException.ThrowIfNull(partitionId);
        ArgumentNullException.ThrowIfNull(dataRowRecordJson);

        using var session = GetSession(partitionId);
        return session.DecryptBytes(dataRowRecordJson);
    }

    public static byte[] DecryptJson(string partitionId, string dataRowRecordJson) =>
        Decrypt(partitionId, Encoding.UTF8.GetBytes(dataRowRecordJson));

    public static string DecryptString(string partitionId, string dataRowRecordJson)
    {
        var plaintext = DecryptJson(partitionId, dataRowRecordJson);
        return Encoding.UTF8.GetString(plaintext);
    }

    public static Task<byte[]> DecryptAsync(string partitionId, byte[] dataRowRecordJson) =>
        Task.Run(() => Decrypt(partitionId, dataRowRecordJson));

    public static Task<string> DecryptStringAsync(string partitionId, string dataRowRecordJson) =>
        Task.Run(() => DecryptString(partitionId, dataRowRecordJson));

    private static AsherahSession GetSession(string partitionId)
    {
        var factory = _sharedFactory
            ?? throw new InvalidOperationException("Asherah not configured; call Setup() first");

        // No caching - just create a new session each time
        if (!_sessionCachingEnabled || _sessionCache is null)
        {
            return factory.GetSession(partitionId);
        }

        // Try to get from cache, create if not present
        // MemoryCache.GetOrCreate is thread-safe
        return _sessionCache.GetOrCreate(partitionId, entry =>
        {
            entry.SlidingExpiration = _sessionCacheDuration;
            entry.RegisterPostEvictionCallback((_, value, _, _) =>
            {
                (value as IDisposable)?.Dispose();
            });
            return factory.GetSession(partitionId);
        })!;
    }
}
