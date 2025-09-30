using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace GoDaddy.Asherah;

public static class Asherah
{
    private static readonly object SyncRoot = new();
    private static AsherahFactory? _sharedFactory;
    private static readonly Dictionary<string, AsherahSession> SessionCache = new();
    private static bool _sessionCachingEnabled = true;

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
            SessionCache.Clear();
            _sessionCachingEnabled = config.SessionCachingEnabled;
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

            foreach (var session in SessionCache.Values)
            {
                try
                {
                    session.Dispose();
                }
                catch
                {
                    // ignore
                }
            }

            SessionCache.Clear();
            _sharedFactory.Dispose();
            _sharedFactory = null;
        }
    }

    public static Task ShutdownAsync() => Task.Run(Shutdown);

    public static bool GetSetupStatus()
    {
        lock (SyncRoot)
        {
            return _sharedFactory is not null;
        }
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
        lock (SyncRoot)
        {
            var session = AcquireSession(partitionId);
            try
            {
                return session.EncryptBytes(plaintext);
            }
            finally
            {
                ReleaseSession(partitionId, session);
            }
        }
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
        lock (SyncRoot)
        {
            var session = AcquireSession(partitionId);
            try
            {
                return session.DecryptBytes(dataRowRecordJson);
            }
            finally
            {
                ReleaseSession(partitionId, session);
            }
        }
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

    private static AsherahSession AcquireSession(string partitionId)
    {
        EnsureConfigured();
        if (_sessionCachingEnabled)
        {
            if (!SessionCache.TryGetValue(partitionId, out var session))
            {
                session = SharedFactory().GetSession(partitionId);
                SessionCache[partitionId] = session;
            }
            return session;
        }

        return SharedFactory().GetSession(partitionId);
    }

    private static void ReleaseSession(string partitionId, AsherahSession session)
    {
        if (!_sessionCachingEnabled)
        {
            session.Dispose();
            return;
        }

        if (!SessionCache.TryGetValue(partitionId, out var cached) || !ReferenceEquals(cached, session))
        {
            session.Dispose();
        }
    }

    private static AsherahFactory SharedFactory() =>
        _sharedFactory ?? throw new InvalidOperationException("Asherah not configured; call Setup() first");

    private static void EnsureConfigured()
    {
        if (_sharedFactory is null)
        {
            throw new InvalidOperationException("Asherah not configured; call Setup() first");
        }
    }
}
