using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace GoDaddy.Asherah.Encryption;

/// <summary>
/// Single-shot convenience API for callers that don't need explicit
/// factory/session lifecycle management.
///
/// <para>
/// Configure once with <see cref="Setup(AsherahConfig)"/>, then call
/// <see cref="Encrypt"/>/<see cref="Decrypt"/> with a partition id; the
/// underlying <see cref="AsherahFactory"/> and <see cref="AsherahSession"/>
/// instances are managed for you (sessions are cached per partition).
/// </para>
///
/// <para>
/// For applications that want explicit session lifecycle, ownership, or
/// testability (e.g. multiple factories with different configs in one
/// process), use <see cref="AsherahFactory.FromConfig"/> and
/// <see cref="AsherahFactory.GetSession"/> directly.
/// </para>
///
/// <para>
/// Observability hooks (log records, metrics events) are configured via
/// <see cref="AsherahHooks"/> and apply globally regardless of which API
/// surface created the factory or session.
/// </para>
/// </summary>
public static class AsherahApi
{
    private static readonly object SetupLock = new();
    private static volatile AsherahFactory? _sharedFactory;
    private static readonly ConcurrentDictionary<string, AsherahSession> SessionCache = new();
    private static volatile bool _sessionCachingEnabled = true;

    /// <summary>
    /// Configure the process-global factory from an explicit
    /// <see cref="AsherahConfig"/>. Call once at startup.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown if Asherah is already configured. Call
    /// <see cref="Shutdown"/> first to reconfigure.
    /// </exception>
    public static void Setup(AsherahConfig config)
    {
        var factory = AsherahFactory.FromConfig(config);
        lock (SetupLock)
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

    /// <inheritdoc cref="Setup(AsherahConfig)"/>
    public static Task SetupAsync(AsherahConfig config) => Task.Run(() => Setup(config));

    /// <summary>
    /// Dispose the process-global factory and any cached sessions. Safe
    /// to call when not configured (no-op).
    /// </summary>
    public static void Shutdown()
    {
        lock (SetupLock)
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
                catch (Exception)
                {
                    // Process-shutdown cleanup: swallow any individual session
                    // disposal failure so a single bad session can't abort
                    // teardown of the rest. ObjectDisposedException (double
                    // dispose) and InvalidOperationException (handle in an
                    // unexpected state) are the realistic shapes; we don't
                    // discriminate because there's no useful recovery here
                    // either way.
                }
            }

            SessionCache.Clear();
            _sharedFactory.Dispose();
            _sharedFactory = null;
        }
    }

    /// <inheritdoc cref="Shutdown"/>
    public static Task ShutdownAsync() => Task.Run(Shutdown);

    /// <summary>True if <see cref="Setup(AsherahConfig)"/> has been called.</summary>
    public static bool GetSetupStatus() => _sharedFactory is not null;

    /// <summary>
    /// Bulk-set environment variables before <see cref="Setup(AsherahConfig)"/>
    /// or <see cref="AsherahFactory.FromEnv"/>. Convenience for tests and
    /// hosted scenarios where env vars come from an injected dictionary.
    /// </summary>
    public static void SetEnv(IDictionary<string, string?> env)
    {
        ArgumentNullException.ThrowIfNull(env);
        foreach (var pair in env)
        {
            Environment.SetEnvironmentVariable(pair.Key, pair.Value);
        }
    }

    /// <summary>
    /// Encrypt <paramref name="plaintext"/> with a session for
    /// <paramref name="partitionId"/>. Returns the JSON-encoded
    /// DataRowRecord (UTF-8 bytes).
    /// </summary>
    public static byte[] Encrypt(string partitionId, byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(partitionId);
        ArgumentNullException.ThrowIfNull(plaintext);
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

    /// <summary>
    /// String overload of <see cref="Encrypt"/>. UTF-8 encodes the input,
    /// returns the UTF-8-decoded JSON DataRowRecord.
    /// </summary>
    public static string EncryptString(string partitionId, string plaintext)
    {
        var ciphertext = Encrypt(partitionId, Encoding.UTF8.GetBytes(plaintext));
        return Encoding.UTF8.GetString(ciphertext);
    }

    /// <inheritdoc cref="Encrypt"/>
    public static async Task<byte[]> EncryptAsync(string partitionId, byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(partitionId);
        ArgumentNullException.ThrowIfNull(plaintext);
        var session = AcquireSession(partitionId);
        try
        {
            return await session.EncryptBytesAsync(plaintext).ConfigureAwait(false);
        }
        finally
        {
            ReleaseSession(partitionId, session);
        }
    }

    /// <inheritdoc cref="EncryptString"/>
    public static async Task<string> EncryptStringAsync(string partitionId, string plaintext)
    {
        var ciphertext = await EncryptAsync(partitionId, Encoding.UTF8.GetBytes(plaintext)).ConfigureAwait(false);
        return Encoding.UTF8.GetString(ciphertext);
    }

    /// <summary>
    /// Decrypt the JSON DataRowRecord (UTF-8 bytes) for
    /// <paramref name="partitionId"/>. Returns the plaintext bytes.
    /// </summary>
    public static byte[] Decrypt(string partitionId, byte[] dataRowRecordJson)
    {
        ArgumentNullException.ThrowIfNull(partitionId);
        ArgumentNullException.ThrowIfNull(dataRowRecordJson);
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

    /// <summary>String-input overload of <see cref="Decrypt"/>.</summary>
    public static byte[] DecryptJson(string partitionId, string dataRowRecordJson) =>
        Decrypt(partitionId, Encoding.UTF8.GetBytes(dataRowRecordJson));

    /// <summary>
    /// String overload that decodes the resulting plaintext bytes as
    /// UTF-8.
    /// </summary>
    public static string DecryptString(string partitionId, string dataRowRecordJson)
    {
        var plaintext = DecryptJson(partitionId, dataRowRecordJson);
        return Encoding.UTF8.GetString(plaintext);
    }

    /// <inheritdoc cref="Decrypt"/>
    public static async Task<byte[]> DecryptAsync(string partitionId, byte[] dataRowRecordJson)
    {
        ArgumentNullException.ThrowIfNull(partitionId);
        ArgumentNullException.ThrowIfNull(dataRowRecordJson);
        var session = AcquireSession(partitionId);
        try
        {
            return await session.DecryptBytesAsync(dataRowRecordJson).ConfigureAwait(false);
        }
        finally
        {
            ReleaseSession(partitionId, session);
        }
    }

    /// <inheritdoc cref="DecryptString"/>
    public static async Task<string> DecryptStringAsync(string partitionId, string dataRowRecordJson)
    {
        var plaintext = await DecryptAsync(partitionId, Encoding.UTF8.GetBytes(dataRowRecordJson)).ConfigureAwait(false);
        return Encoding.UTF8.GetString(plaintext);
    }

    private static AsherahSession AcquireSession(string partitionId)
    {
        EnsureConfigured();
        if (_sessionCachingEnabled)
        {
            return SessionCache.GetOrAdd(partitionId, static (pid, factory) => factory.GetSession(pid), SharedFactory());
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
