using System;
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

    // Session cache: bounded LRU. `Dictionary<string, LinkedListNode>` +
    // `LinkedList` give O(1) lookup, O(1) move-to-most-recent on hit, and
    // O(1) evict-least-recently-used on insert overflow — the same shape
    // as Java's LinkedHashMap and Python's OrderedDict. The bound is
    // `SessionCacheMaxSize` (default 1000), matching the Rust core. The
    // previous implementation used an unbounded ConcurrentDictionary,
    // which silently ignored `SessionCacheMaxSize` and grew without
    // limit.
    private static readonly object CacheLock = new();
    private static readonly Dictionary<string, LinkedListNode<CacheEntry>> SessionCache = new();
    private static readonly LinkedList<CacheEntry> SessionOrder = new();
    private static volatile bool _sessionCachingEnabled = true;
    private static int _sessionCacheMaxSize = 1000;

    private readonly struct CacheEntry
    {
        public readonly string PartitionId;
        public readonly AsherahSession Session;

        public CacheEntry(string partitionId, AsherahSession session)
        {
            PartitionId = partitionId;
            Session = session;
        }
    }

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
            lock (CacheLock)
            {
                SessionCache.Clear();
                SessionOrder.Clear();
            }
            _sessionCachingEnabled = config.SessionCachingEnabled;
            _sessionCacheMaxSize = config.SessionCacheMaxSizeOrDefault;
        }
    }

    /// <inheritdoc cref="Setup(AsherahConfig)"/>
    public static Task SetupAsync(AsherahConfig config) => Task.Run(() => Setup(config));

    /// <summary>
    /// Dispose the process-global factory and any cached sessions. Safe
    /// to call when not configured (no-op).
    /// </summary>
    /// <exception cref="AggregateException">
    /// Thrown if one or more sessions or the factory itself failed to
    /// dispose. Teardown completes regardless — every session is given
    /// a chance to dispose and the factory is disposed last — and all
    /// collected failures are reported together. Callers in host
    /// shutdown contexts that want strictly fire-and-forget semantics
    /// should wrap the call in a try/catch.
    /// </exception>
    public static void Shutdown()
    {
        lock (SetupLock)
        {
            if (_sharedFactory is null)
            {
                return;
            }

            // Collect all disposal failures so a single bad session can't
            // abort teardown of the rest. We still surface them via
            // AggregateException at the end so unexpected failures (e.g.,
            // a native crash inside a session handle release) aren't
            // silently lost — the caller can log or escalate as they see
            // fit, but the factory and other sessions still get disposed.
            List<Exception>? errors = null;

            List<AsherahSession> sessionsToDispose;
            lock (CacheLock)
            {
                sessionsToDispose = new List<AsherahSession>(SessionCache.Count);
                foreach (var node in SessionCache.Values)
                {
                    sessionsToDispose.Add(node.Value.Session);
                }
                SessionCache.Clear();
                SessionOrder.Clear();
            }

            foreach (var session in sessionsToDispose)
            {
                try
                {
                    session.Dispose();
                }
                catch (ObjectDisposedException)
                {
                    // Double-dispose race during shutdown is expected and
                    // matches our intent: just skip.
                }
                catch (Exception ex)
                {
                    (errors ??= new List<Exception>()).Add(ex);
                }
            }

            try
            {
                _sharedFactory.Dispose();
            }
            catch (ObjectDisposedException)
            {
                // Already disposed — fine.
            }
            catch (Exception ex)
            {
                (errors ??= new List<Exception>()).Add(ex);
            }

            // Null out the factory regardless of dispose outcome so the
            // process can be reconfigured via Setup() after a failed
            // Shutdown.
            _sharedFactory = null;

            if (errors is { Count: > 0 })
            {
                throw new AggregateException(
                    $"AsherahApi.Shutdown completed with {errors.Count} disposal " +
                    "failure(s). Teardown finished — the factory is gone and the " +
                    "session cache is cleared — but one or more sessions or the " +
                    "factory itself threw on Dispose. Inspect the inner exceptions " +
                    "to investigate.",
                    errors);
            }
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
        if (!_sessionCachingEnabled)
        {
            return SharedFactory().GetSession(partitionId);
        }

        lock (CacheLock)
        {
            if (SessionCache.TryGetValue(partitionId, out var node))
            {
                // LRU: move the hit to the most-recently-used end.
                SessionOrder.Remove(node);
                SessionOrder.AddLast(node);
                return node.Value.Session;
            }
        }

        // Miss — create outside the lock so we don't hold it across an FFI
        // call. Re-check after creation in case another thread raced us.
        var fresh = SharedFactory().GetSession(partitionId);

        AsherahSession? evicted = null;
        AsherahSession result;
        lock (CacheLock)
        {
            if (SessionCache.TryGetValue(partitionId, out var existing))
            {
                // Lost the race — another thread inserted while we were
                // creating. Move the winner to MRU and discard ours.
                SessionOrder.Remove(existing);
                SessionOrder.AddLast(existing);
                fresh.Dispose();
                return existing.Value.Session;
            }

            var inserted = SessionOrder.AddLast(new CacheEntry(partitionId, fresh));
            SessionCache[partitionId] = inserted;
            result = fresh;

            // LRU eviction: at most one entry can exceed the bound per
            // insert (cache was at maxSize, we added one), so a single
            // RemoveFirst restores the invariant. The head is the
            // least-recently-used entry because hits move to the tail.
            //
            // Race window: an evicted session may be in use by another
            // thread mid-encrypt; disposing it here will surface as an
            // FFI error on that thread. The same window exists in the
            // Go binding. Accepted tradeoff — under LRU the evicted
            // entry is by definition the coldest, so this is rare in
            // typical workloads. A refcount-based fix would have to
            // change AsherahSession's lifecycle and is out of scope.
            if (SessionCache.Count > _sessionCacheMaxSize && SessionOrder.First is { } first)
            {
                SessionOrder.RemoveFirst();
                SessionCache.Remove(first.Value.PartitionId);
                evicted = first.Value.Session;
            }
        }

        evicted?.Dispose();
        return result;
    }

    private static void ReleaseSession(string partitionId, AsherahSession session)
    {
        if (!_sessionCachingEnabled)
        {
            session.Dispose();
            return;
        }

        // If the cache no longer holds this session (e.g., it was evicted
        // by another thread between Acquire and Release, or Shutdown
        // cleared the cache), the caller is the last owner and must
        // dispose. Otherwise the cache owns it.
        lock (CacheLock)
        {
            if (SessionCache.TryGetValue(partitionId, out var node)
                && ReferenceEquals(node.Value.Session, session))
            {
                return;
            }
        }

        session.Dispose();
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
