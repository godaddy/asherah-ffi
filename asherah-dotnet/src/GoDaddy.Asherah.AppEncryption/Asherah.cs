using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GoDaddy.Asherah;

public static class Asherah
{
    private static readonly object SetupLock = new();
    private static volatile AsherahFactory? _sharedFactory;
    private static readonly ConcurrentDictionary<string, AsherahSession> SessionCache = new();
    private static volatile bool _sessionCachingEnabled = true;

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

    public static Task SetupAsync(AsherahConfig config) => Task.Run(() => Setup(config));

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

    public static bool GetSetupStatus() => _sharedFactory is not null;

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

    public static string EncryptString(string partitionId, string plaintext)
    {
        var ciphertext = Encrypt(partitionId, Encoding.UTF8.GetBytes(plaintext));
        return Encoding.UTF8.GetString(ciphertext);
    }

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

    public static async Task<string> EncryptStringAsync(string partitionId, string plaintext)
    {
        var ciphertext = await EncryptAsync(partitionId, Encoding.UTF8.GetBytes(plaintext)).ConfigureAwait(false);
        return Encoding.UTF8.GetString(ciphertext);
    }

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

    public static byte[] DecryptJson(string partitionId, string dataRowRecordJson) =>
        Decrypt(partitionId, Encoding.UTF8.GetBytes(dataRowRecordJson));

    public static string DecryptString(string partitionId, string dataRowRecordJson)
    {
        var plaintext = DecryptJson(partitionId, dataRowRecordJson);
        return Encoding.UTF8.GetString(plaintext);
    }

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

    // ====================================================================
    // Observability hooks (log + metrics)
    //
    // These wrap the C ABI exported by asherah-ffi/src/hooks.rs. The
    // user-supplied delegate is held alive via a static field (not a
    // GCHandle) since we only allow one hook at a time. The unmanaged
    // trampoline catches all exceptions before returning across the FFI
    // boundary — throwing through `extern "C"` aborts the Rust process
    // since 1.81.
    // ====================================================================

    private static readonly object HookLock = new();
    private static Action<LogEvent>? _logHook;
    private static Action<MetricsEvent>? _metricsHook;

    /// <summary>
    /// Register a callback that receives every log event from the Rust
    /// core (encrypt/decrypt path, metastore drivers, KMS clients).
    /// Pass <c>null</c> to deregister.
    /// </summary>
    /// <remarks>
    /// Callbacks may fire from any thread (Rust tokio worker threads, DB
    /// driver threads). The trampoline catches every exception thrown by
    /// the user callback so a faulty hook cannot tear down the process —
    /// log it via your own observability tooling instead of relying on
    /// Asherah to surface it.
    /// </remarks>
    public static unsafe void SetLogHook(Action<LogEvent>? callback)
    {
        lock (HookLock)
        {
            if (callback is null)
            {
                NativeMethods.asherah_clear_log_hook();
                _logHook = null;
                return;
            }
            _logHook = callback;
            var rc = NativeMethods.asherah_set_log_hook(&LogTrampoline, IntPtr.Zero);
            if (rc != 0)
            {
                _logHook = null;
                throw new InvalidOperationException(
                    $"asherah_set_log_hook failed: rc={rc}");
            }
        }
    }

    /// <summary>
    /// Convenience method equivalent to <c>SetLogHook(null)</c>.
    /// </summary>
    public static void ClearLogHook() => SetLogHook(null);

    /// <summary>
    /// Configurable variant of <see cref="SetLogHook(Action{LogEvent}?)"/>.
    /// Tunes the bounded MPSC queue used to deliver records asynchronously
    /// and the minimum severity actually delivered.
    /// </summary>
    /// <param name="callback">The hook to register. <c>null</c> deregisters.</param>
    /// <param name="queueCapacity">
    /// Maximum events buffered in the worker queue. <c>0</c> uses the
    /// default (4096). When the queue is full, additional records are
    /// dropped — see <see cref="LogDroppedCount"/>.
    /// </param>
    /// <param name="minLevel">
    /// Records more verbose than this level are filtered out by the
    /// producer thread before any allocation or queue push. Use this to
    /// skip the verbose <c>Trace</c>/<c>Debug</c> records and only pay for
    /// <c>Warn</c>/<c>Error</c>.
    /// </param>
    public static unsafe void SetLogHook(
        Action<LogEvent>? callback, int queueCapacity, LogLevel minLevel)
    {
        lock (HookLock)
        {
            if (callback is null)
            {
                NativeMethods.asherah_clear_log_hook();
                _logHook = null;
                return;
            }
            _logHook = callback;
            var rc = NativeMethods.asherah_set_log_hook_with_config(
                &LogTrampoline,
                IntPtr.Zero,
                (UIntPtr)Math.Max(queueCapacity, 0),
                (int)minLevel);
            if (rc != 0)
            {
                _logHook = null;
                throw new InvalidOperationException(
                    $"asherah_set_log_hook_with_config failed: rc={rc}");
            }
        }
    }

    /// <summary>
    /// Cumulative count of log records dropped because the async
    /// dispatcher's queue was full, since the process started. Cumulative
    /// across all hook installations; never resets.
    /// </summary>
    public static ulong LogDroppedCount() => NativeMethods.asherah_log_dropped_count();

    /// <summary>
    /// Synchronous variant of <see cref="SetLogHook(Action{LogEvent}?)"/>.
    /// The callback fires <b>on the encrypt/decrypt thread, before the
    /// operation returns</b>. No queue, no worker thread, no drop counter.
    /// </summary>
    /// <param name="callback">The hook to register. <c>null</c> deregisters.</param>
    /// <param name="minLevel">
    /// Records more verbose than this level are filtered out before the
    /// callback is invoked. Default <see cref="LogLevel.Trace"/> delivers
    /// everything.
    /// </param>
    /// <remarks>
    /// Use this when you're diagnosing a problem and need the callback to
    /// fire before any subsequent panic/crash, when you need thread-local
    /// context (trace IDs) intact in the callback, or when you've verified
    /// your handler is non-blocking and prefer not to pay the queue cost.
    /// <para>
    /// Trade-off: a slow callback directly extends encrypt/decrypt
    /// latency. Prefer <see cref="SetLogHook(Action{LogEvent}?)"/> for the
    /// async-by-default behaviour that protects the hot path from a
    /// misbehaving handler.
    /// </para>
    /// </remarks>
    public static unsafe void SetLogHookSync(
        Action<LogEvent>? callback, LogLevel minLevel = LogLevel.Trace)
    {
        lock (HookLock)
        {
            if (callback is null)
            {
                NativeMethods.asherah_clear_log_hook();
                _logHook = null;
                return;
            }
            _logHook = callback;
            var rc = NativeMethods.asherah_set_log_hook_sync(
                &LogTrampoline, IntPtr.Zero, (int)minLevel);
            if (rc != 0)
            {
                _logHook = null;
                throw new InvalidOperationException(
                    $"asherah_set_log_hook_sync failed: rc={rc}");
            }
        }
    }

    /// <summary>
    /// Register a callback that receives every metrics event from the
    /// Rust core: encrypt/decrypt timings, metastore store/load timings,
    /// and key cache hit/miss/stale counters. Pass <c>null</c> to
    /// deregister.
    /// </summary>
    /// <remarks>
    /// Metrics collection is enabled automatically when a hook is
    /// installed and disabled when cleared. Same threading and exception
    /// semantics as <see cref="SetLogHook(Action{LogEvent}?)"/>.
    /// </remarks>
    public static unsafe void SetMetricsHook(Action<MetricsEvent>? callback)
    {
        lock (HookLock)
        {
            if (callback is null)
            {
                NativeMethods.asherah_clear_metrics_hook();
                _metricsHook = null;
                return;
            }
            _metricsHook = callback;
            var rc = NativeMethods.asherah_set_metrics_hook(&MetricsTrampoline, IntPtr.Zero);
            if (rc != 0)
            {
                _metricsHook = null;
                throw new InvalidOperationException(
                    $"asherah_set_metrics_hook failed: rc={rc}");
            }
        }
    }

    /// <summary>
    /// Configurable variant of <see cref="SetMetricsHook(Action{MetricsEvent}?)"/>.
    /// </summary>
    public static unsafe void SetMetricsHook(Action<MetricsEvent>? callback, int queueCapacity)
    {
        lock (HookLock)
        {
            if (callback is null)
            {
                NativeMethods.asherah_clear_metrics_hook();
                _metricsHook = null;
                return;
            }
            _metricsHook = callback;
            var rc = NativeMethods.asherah_set_metrics_hook_with_config(
                &MetricsTrampoline,
                IntPtr.Zero,
                (UIntPtr)Math.Max(queueCapacity, 0));
            if (rc != 0)
            {
                _metricsHook = null;
                throw new InvalidOperationException(
                    $"asherah_set_metrics_hook_with_config failed: rc={rc}");
            }
        }
    }

    /// <summary>
    /// Cumulative count of metrics events dropped because the async
    /// dispatcher's queue was full, since the process started.
    /// </summary>
    public static ulong MetricsDroppedCount() => NativeMethods.asherah_metrics_dropped_count();

    /// <summary>
    /// Synchronous variant of <see cref="SetMetricsHook(Action{MetricsEvent}?)"/>.
    /// The callback fires on the encrypt/decrypt thread before the
    /// operation returns. See <see cref="SetLogHookSync"/> for when to use
    /// this and the trade-off.
    /// </summary>
    public static unsafe void SetMetricsHookSync(Action<MetricsEvent>? callback)
    {
        lock (HookLock)
        {
            if (callback is null)
            {
                NativeMethods.asherah_clear_metrics_hook();
                _metricsHook = null;
                return;
            }
            _metricsHook = callback;
            var rc = NativeMethods.asherah_set_metrics_hook_sync(
                &MetricsTrampoline, IntPtr.Zero);
            if (rc != 0)
            {
                _metricsHook = null;
                throw new InvalidOperationException(
                    $"asherah_set_metrics_hook_sync failed: rc={rc}");
            }
        }
    }

    /// <summary>
    /// Convenience method equivalent to <c>SetMetricsHook(null)</c>.
    /// </summary>
    public static void ClearMetricsHook() => SetMetricsHook(null);

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static void LogTrampoline(IntPtr userData, int level, IntPtr targetPtr, IntPtr messagePtr)
    {
        // Snapshot the delegate locally so a concurrent SetLogHook(null)
        // doesn't race with us.
        var hook = _logHook;
        if (hook is null) return;
        try
        {
            var target = Marshal.PtrToStringUTF8(targetPtr) ?? string.Empty;
            var message = Marshal.PtrToStringUTF8(messagePtr) ?? string.Empty;
            var lvl = level switch
            {
                0 => LogLevel.Trace,
                1 => LogLevel.Debug,
                2 => LogLevel.Info,
                3 => LogLevel.Warn,
                _ => LogLevel.Error,
            };
            hook(new LogEvent(lvl, target, message));
        }
        catch
        {
            // Swallow — we cannot let exceptions cross the FFI boundary.
        }
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
    private static void MetricsTrampoline(IntPtr userData, int eventType, ulong durationNs, IntPtr namePtr)
    {
        var hook = _metricsHook;
        if (hook is null) return;
        try
        {
            var type = eventType switch
            {
                0 => MetricsEventType.Encrypt,
                1 => MetricsEventType.Decrypt,
                2 => MetricsEventType.Store,
                3 => MetricsEventType.Load,
                4 => MetricsEventType.CacheHit,
                5 => MetricsEventType.CacheMiss,
                _ => MetricsEventType.CacheStale,
            };
            string? name = namePtr == IntPtr.Zero ? null : Marshal.PtrToStringUTF8(namePtr);
            hook(new MetricsEvent(type, durationNs, name));
        }
        catch
        {
            // Swallow.
        }
    }
}
