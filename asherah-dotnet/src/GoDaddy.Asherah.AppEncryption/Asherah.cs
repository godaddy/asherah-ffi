using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
// `using Microsoft.Extensions.Logging` brings in both the ILogger interface
// and the LoggerExtensions structured-logging extension methods (`.Log`,
// `.LogWarning`, etc.) we need below.
using Microsoft.Extensions.Logging;
// Disambiguate: Microsoft.Extensions.Logging.LogLevel vs our LogLevel.
using MsLogLevel = Microsoft.Extensions.Logging.LogLevel;

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
    /// Convenience method equivalent to <c>SetLogHook((Action&lt;LogEvent&gt;?)null)</c>.
    /// </summary>
    public static void ClearLogHook() => SetLogHook((Action<LogEvent>?)null);

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
    /// callback is invoked. Defaults to <see cref="LogLevel.Warn"/> so
    /// only <c>Warn</c>/<c>Error</c> records are delivered. Pass
    /// <see cref="LogLevel.Trace"/> to deliver everything.
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
        Action<LogEvent>? callback, LogLevel minLevel = LogLevel.Warn)
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
    /// Convenience method equivalent to <c>SetMetricsHook((Action&lt;MetricsEvent&gt;?)null)</c>.
    /// </summary>
    public static void ClearMetricsHook() => SetMetricsHook((Action<MetricsEvent>?)null);

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

    // ─── Microsoft.Extensions.Logging.ILogger integration ────────────────
    //
    // Most modern .NET apps consume logging through an `ILogger` injected by
    // the host (ASP.NET Core, Generic Host, Worker Service). These overloads
    // bridge our LogEvent stream into a caller-supplied ILogger so users
    // don't have to write the boilerplate themselves.

    private static MsLogLevel MapToMsLogLevel(LogLevel level) => level switch
    {
        LogLevel.Trace => MsLogLevel.Trace,
        LogLevel.Debug => MsLogLevel.Debug,
        LogLevel.Info => MsLogLevel.Information,
        LogLevel.Warn => MsLogLevel.Warning,
        _ => MsLogLevel.Error,
    };

    private static Action<LogEvent> AdaptLogger(ILogger logger) => evt =>
    {
        var ms = MapToMsLogLevel(evt.Level);
        if (!logger.IsEnabled(ms)) return;
        // Structured form: `{Target}` and `{Message}` become first-class
        // properties for any ILogger provider that consumes them
        // (Serilog, OpenTelemetry, Application Insights, etc.).
        logger.Log(ms, "{Target}: {Message}", evt.Target, evt.Message);
    };

    private static Action<LogEvent> AdaptLoggerFactory(ILoggerFactory factory)
    {
        // One ILogger per Target so host-side filter rules can match by
        // category (e.g. `"asherah::session": Debug`). Loggers are cheap;
        // we cache to avoid creating one per record.
        var cache = new ConcurrentDictionary<string, ILogger>(StringComparer.Ordinal);
        return evt =>
        {
            var logger = cache.GetOrAdd(evt.Target, factory.CreateLogger);
            var ms = MapToMsLogLevel(evt.Level);
            if (!logger.IsEnabled(ms)) return;
            logger.Log(ms, "{Message}", evt.Message);
        };
    }

    /// <summary>
    /// Register a Microsoft.Extensions.Logging <see cref="ILogger"/> as the
    /// destination for Asherah log records. Async delivery on a worker
    /// thread; producer-side filter set to <see cref="LogLevel.Warn"/>+ by
    /// default.
    /// </summary>
    public static void SetLogHook(ILogger logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        SetLogHook(AdaptLogger(logger));
    }

    /// <summary>
    /// Register an <see cref="ILogger"/> with explicit queue capacity and
    /// minimum level.
    /// </summary>
    public static void SetLogHook(ILogger logger, int queueCapacity, LogLevel minLevel)
    {
        ArgumentNullException.ThrowIfNull(logger);
        SetLogHook(AdaptLogger(logger), queueCapacity, minLevel);
    }

    /// <summary>
    /// Register an <see cref="ILoggerFactory"/>. A categorised
    /// <see cref="ILogger"/> is created per Asherah log target (e.g.
    /// <c>asherah::session</c>) so host-side filter rules can match by
    /// category.
    /// </summary>
    public static void SetLogHook(ILoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        SetLogHook(AdaptLoggerFactory(loggerFactory));
    }

    /// <summary>
    /// Register an <see cref="ILoggerFactory"/> with explicit queue
    /// capacity and minimum level.
    /// </summary>
    public static void SetLogHook(ILoggerFactory loggerFactory, int queueCapacity, LogLevel minLevel)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        SetLogHook(AdaptLoggerFactory(loggerFactory), queueCapacity, minLevel);
    }

    /// <summary>
    /// Synchronous variant accepting an <see cref="ILogger"/>. The bridge
    /// fires on the encrypt/decrypt thread; pick this if you need
    /// thread-local context (trace IDs / scopes) intact when the host's
    /// logger writes the record.
    /// </summary>
    public static void SetLogHookSync(ILogger logger, LogLevel minLevel = LogLevel.Warn)
    {
        ArgumentNullException.ThrowIfNull(logger);
        SetLogHookSync(AdaptLogger(logger), minLevel);
    }

    /// <summary>
    /// Synchronous variant accepting an <see cref="ILoggerFactory"/>.
    /// </summary>
    public static void SetLogHookSync(ILoggerFactory loggerFactory, LogLevel minLevel = LogLevel.Warn)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        SetLogHookSync(AdaptLoggerFactory(loggerFactory), minLevel);
    }

    // ─── System.Diagnostics.Metrics.Meter integration ─────────────────────
    //
    // The standard .NET 6+ metrics primitive. OpenTelemetry, Application
    // Insights, Prometheus exporters all consume from a Meter. The bridge
    // creates one Histogram per timing event type (encrypt/decrypt/store/
    // load) and one Counter per cache event (hit/miss/stale).

    private static Action<MetricsEvent> AdaptMeter(Meter meter)
    {
        // Instruments are created once per Set call. Calling SetMetricsHook
        // with the same Meter twice will create duplicate instruments —
        // that's an unusual pattern; document and don't optimise for it.
        var encryptHist = meter.CreateHistogram<double>(
            name: "asherah.encrypt.duration", unit: "ms",
            description: "Time spent in PublicSession.encrypt()");
        var decryptHist = meter.CreateHistogram<double>(
            name: "asherah.decrypt.duration", unit: "ms",
            description: "Time spent in PublicSession.decrypt()");
        var storeHist = meter.CreateHistogram<double>(
            name: "asherah.store.duration", unit: "ms",
            description: "Time spent storing an envelope key in the metastore");
        var loadHist = meter.CreateHistogram<double>(
            name: "asherah.load.duration", unit: "ms",
            description: "Time spent loading an envelope key from the metastore");
        var cacheHit = meter.CreateCounter<long>(
            name: "asherah.cache.hits",
            description: "Cache lookups that returned a fresh entry");
        var cacheMiss = meter.CreateCounter<long>(
            name: "asherah.cache.misses",
            description: "Cache lookups that found no entry");
        var cacheStale = meter.CreateCounter<long>(
            name: "asherah.cache.stale",
            description: "Cache lookups that returned an expired entry");

        return evt =>
        {
            switch (evt.Type)
            {
                case MetricsEventType.Encrypt:
                    encryptHist.Record(evt.DurationNs / 1_000_000.0);
                    break;
                case MetricsEventType.Decrypt:
                    decryptHist.Record(evt.DurationNs / 1_000_000.0);
                    break;
                case MetricsEventType.Store:
                    storeHist.Record(evt.DurationNs / 1_000_000.0);
                    break;
                case MetricsEventType.Load:
                    loadHist.Record(evt.DurationNs / 1_000_000.0);
                    break;
                case MetricsEventType.CacheHit:
                    cacheHit.Add(1, new KeyValuePair<string, object?>("cache", evt.Name ?? string.Empty));
                    break;
                case MetricsEventType.CacheMiss:
                    cacheMiss.Add(1, new KeyValuePair<string, object?>("cache", evt.Name ?? string.Empty));
                    break;
                case MetricsEventType.CacheStale:
                    cacheStale.Add(1, new KeyValuePair<string, object?>("cache", evt.Name ?? string.Empty));
                    break;
            }
        };
    }

    /// <summary>
    /// Register a <see cref="Meter"/> as the destination for Asherah
    /// metrics events. The bridge creates standard instruments
    /// (<c>asherah.encrypt.duration</c>, <c>asherah.cache.hits</c>, etc.)
    /// and forwards each event to the appropriate one. Async delivery via
    /// the default-sized worker queue.
    /// </summary>
    public static void SetMetricsHook(Meter meter)
    {
        ArgumentNullException.ThrowIfNull(meter);
        SetMetricsHook(AdaptMeter(meter));
    }

    /// <summary>
    /// Register a <see cref="Meter"/> with explicit queue capacity.
    /// </summary>
    public static void SetMetricsHook(Meter meter, int queueCapacity)
    {
        ArgumentNullException.ThrowIfNull(meter);
        SetMetricsHook(AdaptMeter(meter), queueCapacity);
    }

    /// <summary>
    /// Synchronous variant accepting a <see cref="Meter"/>.
    /// </summary>
    public static void SetMetricsHookSync(Meter meter)
    {
        ArgumentNullException.ThrowIfNull(meter);
        SetMetricsHookSync(AdaptMeter(meter));
    }
}
