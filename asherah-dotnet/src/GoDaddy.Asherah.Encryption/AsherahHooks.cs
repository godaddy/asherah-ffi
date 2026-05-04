using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
// `LogEvent.Level` is `Microsoft.Extensions.Logging.LogLevel` — bringing in
// the namespace gives us the enum, the ILogger interface, and the
// LoggerExtensions structured-logging extension methods (`.Log`,
// `.LogWarning`, etc.) we need below.
using Microsoft.Extensions.Logging;

namespace GoDaddy.Asherah.Encryption;

/// <summary>
/// Observability hook registration: log records and metrics events emitted
/// by the Rust core. Hooks are process-global and apply to every
/// <see cref="AsherahFactory"/> / <see cref="AsherahSession"/> in the
/// process, regardless of which API surface (single-shot
/// <see cref="AsherahApi"/> or explicit factory/session) created them.
/// </summary>
/// <remarks>
/// Wraps the C ABI exported by <c>asherah-ffi/src/hooks.rs</c>. The
/// user-supplied delegate is held alive via a static field (not a
/// <see cref="GCHandle"/>) since we only allow one hook of each type at a
/// time. The unmanaged trampoline catches all exceptions before returning
/// across the FFI boundary — throwing through <c>extern "C"</c> aborts
/// the Rust process since 1.81.
/// </remarks>
public static class AsherahHooks
{
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
                LogLevelToCAbi(minLevel));
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
    /// callback is invoked. Defaults to <see cref="LogLevel.Warning"/> so
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
        Action<LogEvent>? callback, LogLevel minLevel = LogLevel.Warning)
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
                &LogTrampoline, IntPtr.Zero, LogLevelToCAbi(minLevel));
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
    /// operation returns. See <see cref="SetLogHookSync(System.Action{LogEvent},Microsoft.Extensions.Logging.LogLevel)"/> for when to use
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
            // C ABI integers happen to match Microsoft.Extensions.Logging.LogLevel
            // 1:1 for our five produced levels (Trace=0, Debug=1, Information=2,
            // Warning=3, Error=4). Any unexpected value is clamped to Error.
            var lvl = level switch
            {
                0 => LogLevel.Trace,
                1 => LogLevel.Debug,
                2 => LogLevel.Information,
                3 => LogLevel.Warning,
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
            // Swallow — we cannot let exceptions cross the FFI boundary.
        }
    }

    // ─── Microsoft.Extensions.Logging.ILogger integration ────────────────
    //
    // Most modern .NET apps consume logging through an `ILogger` injected by
    // the host (ASP.NET Core, Generic Host, Worker Service). These overloads
    // bridge our LogEvent stream into a caller-supplied ILogger so users
    // don't have to write the boilerplate themselves.
    //
    // `LogEvent.Level` is already `Microsoft.Extensions.Logging.LogLevel` —
    // no level mapping needed.

    private static Action<LogEvent> AdaptLogger(ILogger logger) => evt =>
    {
        if (!logger.IsEnabled(evt.Level)) return;
        // Structured form: `{Target}` and `{Message}` become first-class
        // properties for any ILogger provider that consumes them
        // (Serilog, OpenTelemetry, Application Insights, etc.).
        logger.Log(evt.Level, "{Target}: {Message}", evt.Target, evt.Message);
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
            if (!logger.IsEnabled(evt.Level)) return;
            logger.Log(evt.Level, "{Message}", evt.Message);
        };
    }

    /// <summary>
    /// Translate a Microsoft.Extensions.Logging.LogLevel into the C-ABI
    /// integer the Rust side expects. Critical and None map to the C ABI's
    /// "drop everything" sentinel.
    /// </summary>
    private static int LogLevelToCAbi(LogLevel level) => level switch
    {
        LogLevel.Trace => 0,
        LogLevel.Debug => 1,
        LogLevel.Information => 2,
        LogLevel.Warning => 3,
        LogLevel.Error => 4,
        // Critical, None — neither is produced by the Rust source. Treat as
        // "filter everything" (ASHERAH_LOG_OFF = 5 in asherah-ffi/hooks.rs).
        _ => 5,
    };

    /// <summary>
    /// Register a Microsoft.Extensions.Logging <see cref="ILogger"/> as the
    /// destination for Asherah log records. Async delivery on a worker
    /// thread; producer-side filter set to <see cref="LogLevel.Warning"/>+ by
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
    public static void SetLogHookSync(ILogger logger, LogLevel minLevel = LogLevel.Warning)
    {
        ArgumentNullException.ThrowIfNull(logger);
        SetLogHookSync(AdaptLogger(logger), minLevel);
    }

    /// <summary>
    /// Synchronous variant accepting an <see cref="ILoggerFactory"/>.
    /// </summary>
    public static void SetLogHookSync(ILoggerFactory loggerFactory, LogLevel minLevel = LogLevel.Warning)
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
