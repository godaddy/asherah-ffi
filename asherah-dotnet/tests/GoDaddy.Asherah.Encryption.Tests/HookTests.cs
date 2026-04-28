using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using GoDaddy.Asherah;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace GoDaddy.Asherah.Encryption.Tests;

// Comprehensive log/metrics hook coverage for the .NET binding.
//
// Hooks are global state on the C ABI side; tests in this collection run
// serially via xUnit's [Collection] mechanism so they do not race.
[Collection("Hooks")]
public class HookTests
{
    static HookTests()
    {
        Environment.SetEnvironmentVariable("SERVICE_NAME",
            Environment.GetEnvironmentVariable("SERVICE_NAME") ?? "hook-test-svc");
        Environment.SetEnvironmentVariable("PRODUCT_ID",
            Environment.GetEnvironmentVariable("PRODUCT_ID") ?? "hook-test-prod");
        Environment.SetEnvironmentVariable("KMS",
            Environment.GetEnvironmentVariable("KMS") ?? "static");
        Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX",
            Environment.GetEnvironmentVariable("STATIC_MASTER_KEY_HEX")
                ?? new string('2', 64));

        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASHERAH_DOTNET_NATIVE")))
        {
            var root = LocateRepoRoot();
            Environment.SetEnvironmentVariable(
                "ASHERAH_DOTNET_NATIVE", Path.Combine(root, "target", "debug"));
        }
    }

    private static AsherahConfig CreateConfig(bool verbose = false) =>
        AsherahConfig.CreateBuilder()
            .WithServiceName("hook-test-svc")
            .WithProductId("hook-test-prod")
            .WithMetastore("memory")
            .WithKms("static")
            .WithEnableSessionCaching(true)
            .WithVerbose(verbose)
            .Build();

    /// <summary>
    /// RAII guard: clears any leftover hook state before the test runs and
    /// again on disposal so subsequent tests start clean even if this one
    /// throws.
    /// </summary>
    private sealed class HookScope : IDisposable
    {
        public HookScope()
        {
            Asherah.SetLogHook((Action<LogEvent>?)null);
            Asherah.SetMetricsHook((Action<MetricsEvent>?)null);
            if (Asherah.GetSetupStatus()) Asherah.Shutdown();
        }
        public void Dispose()
        {
            Asherah.SetLogHook((Action<LogEvent>?)null);
            Asherah.SetMetricsHook((Action<MetricsEvent>?)null);
            if (Asherah.GetSetupStatus()) Asherah.Shutdown();
        }
    }

    /// <summary>
    /// The C ABI delivers hook events asynchronously on a dedicated worker
    /// thread to keep the encrypt/decrypt hot path independent of how slow
    /// a user-supplied callback is. Tests that assert on collected events
    /// need to give the worker a moment to drain.
    /// </summary>
    private static void WaitFor(Func<bool> cond, int timeoutMs = 2000)
    {
        var deadline = Environment.TickCount + timeoutMs;
        while (!cond() && Environment.TickCount < deadline)
        {
            Thread.Sleep(2);
        }
    }

    [Fact]
    public void LogHook_Fires_OnEncryptDecrypt()
    {
        using var _ = new HookScope();
        var events = new ConcurrentBag<LogEvent>();
        Asherah.SetLogHook(e => events.Add(e));
        Asherah.Setup(CreateConfig(verbose: true));
        var ct = Asherah.EncryptString("p1", "log-test");
        Asherah.DecryptString("p1", ct);
        WaitFor(() => !events.IsEmpty);
        Asherah.Shutdown();
        Assert.NotEmpty(events);
        // Every event must have the documented shape.
        foreach (var e in events)
        {
            Assert.NotNull(e.Target);
            Assert.NotNull(e.Message);
            Assert.InRange((int)e.Level, 0, 4);
        }
    }

    [Fact]
    public void LogHook_Clear_StopsCallbacks()
    {
        using var _ = new HookScope();
        var events = new ConcurrentBag<LogEvent>();
        Asherah.SetLogHook(e => events.Add(e));
        Asherah.Setup(CreateConfig(verbose: true));
        Asherah.EncryptString("p2", "first");
        // Drain the queue before snapshotting (worker may still be
        // delivering events from the encrypt above).
        Thread.Sleep(50);
        var beforeClear = events.Count;
        Assert.True(beforeClear >= 1);
        Asherah.SetLogHook((Action<LogEvent>?)null);
        Asherah.EncryptString("p2", "second");
        Thread.Sleep(50);
        Asherah.Shutdown();
        Assert.Equal(beforeClear, events.Count);
    }

    [Fact]
    public void LogHook_Replace_KeepsFiring()
    {
        using var _ = new HookScope();
        var a = new ConcurrentBag<LogEvent>();
        var b = new ConcurrentBag<LogEvent>();
        // Trace filter: encrypt() emits Debug records every call. The
        // default Warn filter only delivers the one-shot static-master-key
        // warning at Setup, so the second-hook bag would never fill.
        Asherah.SetLogHook(e => a.Add(e), queueCapacity: 0, minLevel: LogLevel.Trace);
        Asherah.Setup(CreateConfig(verbose: true));
        Asherah.EncryptString("p3", "first");
        WaitFor(() => !a.IsEmpty);
        Assert.NotEmpty(a);
        Asherah.SetLogHook(e => b.Add(e), queueCapacity: 0, minLevel: LogLevel.Trace);
        Asherah.EncryptString("p3", "second");
        WaitFor(() => !b.IsEmpty);
        Asherah.Shutdown();
        Assert.NotEmpty(a);
        Assert.NotEmpty(b);
    }

    [Fact]
    public void LogHook_CallbackException_DoesNotCrash()
    {
        using var _ = new HookScope();
        Asherah.SetLogHook(_ => throw new InvalidOperationException("intentional"));
        Asherah.Setup(CreateConfig(verbose: true));
        // Must not crash the process even though the callback throws.
        Asherah.EncryptString("p4", "exception-safe");
        Asherah.Shutdown();
    }

    [Fact]
    public void MetricsHook_Fires_OnEncryptDecrypt()
    {
        using var _ = new HookScope();
        var events = new ConcurrentBag<MetricsEvent>();
        Asherah.SetMetricsHook(e => events.Add(e));
        Asherah.Setup(CreateConfig());
        for (int i = 0; i < 5; i++)
        {
            var ct = Asherah.EncryptString("p5", $"payload-{i}");
            Asherah.DecryptString("p5", ct);
        }
        WaitFor(() =>
            events.Count(e => e.Type == MetricsEventType.Encrypt) >= 5 &&
            events.Count(e => e.Type == MetricsEventType.Decrypt) >= 5);
        Asherah.Shutdown();
        var encrypts = events.Where(e => e.Type == MetricsEventType.Encrypt).ToList();
        var decrypts = events.Where(e => e.Type == MetricsEventType.Decrypt).ToList();
        Assert.True(encrypts.Count >= 5, $"expected ≥5 encrypt events, got {encrypts.Count}");
        Assert.True(decrypts.Count >= 5, $"expected ≥5 decrypt events, got {decrypts.Count}");
        Assert.All(encrypts, e => Assert.True(e.DurationNs > 0));
        Assert.All(encrypts, e => Assert.Null(e.Name));
    }

    [Fact]
    public void MetricsHook_CacheEvents_HaveName()
    {
        using var _ = new HookScope();
        var events = new ConcurrentBag<MetricsEvent>();
        Asherah.SetMetricsHook(e => events.Add(e));
        Asherah.Setup(CreateConfig());
        for (int i = 0; i < 3; i++)
        {
            Asherah.EncryptString("cache-p", $"item-{i}");
        }
        WaitFor(() => !events.IsEmpty);
        Asherah.Shutdown();
        // Cache events may or may not surface depending on session
        // caching state; assert structure of any that do fire.
        var cacheEvents = events.Where(e =>
            e.Type == MetricsEventType.CacheHit ||
            e.Type == MetricsEventType.CacheMiss ||
            e.Type == MetricsEventType.CacheStale).ToList();
        Assert.All(cacheEvents, e => Assert.False(string.IsNullOrEmpty(e.Name)));
    }

    [Fact]
    public void MetricsHook_Clear_StopsCallbacks()
    {
        using var _ = new HookScope();
        var events = new ConcurrentBag<MetricsEvent>();
        Asherah.SetMetricsHook(e => events.Add(e));
        Asherah.Setup(CreateConfig());
        Asherah.EncryptString("p6", "pre-deregister");
        // Wait for the async dispatcher to fully drain its queue before
        // snapshotting `beforeClear` — otherwise the worker is still
        // delivering events from the encrypt above when we read the count.
        Thread.Sleep(50);
        var beforeClear = events.Count;
        Assert.True(beforeClear > 0);
        Asherah.SetMetricsHook((Action<MetricsEvent>?)null);
        Asherah.EncryptString("p6", "post-deregister");
        Thread.Sleep(50);
        Asherah.Shutdown();
        Assert.Equal(beforeClear, events.Count);
    }

    [Fact]
    public void MetricsHook_Replace_KeepsFiring()
    {
        using var _ = new HookScope();
        var a = new ConcurrentBag<MetricsEvent>();
        var b = new ConcurrentBag<MetricsEvent>();
        Asherah.SetMetricsHook(e => a.Add(e));
        Asherah.Setup(CreateConfig());
        Asherah.EncryptString("p7", "first");
        WaitFor(() => !a.IsEmpty);
        Assert.NotEmpty(a);
        Asherah.SetMetricsHook(e => b.Add(e));
        Asherah.EncryptString("p7", "second");
        WaitFor(() => !b.IsEmpty);
        Asherah.Shutdown();
        Assert.NotEmpty(a);
        Assert.NotEmpty(b);
    }

    [Fact]
    public void MetricsHook_CallbackException_DoesNotCrash()
    {
        using var _ = new HookScope();
        Asherah.SetMetricsHook(_ => throw new InvalidOperationException("intentional"));
        Asherah.Setup(CreateConfig());
        Asherah.EncryptString("p8", "exception-safe");
        Asherah.Shutdown();
    }

    [Fact]
    public void Hooks_FireUnderFactorySessionApi()
    {
        using var _ = new HookScope();
        var logs = new ConcurrentBag<LogEvent>();
        var metrics = new ConcurrentBag<MetricsEvent>();
        Asherah.SetLogHook(e => logs.Add(e));
        Asherah.SetMetricsHook(e => metrics.Add(e));
        using (var factory = Asherah.FactoryFromConfig(CreateConfig()))
        using (var session = factory.GetSession("factory-p"))
        {
            var ct = session.EncryptString("factory-payload");
            Assert.Equal("factory-payload", session.DecryptString(ct));
        }
        WaitFor(() => !metrics.IsEmpty);
        Assert.NotEmpty(metrics);
    }

    [Fact]
    public void Hook_InstalledBeforeSetup_FiresEvents()
    {
        using var _ = new HookScope();
        var events = new ConcurrentBag<MetricsEvent>();
        Asherah.SetMetricsHook(e => events.Add(e));
        Asherah.Setup(CreateConfig());
        Asherah.EncryptString("p9", "before-setup");
        WaitFor(() => !events.IsEmpty);
        Asherah.Shutdown();
        Assert.NotEmpty(events);
    }

    [Fact]
    public void Hooks_MultipleRegisterClearCycles()
    {
        using var _ = new HookScope();
        for (int cycle = 0; cycle < 3; cycle++)
        {
            var events = new ConcurrentBag<MetricsEvent>();
            Asherah.SetMetricsHook(e => events.Add(e));
            Asherah.Setup(CreateConfig());
            Asherah.EncryptString("p10", $"cycle-{cycle}");
            // Drain async dispatcher's queue before tearing down the hook —
            // otherwise the worker could still be holding events when we
            // null out the callback.
            WaitFor(() => events.Count > 0);
            Asherah.Shutdown();
            Asherah.SetMetricsHook((Action<MetricsEvent>?)null);
            Assert.True(events.Count > 0, $"cycle {cycle} produced no events");
        }
    }

    [Fact]
    public void IAsherah_ExposesHookApi()
    {
        using var _ = new HookScope();
        IAsherah client = new AsherahClient();
        var events = new ConcurrentBag<MetricsEvent>();
        client.SetMetricsHook(e => events.Add(e));
        client.Setup(CreateConfig());
        client.EncryptString("p11", "via-iface");
        WaitFor(() => !events.IsEmpty);
        client.Shutdown();
        client.SetMetricsHook(null);
        Assert.NotEmpty(events);
    }

    // ── Sync-mode hooks ────────────────────────────────────────────
    //
    // The async-mode tests above cover correctness of the events; these
    // tests prove the threading difference (callback runs on the
    // encrypt thread, not on a worker).

    [Fact]
    public void LogHookSync_FiresOnCallingThread()
    {
        using var _ = new HookScope();
        var callerThreadId = Environment.CurrentManagedThreadId;
        int? observedThreadId = null;
        Asherah.SetLogHookSync(_ => observedThreadId = Environment.CurrentManagedThreadId);
        Asherah.Setup(CreateConfig(verbose: true));
        Asherah.EncryptString("sync-p1", "sync-payload");
        // No WaitFor — sync delivery means the callback has already run by
        // the time EncryptString returns.
        Asherah.Shutdown();
        Assert.NotNull(observedThreadId);
        Assert.Equal(callerThreadId, observedThreadId);
    }

    [Fact]
    public void LogHookSync_MinLevelFilter()
    {
        using var _ = new HookScope();
        var events = new ConcurrentBag<LogEvent>();
        Asherah.SetLogHookSync(e => events.Add(e), LogLevel.Warning);
        Asherah.Setup(CreateConfig(verbose: true));
        Asherah.EncryptString("sync-p2", "filter-payload");
        Asherah.Shutdown();
        Assert.All(events, e =>
            Assert.True(
                e.Level == LogLevel.Warning || e.Level == LogLevel.Error,
                $"unexpected {e.Level} record passed Warning filter: {e.Message}"));
    }

    [Fact]
    public void MetricsHookSync_FiresOnCallingThread()
    {
        using var _ = new HookScope();
        var callerThreadId = Environment.CurrentManagedThreadId;
        var observedThreadIds = new ConcurrentBag<int>();
        Asherah.SetMetricsHookSync(_ => observedThreadIds.Add(Environment.CurrentManagedThreadId));
        Asherah.Setup(CreateConfig());
        Asherah.EncryptString("sync-p3", "sync-payload");
        Asherah.Shutdown();
        Assert.NotEmpty(observedThreadIds);
        Assert.All(observedThreadIds, tid => Assert.Equal(callerThreadId, tid));
    }

    // ── Microsoft.Extensions.Logging.ILogger integration ──────────────
    //
    // These tests use a small CapturingLogger fake so they don't need
    // ASP.NET Core's hosting infrastructure. The contract being verified:
    // Asherah's bridge maps our LogEvent.Level to the correct
    // Microsoft.Extensions.Logging.LogLevel, and emits structured-format
    // messages.

    private sealed class CapturedLogEntry
    {
        public Microsoft.Extensions.Logging.LogLevel Level { get; init; }
        public string Message { get; init; } = string.Empty;
        public string Category { get; init; } = string.Empty;
    }

    private sealed class CapturingLogger : ILogger
    {
        private readonly string _category;
        private readonly ConcurrentBag<CapturedLogEntry> _captured;
        public CapturingLogger(string category, ConcurrentBag<CapturedLogEntry> captured)
        {
            _category = category;
            _captured = captured;
        }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;
        public void Log<TState>(
            Microsoft.Extensions.Logging.LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            _captured.Add(new CapturedLogEntry
            {
                Level = logLevel,
                Message = formatter(state, exception),
                Category = _category,
            });
        }
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public readonly ConcurrentBag<CapturedLogEntry> Captured = new();
        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, Captured);
        public void Dispose() { }
    }

    private sealed class CapturingLoggerFactory : ILoggerFactory
    {
        public readonly CapturingLoggerProvider Provider = new();
        public ILogger CreateLogger(string categoryName) => Provider.CreateLogger(categoryName);
        public void AddProvider(ILoggerProvider provider) { /* no-op */ }
        public void Dispose() { }
    }

    [Fact]
    public void SetLogHook_Accepts_ILogger_AndMapsLevels()
    {
        using var _ = new HookScope();
        var captured = new ConcurrentBag<CapturedLogEntry>();
        var logger = new CapturingLogger("test", captured);
        // Wide filter so the test exercises the level mapping.
        Asherah.SetLogHook(logger, queueCapacity: 0, minLevel: LogLevel.Trace);
        Asherah.Setup(CreateConfig(verbose: true));
        Asherah.EncryptString("ilogger-p", "via-ilogger");
        WaitFor(() => !captured.IsEmpty);
        Asherah.Shutdown();
        Assert.NotEmpty(captured);
        // Every captured entry must have a known M.E.L.LogLevel.
        foreach (var e in captured)
        {
            Assert.InRange((int)e.Level,
                (int)Microsoft.Extensions.Logging.LogLevel.Trace,
                (int)Microsoft.Extensions.Logging.LogLevel.Critical);
            Assert.False(string.IsNullOrWhiteSpace(e.Message));
        }
    }

    [Fact]
    public void SetLogHook_Accepts_ILoggerFactory_CategoriesByTarget()
    {
        using var _ = new HookScope();
        using var factory = new CapturingLoggerFactory();
        Asherah.SetLogHook(factory, queueCapacity: 0, minLevel: LogLevel.Trace);
        Asherah.Setup(CreateConfig(verbose: true));
        Asherah.EncryptString("ilf-p", "via-iloggerfactory");
        WaitFor(() => !factory.Provider.Captured.IsEmpty);
        Asherah.Shutdown();
        Assert.NotEmpty(factory.Provider.Captured);
        // Categories should come from our log targets (e.g. "asherah::session"),
        // not a single hard-coded category.
        var categories = factory.Provider.Captured.Select(e => e.Category).Distinct().ToList();
        Assert.NotEmpty(categories);
        Assert.All(categories, c => Assert.False(string.IsNullOrEmpty(c)));
    }

    [Fact]
    public void SetLogHookSync_Accepts_ILogger()
    {
        using var _ = new HookScope();
        var captured = new ConcurrentBag<CapturedLogEntry>();
        var logger = new CapturingLogger("sync", captured);
        Asherah.SetLogHookSync(logger, LogLevel.Trace);
        Asherah.Setup(CreateConfig(verbose: true));
        Asherah.EncryptString("ilogger-sync-p", "sync-via-ilogger");
        // Sync delivery — no WaitFor needed.
        Asherah.Shutdown();
        Assert.NotEmpty(captured);
    }

    // ── System.Diagnostics.Metrics.Meter integration ──────────────────
    //
    // MeterListener gives us the standard way to observe instrument
    // measurements without depending on OpenTelemetry. We verify the
    // bridge creates the documented instruments (asherah.encrypt.duration,
    // asherah.cache.hits, etc.) and emits to them.

    [Fact]
    public void SetMetricsHook_Accepts_Meter_EmitsToInstruments()
    {
        using var _ = new HookScope();
        using var meter = new Meter("Asherah.Test", "1.0");
        var observed = new ConcurrentBag<string>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter == meter)
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<double>((instrument, _, _, _) =>
            observed.Add(instrument.Name));
        listener.SetMeasurementEventCallback<long>((instrument, _, _, _) =>
            observed.Add(instrument.Name));
        listener.Start();

        Asherah.SetMetricsHook(meter);
        Asherah.Setup(CreateConfig());
        for (int i = 0; i < 3; i++)
        {
            var ct = Asherah.EncryptString("meter-p", $"payload-{i}");
            Asherah.DecryptString("meter-p", ct);
        }
        WaitFor(() =>
            observed.Contains("asherah.encrypt.duration") &&
            observed.Contains("asherah.decrypt.duration"));
        Asherah.Shutdown();
        listener.Dispose();

        // The bridge must have produced measurements on the documented
        // instruments. Cache instruments are best-effort (depends on
        // session caching), but encrypt+decrypt are deterministic.
        Assert.Contains("asherah.encrypt.duration", observed);
        Assert.Contains("asherah.decrypt.duration", observed);
    }

    [Fact]
    public void SetMetricsHookSync_Accepts_Meter()
    {
        using var _ = new HookScope();
        using var meter = new Meter("Asherah.SyncTest", "1.0");
        var observed = new ConcurrentBag<string>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter == meter) l.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<double>((instrument, _, _, _) =>
            observed.Add(instrument.Name));
        listener.Start();

        Asherah.SetMetricsHookSync(meter);
        Asherah.Setup(CreateConfig());
        var ct = Asherah.EncryptString("meter-sync-p", "sync-via-meter");
        Asherah.DecryptString("meter-sync-p", ct);
        Asherah.Shutdown();
        listener.Dispose();

        // Sync delivery — no WaitFor.
        Assert.Contains("asherah.encrypt.duration", observed);
    }

    private static string LocateRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Cargo.toml")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Unable to locate repository root");
    }
}
