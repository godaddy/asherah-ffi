using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using GoDaddy.Asherah;
using Xunit;

namespace GoDaddy.Asherah.AppEncryption.Tests;

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
            Asherah.SetLogHook(null);
            Asherah.SetMetricsHook(null);
            if (Asherah.GetSetupStatus()) Asherah.Shutdown();
        }
        public void Dispose()
        {
            Asherah.SetLogHook(null);
            Asherah.SetMetricsHook(null);
            if (Asherah.GetSetupStatus()) Asherah.Shutdown();
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
        var beforeClear = events.Count;
        Assert.True(beforeClear >= 1);
        Asherah.SetLogHook(null);
        Asherah.EncryptString("p2", "second");
        Asherah.Shutdown();
        Assert.Equal(beforeClear, events.Count);
    }

    [Fact]
    public void LogHook_Replace_KeepsFiring()
    {
        using var _ = new HookScope();
        var a = new ConcurrentBag<LogEvent>();
        var b = new ConcurrentBag<LogEvent>();
        Asherah.SetLogHook(e => a.Add(e));
        Asherah.Setup(CreateConfig(verbose: true));
        Asherah.EncryptString("p3", "first");
        Assert.NotEmpty(a);
        Asherah.SetLogHook(e => b.Add(e));
        Asherah.EncryptString("p3", "second");
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
        var beforeClear = events.Count;
        Assert.True(beforeClear > 0);
        Asherah.SetMetricsHook(null);
        Asherah.EncryptString("p6", "post-deregister");
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
        Assert.NotEmpty(a);
        Asherah.SetMetricsHook(e => b.Add(e));
        Asherah.EncryptString("p7", "second");
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
            Asherah.Shutdown();
            Asherah.SetMetricsHook(null);
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
        client.Shutdown();
        client.SetMetricsHook(null);
        Assert.NotEmpty(events);
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
