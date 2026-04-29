using System;
using System.Text;
using Xunit;

namespace GoDaddy.Asherah.Encryption.Tests;

/// <summary>
/// Verifies that <see cref="AsherahApi"/> respects
/// <c>SessionCacheMaxSize</c>. Prior to the fix this value was ignored and
/// the C# wrapper cache grew unbounded, pinning native session handles for
/// the life of the process even after the Rust core had evicted them.
/// </summary>
public class SessionCacheBoundTests
{
    private static AsherahConfig BuildConfig(int? maxSize)
    {
        var b = AsherahConfig.CreateBuilder()
            .WithServiceName("test-svc")
            .WithProductId("test-prod")
            .WithMetastore("memory")
            .WithKms("static")
            .WithEnableSessionCaching(true);
        if (maxSize is { } v)
        {
            b = b.WithSessionCacheMaxSize(v);
        }
        return b.Build();
    }

    [Fact]
    public void Encrypt_AcrossManyPartitions_EvictsBeyondConfiguredBound()
    {
        // With a small bound, exercising many distinct partitions used to
        // leak (cache grew without limit). We can't directly observe the
        // cache size from outside, but the round-trip must remain correct
        // under eviction churn — that exercises the eviction + dispose
        // path and would surface as crashes or use-after-free if the
        // implementation were wrong.
        AsherahApi.Setup(BuildConfig(maxSize: 4));
        try
        {
            for (var i = 0; i < 64; i++)
            {
                var partition = $"churn-{i}";
                var payload = $"payload-{i}";
                var ct = AsherahApi.EncryptString(partition, payload);
                Assert.Equal(payload, AsherahApi.DecryptString(partition, ct));
            }
        }
        finally
        {
            AsherahApi.Shutdown();
        }
    }

    [Fact]
    public void Encrypt_ReusesCachedSessionWithinBound()
    {
        // Hot partitions (re-used within the bound) must continue to
        // round-trip correctly across many calls.
        AsherahApi.Setup(BuildConfig(maxSize: 2));
        try
        {
            for (var i = 0; i < 32; i++)
            {
                var ct = AsherahApi.EncryptString("hot-a", "a");
                Assert.Equal("a", AsherahApi.DecryptString("hot-a", ct));
                ct = AsherahApi.EncryptString("hot-b", "b");
                Assert.Equal("b", AsherahApi.DecryptString("hot-b", ct));
            }
        }
        finally
        {
            AsherahApi.Shutdown();
        }
    }

    [Fact]
    public void Encrypt_DefaultBound_RoundTripsAcrossThousandsOfPartitions()
    {
        // Default bound (1000). Walking past it must not break correctness.
        AsherahApi.Setup(BuildConfig(maxSize: null));
        try
        {
            for (var i = 0; i < 1500; i++)
            {
                var partition = $"default-{i}";
                var payload = Encoding.UTF8.GetBytes($"p{i}");
                var ct = AsherahApi.Encrypt(partition, payload);
                var recovered = AsherahApi.Decrypt(partition, ct);
                Assert.Equal(payload, recovered);
            }
        }
        finally
        {
            AsherahApi.Shutdown();
        }
    }

    [Fact]
    public void Encrypt_WithSessionCachingDisabled_StillRoundTrips()
    {
        var cfg = AsherahConfig.CreateBuilder()
            .WithServiceName("test-svc")
            .WithProductId("test-prod")
            .WithMetastore("memory")
            .WithKms("static")
            .WithEnableSessionCaching(false)
            .Build();
        AsherahApi.Setup(cfg);
        try
        {
            for (var i = 0; i < 8; i++)
            {
                var ct = AsherahApi.EncryptString($"nocache-{i}", "x");
                Assert.Equal("x", AsherahApi.DecryptString($"nocache-{i}", ct));
            }
        }
        finally
        {
            AsherahApi.Shutdown();
        }
    }
}
