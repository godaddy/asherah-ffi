using System.Reflection;
using GoDaddy.Asherah.AppEncryption;
using Microsoft.Extensions.Caching.Memory;
using Xunit;

namespace AsherahDotNet.SharedTests;

public class SessionCacheTests
{
    static SessionCacheTests()
    {
        TestHelpers.EnsureNativeLibraryConfigured();
    }

    [Fact]
    public void Cache_ReusesSessionForSamePartition()
    {
        using SessionFactory factory = TestHelpers.CreateSessionFactory(
            enableSessionCache: true,
            sessionCacheMaxSize: 10,
            sessionCacheExpireMillis: 60000);

        _ = factory.GetSessionJson("partition-cache");
        _ = factory.GetSessionJson("partition-cache");

        MemoryCache cache = GetSessionCache(factory);
        Assert.Equal(1, cache.Count);
    }

    private static MemoryCache GetSessionCache(SessionFactory factory)
    {
        var prop = typeof(SessionFactory).GetProperty(
            "SessionCache",
            BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public);
        Assert.NotNull(prop);
        return (MemoryCache)prop!.GetValue(factory)!;
    }
}
