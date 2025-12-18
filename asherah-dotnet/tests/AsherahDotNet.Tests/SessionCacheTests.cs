using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using GoDaddy.Asherah;
using Xunit;

namespace AsherahDotNet.Tests;

public class SessionCacheTests
{
    static SessionCacheTests()
    {
        Environment.SetEnvironmentVariable("SERVICE_NAME", Environment.GetEnvironmentVariable("SERVICE_NAME") ?? "svc");
        Environment.SetEnvironmentVariable("PRODUCT_ID", Environment.GetEnvironmentVariable("PRODUCT_ID") ?? "prod");
        Environment.SetEnvironmentVariable("KMS", Environment.GetEnvironmentVariable("KMS") ?? "static");
        Environment.SetEnvironmentVariable(
            "STATIC_MASTER_KEY_HEX",
            Environment.GetEnvironmentVariable("STATIC_MASTER_KEY_HEX")
                ?? "2222222222222222222222222222222222222222222222222222222222222222");

        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASHERAH_DOTNET_NATIVE")))
        {
            var root = LocateRepoRoot();
            var nativeRoot = Path.Combine(root, "target", "debug");
            Environment.SetEnvironmentVariable("ASHERAH_DOTNET_NATIVE", nativeRoot);
        }
    }

    [Fact]
    public void SessionCache_AllowsConcurrentEncrypt()
    {
        var config = AsherahConfig.CreateBuilder()
            .WithServiceName("svc")
            .WithProductId("prod")
            .WithMetastore("memory")
            .WithStaticMasterKey("22222222222222222222222222222222")
            .WithEnableSessionCaching(true)
            .WithSessionCacheMaxSize(10)
            .WithSessionCacheDuration(60)
            .Build();

        Asherah.Setup(config);
        try
        {
            Parallel.For(0, 20, i =>
            {
                var payload = $"payload-{i}";
                var ciphertext = Asherah.EncryptString("cached", payload);
                var recovered = Asherah.DecryptString("cached", ciphertext);
                Assert.Equal(payload, recovered);
            });
        }
        finally
        {
            Asherah.Shutdown();
        }
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
