using System;
using System.IO;
using System.Text;
using GoDaddy.Asherah;
using Xunit;

namespace AsherahDotNet.Tests;

public class RoundTripTests
{
    static RoundTripTests()
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
    public void EncryptDecrypt_RoundTrip()
    {
        using var factory = Asherah.FactoryFromEnv();
        using var session = factory.GetSession("dotnet-test");

        var plaintext = Encoding.UTF8.GetBytes("dotnet secret payload");
        var json = session.EncryptString(Encoding.UTF8.GetString(plaintext));
        var recovered = session.DecryptString(json);

        Assert.Equal("dotnet secret payload", recovered);
    }

    [Fact]
    public void Setup_GlobalEncryptDecrypt()
    {
        var config = AsherahConfig.CreateBuilder()
            .WithServiceName("svc")
            .WithProductId("prod")
            .WithMetastore("memory")
            .WithStaticMasterKey("22222222222222222222222222222222")
            .WithEnableSessionCaching(true)
            .WithVerbose(false)
            .Build();

        Asherah.Setup(config);
        try
        {
            const string partition = "dotnet-setup";
            const string plaintext = "setup payload";
            var ciphertext = Asherah.EncryptString(partition, plaintext);
            var recovered = Asherah.DecryptString(partition, ciphertext);
            Assert.Equal(plaintext, recovered);
        }
        finally
        {
            Asherah.Shutdown();
        }
    }

    [Fact]
    public void Setup_CanBeRepeatedAfterShutdown()
    {
        var config = AsherahConfig.CreateBuilder()
            .WithServiceName("svc")
            .WithProductId("prod")
            .WithMetastore("memory")
            .WithStaticMasterKey("22222222222222222222222222222222")
            .Build();

        Asherah.Setup(config);
        Asherah.Shutdown();

        Asherah.Setup(config);
        try
        {
            var ciphertext = Asherah.EncryptString("repeat", "payload");
            var recovered = Asherah.DecryptString("repeat", ciphertext);
            Assert.Equal("payload", recovered);
        }
        finally
        {
            Asherah.Shutdown();
        }

        Assert.False(Asherah.GetSetupStatus());
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
