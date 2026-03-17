using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
            .WithKms("static")
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
            .WithKms("static")
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

    [Fact]
    public void AsherahClient_ImplementsIAsherah()
    {
        IAsherah client = new AsherahClient();

        var config = AsherahConfig.CreateBuilder()
            .WithServiceName("svc")
            .WithProductId("prod")
            .WithMetastore("memory")
            .WithKms("static")
            .WithEnableSessionCaching(true)
            .Build();

        client.Setup(config);
        try
        {
            Assert.True(client.GetSetupStatus());

            const string partition = "iface-test";
            const string plaintext = "interface payload";
            var ciphertext = client.EncryptString(partition, plaintext);
            var recovered = client.DecryptString(partition, ciphertext);
            Assert.Equal(plaintext, recovered);
        }
        finally
        {
            client.Shutdown();
        }

        Assert.False(client.GetSetupStatus());
    }

    [Fact]
    public void AsherahFactory_ImplementsIAsherahFactory()
    {
        IAsherahFactory factory = Asherah.FactoryFromEnv();
        try
        {
            IAsherahSession session = factory.GetSession("iface-factory-test");
            try
            {
                var ciphertext = session.EncryptString("factory interface payload");
                var recovered = session.DecryptString(ciphertext);
                Assert.Equal("factory interface payload", recovered);
            }
            finally
            {
                session.Dispose();
            }
        }
        finally
        {
            factory.Dispose();
        }
    }

    // --- FFI Boundary Tests ---

    private AsherahConfig CreateBoundaryConfig()
    {
        return AsherahConfig.CreateBuilder()
            .WithServiceName("ffi-test")
            .WithProductId("prod")
            .WithMetastore("memory")
            .WithKms("static")
            .WithEnableSessionCaching(false)
            .Build();
    }

    [Fact]
    public void Unicode_CJK_RoundTrip()
    {
        Asherah.Setup(CreateBoundaryConfig());
        try
        {
            const string text = "你好世界こんにちは세계";
            var ct = Asherah.EncryptString("dotnet-unicode", text);
            Assert.Equal(text, Asherah.DecryptString("dotnet-unicode", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Unicode_Emoji_RoundTrip()
    {
        Asherah.Setup(CreateBoundaryConfig());
        try
        {
            const string text = "🦀🔐🎉💾🌍";
            var ct = Asherah.EncryptString("dotnet-unicode", text);
            Assert.Equal(text, Asherah.DecryptString("dotnet-unicode", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Unicode_MixedScripts_RoundTrip()
    {
        Asherah.Setup(CreateBoundaryConfig());
        try
        {
            const string text = "Hello 世界 مرحبا Привет 🌍";
            var ct = Asherah.EncryptString("dotnet-unicode", text);
            Assert.Equal(text, Asherah.DecryptString("dotnet-unicode", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Unicode_CombiningCharacters_RoundTrip()
    {
        Asherah.Setup(CreateBoundaryConfig());
        try
        {
            var text = "e\u0301 n\u0303 a\u0308";
            var ct = Asherah.EncryptString("dotnet-unicode", text);
            Assert.Equal(text, Asherah.DecryptString("dotnet-unicode", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Unicode_ZwjSequence_RoundTrip()
    {
        Asherah.Setup(CreateBoundaryConfig());
        try
        {
            var text = "\U0001F468\u200D\U0001F469\u200D\U0001F467\u200D\U0001F466";
            var ct = Asherah.EncryptString("dotnet-unicode", text);
            Assert.Equal(text, Asherah.DecryptString("dotnet-unicode", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Binary_AllByteValues_RoundTrip()
    {
        using var factory = Asherah.FactoryFromEnv();
        using var session = factory.GetSession("dotnet-binary");

        var payload = new byte[256];
        for (int i = 0; i < 256; i++) payload[i] = (byte)i;

        var ct = session.EncryptBytes(payload);
        var recovered = session.DecryptBytes(ct);
        Assert.Equal(payload, recovered);
    }

    [Fact]
    public void Empty_Payload_RoundTrip()
    {
        using var factory = Asherah.FactoryFromEnv();
        using var session = factory.GetSession("dotnet-empty");

        var ct = session.EncryptBytes(Array.Empty<byte>());
        var recovered = session.DecryptBytes(ct);
        Assert.Empty(recovered);
    }

    [Fact]
    public void Large_1MB_Payload_RoundTrip()
    {
        using var factory = Asherah.FactoryFromEnv();
        using var session = factory.GetSession("dotnet-large");

        var payload = new byte[1024 * 1024];
        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 256);

        var ct = session.EncryptBytes(payload);
        var recovered = session.DecryptBytes(ct);
        Assert.Equal(payload.Length, recovered.Length);
        Assert.Equal(payload, recovered);
    }

    [Fact]
    public void Decrypt_InvalidJson_Throws()
    {
        Asherah.Setup(CreateBoundaryConfig());
        try
        {
            Assert.ThrowsAny<Exception>(() =>
                Asherah.DecryptString("dotnet-error", "not valid json"));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Decrypt_WrongPartition_Throws()
    {
        Asherah.Setup(CreateBoundaryConfig());
        try
        {
            var ct = Asherah.EncryptString("partition-a", "secret");
            Assert.ThrowsAny<Exception>(() =>
                Asherah.DecryptString("partition-b", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    // --- Factory/Session API Tests ---

    private AsherahConfig CreateFactoryConfig()
    {
        return AsherahConfig.CreateBuilder()
            .WithServiceName("factory-test")
            .WithProductId("prod")
            .WithMetastore("memory")
            .WithKms("static")
            .WithEnableSessionCaching(false)
            .Build();
    }

    [Fact]
    public void FactorySession_RoundTrip()
    {
        using var factory = Asherah.FactoryFromConfig(CreateFactoryConfig());
        using var session = factory.GetSession("factory-bytes");

        var plaintext = Encoding.UTF8.GetBytes("factory session payload");
        var ciphertext = session.EncryptBytes(plaintext);
        var recovered = session.DecryptBytes(ciphertext);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void FactorySession_StringApi()
    {
        using var factory = Asherah.FactoryFromConfig(CreateFactoryConfig());
        using var session = factory.GetSession("factory-string");

        const string plaintext = "factory string round-trip";
        var ciphertext = session.EncryptString(plaintext);
        var recovered = session.DecryptString(ciphertext);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void FactorySession_MultipleSessions()
    {
        using var factory = Asherah.FactoryFromConfig(CreateFactoryConfig());
        using var sessionA = factory.GetSession("partition-alpha");
        using var sessionB = factory.GetSession("partition-beta");

        const string plaintextA = "alpha payload";
        const string plaintextB = "beta payload";

        var ctA = sessionA.EncryptString(plaintextA);
        var ctB = sessionB.EncryptString(plaintextB);

        // Each session can decrypt its own ciphertext
        Assert.Equal(plaintextA, sessionA.DecryptString(ctA));
        Assert.Equal(plaintextB, sessionB.DecryptString(ctB));

        // Cross-partition decrypt should fail
        Assert.ThrowsAny<Exception>(() => sessionB.DecryptString(ctA));
        Assert.ThrowsAny<Exception>(() => sessionA.DecryptString(ctB));
    }

    [Fact]
    public void FactorySession_DisposePreventsUse()
    {
        using var factory = Asherah.FactoryFromConfig(CreateFactoryConfig());
        var session = factory.GetSession("dispose-test");
        session.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            session.EncryptBytes(Encoding.UTF8.GetBytes("should fail")));
    }

    [Fact]
    public async Task ConcurrentEncryptDecrypt()
    {
        using var factory = Asherah.FactoryFromConfig(CreateFactoryConfig());

        var tasks = Enumerable.Range(0, 10).Select(i => Task.Run(() =>
        {
            using var session = factory.GetSession($"concurrent-{i}");
            var plaintext = $"concurrent payload {i}";
            var ciphertext = session.EncryptString(plaintext);
            var recovered = session.DecryptString(ciphertext);
            Assert.Equal(plaintext, recovered);
        })).ToArray();

        await Task.WhenAll(tasks);
    }

    [Fact]
    public void ConfigValidation_MissingServiceName()
    {
        Assert.Throws<InvalidOperationException>(() =>
            AsherahConfig.CreateBuilder()
                .WithProductId("prod")
                .WithMetastore("memory")
                .WithKms("static")
                .Build());
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
