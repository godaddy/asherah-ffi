using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using GoDaddy.Asherah;
using Xunit;

namespace GoDaddy.Asherah.AppEncryption.Tests;

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

    private AsherahConfig CreateConfig(bool sessionCaching = false)
    {
        return AsherahConfig.CreateBuilder()
            .WithServiceName("test-svc")
            .WithProductId("test-prod")
            .WithMetastore("memory")
            .WithKms("static")
            .WithEnableSessionCaching(sessionCaching)
            .Build();
    }

    // ============================================================
    // Factory/Session API (core pattern)
    // ============================================================

    [Fact]
    public void FactoryFromEnv_RoundTrip()
    {
        using var factory = Asherah.FactoryFromEnv();
        using var session = factory.GetSession("env-test");

        var plaintext = Encoding.UTF8.GetBytes("dotnet secret payload");
        var json = session.EncryptString(Encoding.UTF8.GetString(plaintext));
        var recovered = session.DecryptString(json);

        Assert.Equal("dotnet secret payload", recovered);
    }

    [Fact]
    public void FactoryFromConfig_BytesRoundTrip()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("factory-bytes");

        var plaintext = Encoding.UTF8.GetBytes("factory bytes payload");
        var ciphertext = session.EncryptBytes(plaintext);
        var recovered = session.DecryptBytes(ciphertext);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void FactoryFromConfig_StringRoundTrip()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("factory-string");

        const string plaintext = "factory string round-trip";
        var ciphertext = session.EncryptString(plaintext);
        var recovered = session.DecryptString(ciphertext);

        Assert.Equal(plaintext, recovered);
    }

    [Fact]
    public void Factory_MultipleSessions_PartitionIsolation()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var sessionA = factory.GetSession("partition-alpha");
        using var sessionB = factory.GetSession("partition-beta");

        var ctA = sessionA.EncryptString("alpha payload");
        var ctB = sessionB.EncryptString("beta payload");

        Assert.Equal("alpha payload", sessionA.DecryptString(ctA));
        Assert.Equal("beta payload", sessionB.DecryptString(ctB));

        Assert.ThrowsAny<Exception>(() => sessionB.DecryptString(ctA));
        Assert.ThrowsAny<Exception>(() => sessionA.DecryptString(ctB));
    }

    [Fact]
    public void Factory_ImplementsIAsherahFactory()
    {
        using IAsherahFactory factory = Asherah.FactoryFromEnv();
        using IAsherahSession session = factory.GetSession("iface-test");
        var ciphertext = session.EncryptString("interface payload");
        Assert.Equal("interface payload", session.DecryptString(ciphertext));
    }

    [Fact]
    public void Factory_DisposePreventsGetSession()
    {
        var factory = Asherah.FactoryFromConfig(CreateConfig());
        factory.Dispose();

        Assert.Throws<ObjectDisposedException>(() => factory.GetSession("should-fail"));
    }

    [Fact]
    public void Session_DisposePreventsUse()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        var session = factory.GetSession("dispose-test");
        session.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            session.EncryptBytes(Encoding.UTF8.GetBytes("should fail")));
    }

    [Fact]
    public async Task Factory_ConcurrentSessions()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());

        var tasks = Enumerable.Range(0, 10).Select(i => Task.Run(() =>
        {
            using var session = factory.GetSession($"concurrent-{i}");
            var plaintext = $"concurrent payload {i}";
            var ciphertext = session.EncryptString(plaintext);
            Assert.Equal(plaintext, session.DecryptString(ciphertext));
        })).ToArray();

        await Task.WhenAll(tasks);
    }

    // ============================================================
    // Static API (Asherah.Setup / Encrypt / Decrypt)
    // ============================================================

    [Fact]
    public void Setup_EncryptString_DecryptString()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            var ct = Asherah.EncryptString("static-str", "static payload");
            Assert.Equal("static payload", Asherah.DecryptString("static-str", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Setup_EncryptBytes_DecryptBytes()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            var plaintext = Encoding.UTF8.GetBytes("bytes payload");
            var ct = Asherah.Encrypt("static-bytes", plaintext);
            var recovered = Asherah.Decrypt("static-bytes", ct);
            Assert.Equal(plaintext, recovered);
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Setup_DecryptJson_StringInputBytesOutput()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            var ct = Asherah.EncryptString("json-test", "json payload");
            var recovered = Asherah.DecryptJson("json-test", ct);
            Assert.Equal("json payload", Encoding.UTF8.GetString(recovered));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public async Task SetupAsync_ShutdownAsync()
    {
        await Asherah.SetupAsync(CreateConfig());
        try
        {
            Assert.True(Asherah.GetSetupStatus());
            var ct = Asherah.EncryptString("async-setup", "async payload");
            Assert.Equal("async payload", Asherah.DecryptString("async-setup", ct));
        }
        finally
        {
            await Asherah.ShutdownAsync();
        }
        Assert.False(Asherah.GetSetupStatus());
    }

    [Fact]
    public async Task EncryptAsync_DecryptAsync_Bytes()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            var plaintext = Encoding.UTF8.GetBytes("async bytes");
            var ct = await Asherah.EncryptAsync("async-bytes", plaintext);
            var recovered = await Asherah.DecryptAsync("async-bytes", ct);
            Assert.Equal(plaintext, recovered);
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public async Task EncryptStringAsync_DecryptStringAsync()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            var ct = await Asherah.EncryptStringAsync("async-str", "async string payload");
            var recovered = await Asherah.DecryptStringAsync("async-str", ct);
            Assert.Equal("async string payload", recovered);
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Setup_ShutdownCycle()
    {
        var config = CreateConfig();
        Asherah.Setup(config);
        Asherah.Shutdown();

        Asherah.Setup(config);
        try
        {
            var ct = Asherah.EncryptString("cycle", "cycle payload");
            Assert.Equal("cycle payload", Asherah.DecryptString("cycle", ct));
        }
        finally { Asherah.Shutdown(); }

        Assert.False(Asherah.GetSetupStatus());
    }

    [Fact]
    public void Setup_DoubleSetup_Throws()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            Assert.Throws<InvalidOperationException>(() => Asherah.Setup(CreateConfig()));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Shutdown_WhenNotConfigured_IsIdempotent()
    {
        // Should not throw
        Asherah.Shutdown();
        Asherah.Shutdown();
    }

    [Fact]
    public void Setup_WithSessionCaching()
    {
        Asherah.Setup(CreateConfig(sessionCaching: true));
        try
        {
            // Multiple operations on same partition should use cached session
            var ct1 = Asherah.EncryptString("cached-p", "first");
            var ct2 = Asherah.EncryptString("cached-p", "second");
            Assert.Equal("first", Asherah.DecryptString("cached-p", ct1));
            Assert.Equal("second", Asherah.DecryptString("cached-p", ct2));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void SetEnv_SetsEnvironmentVariables()
    {
        var env = new Dictionary<string, string?> { ["ASHERAH_TEST_VAR"] = "test_value" };
        Asherah.SetEnv(env);
        Assert.Equal("test_value", Environment.GetEnvironmentVariable("ASHERAH_TEST_VAR"));
        Environment.SetEnvironmentVariable("ASHERAH_TEST_VAR", null);
    }

    [Fact]
    public void AsherahClient_ImplementsIAsherah()
    {
        IAsherah client = new AsherahClient();

        client.Setup(CreateConfig());
        try
        {
            Assert.True(client.GetSetupStatus());
            var ct = client.EncryptString("client-test", "client payload");
            Assert.Equal("client payload", client.DecryptString("client-test", ct));
        }
        finally { client.Shutdown(); }

        Assert.False(client.GetSetupStatus());
    }

    // ============================================================
    // Config validation
    // ============================================================

    [Fact]
    public void Config_MissingServiceName_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            AsherahConfig.CreateBuilder()
                .WithProductId("prod")
                .WithMetastore("memory")
                .Build());
    }

    [Fact]
    public void Config_MissingProductId_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            AsherahConfig.CreateBuilder()
                .WithServiceName("svc")
                .WithMetastore("memory")
                .Build());
    }

    [Fact]
    public void Config_MissingMetastore_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            AsherahConfig.CreateBuilder()
                .WithServiceName("svc")
                .WithProductId("prod")
                .Build());
    }

    // ============================================================
    // FFI boundary — data integrity
    // ============================================================

    [Fact]
    public void Unicode_CJK_RoundTrip()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            const string text = "你好世界こんにちは세계";
            var ct = Asherah.EncryptString("unicode", text);
            Assert.Equal(text, Asherah.DecryptString("unicode", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Unicode_Emoji_RoundTrip()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            const string text = "🦀🔐🎉💾🌍";
            var ct = Asherah.EncryptString("unicode", text);
            Assert.Equal(text, Asherah.DecryptString("unicode", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Unicode_MixedScripts_RoundTrip()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            const string text = "Hello 世界 مرحبا Привет 🌍";
            var ct = Asherah.EncryptString("unicode", text);
            Assert.Equal(text, Asherah.DecryptString("unicode", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Unicode_CombiningCharacters_RoundTrip()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            var text = "e\u0301 n\u0303 a\u0308";
            var ct = Asherah.EncryptString("unicode", text);
            Assert.Equal(text, Asherah.DecryptString("unicode", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Unicode_ZwjSequence_RoundTrip()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            var text = "\U0001F468\u200D\U0001F469\u200D\U0001F467\u200D\U0001F466";
            var ct = Asherah.EncryptString("unicode", text);
            Assert.Equal(text, Asherah.DecryptString("unicode", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Binary_AllByteValues_RoundTrip()
    {
        using var factory = Asherah.FactoryFromEnv();
        using var session = factory.GetSession("binary");

        var payload = new byte[256];
        for (int i = 0; i < 256; i++) payload[i] = (byte)i;

        var ct = session.EncryptBytes(payload);
        Assert.Equal(payload, session.DecryptBytes(ct));
    }

    [Fact]
    public void Empty_Payload_RoundTrip()
    {
        using var factory = Asherah.FactoryFromEnv();
        using var session = factory.GetSession("empty");

        var ct = session.EncryptBytes(Array.Empty<byte>());
        Assert.Empty(session.DecryptBytes(ct));
    }

    [Fact]
    public void Large_1MB_Payload_RoundTrip()
    {
        using var factory = Asherah.FactoryFromEnv();
        using var session = factory.GetSession("large");

        var payload = new byte[1024 * 1024];
        for (int i = 0; i < payload.Length; i++) payload[i] = (byte)(i % 256);

        var ct = session.EncryptBytes(payload);
        var recovered = session.DecryptBytes(ct);
        Assert.Equal(payload.Length, recovered.Length);
        Assert.Equal(payload, recovered);
    }

    // ============================================================
    // Error handling
    // ============================================================

    [Fact]
    public void Decrypt_InvalidJson_Throws()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            Assert.ThrowsAny<Exception>(() =>
                Asherah.DecryptString("error", "not valid json"));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Decrypt_WrongPartition_Throws()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            var ct = Asherah.EncryptString("partition-a", "secret");
            Assert.ThrowsAny<Exception>(() =>
                Asherah.DecryptString("partition-b", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Encrypt_WithoutSetup_Throws()
    {
        Assert.ThrowsAny<Exception>(() =>
            Asherah.EncryptString("no-setup", "should fail"));
    }

    // ============================================================
    // Null and empty input handling
    //
    // Contract:
    //   - null arguments are programming errors → ArgumentNullException
    //     thrown by the binding before reaching native code.
    //   - empty string / empty byte[] is a valid cryptographic operation
    //     and must round-trip back to empty.
    //   - decrypting an empty string is invalid JSON and must throw.
    // ============================================================

    [Fact]
    public void Session_EncryptBytes_Null_Throws()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("null-bytes");
        Assert.Throws<ArgumentNullException>(() => session.EncryptBytes(null!));
    }

    [Fact]
    public void Session_EncryptString_Null_Throws()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("null-string");
        Assert.Throws<ArgumentNullException>(() => session.EncryptString(null!));
    }

    [Fact]
    public void Session_DecryptBytes_Null_Throws()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("null-decrypt-bytes");
        Assert.Throws<ArgumentNullException>(() => session.DecryptBytes(null!));
    }

    [Fact]
    public void Session_DecryptString_Null_Throws()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("null-decrypt-string");
        Assert.Throws<ArgumentNullException>(() => session.DecryptString(null!));
    }

    [Fact]
    public async Task Session_EncryptBytesAsync_Null_Throws()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("null-bytes-async");
        await Assert.ThrowsAsync<ArgumentNullException>(() => session.EncryptBytesAsync(null!));
    }

    [Fact]
    public async Task Session_EncryptStringAsync_Null_Throws()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("null-string-async");
        await Assert.ThrowsAsync<ArgumentNullException>(() => session.EncryptStringAsync(null!));
    }

    [Fact]
    public async Task Session_DecryptBytesAsync_Null_Throws()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("null-decrypt-bytes-async");
        await Assert.ThrowsAsync<ArgumentNullException>(() => session.DecryptBytesAsync(null!));
    }

    [Fact]
    public async Task Session_DecryptStringAsync_Null_Throws()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("null-decrypt-string-async");
        await Assert.ThrowsAsync<ArgumentNullException>(() => session.DecryptStringAsync(null!));
    }

    [Fact]
    public void Factory_GetSession_Null_Throws()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        Assert.Throws<ArgumentNullException>(() => factory.GetSession(null!));
    }

    [Fact]
    public void StaticApi_Encrypt_NullPartition_Throws()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            Assert.Throws<ArgumentNullException>(() =>
                Asherah.Encrypt(null!, Encoding.UTF8.GetBytes("x")));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void StaticApi_Encrypt_NullPlaintext_Throws()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            Assert.Throws<ArgumentNullException>(() =>
                Asherah.Encrypt("p", null!));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void StaticApi_EncryptString_NullPlaintext_Throws()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            Assert.Throws<ArgumentNullException>(() =>
                Asherah.EncryptString("p", null!));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void StaticApi_Decrypt_NullPartition_Throws()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            Assert.Throws<ArgumentNullException>(() =>
                Asherah.Decrypt(null!, new byte[] { 0 }));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void StaticApi_Decrypt_NullCiphertext_Throws()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            Assert.Throws<ArgumentNullException>(() => Asherah.Decrypt("p", null!));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void StaticApi_DecryptString_NullCiphertext_Throws()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            Assert.Throws<ArgumentNullException>(() =>
                Asherah.DecryptString("p", null!));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public async Task StaticApi_EncryptAsync_NullPlaintext_Throws()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                Asherah.EncryptAsync("p", null!));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public async Task StaticApi_DecryptAsync_NullCiphertext_Throws()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                Asherah.DecryptAsync("p", null!));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Session_EmptyString_RoundTrip()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("empty-string");

        var ct = session.EncryptString(string.Empty);
        Assert.NotEqual(string.Empty, ct); // ciphertext envelope is non-empty
        Assert.Equal(string.Empty, session.DecryptString(ct));
    }

    [Fact]
    public void Session_EmptyBytes_RoundTrip_StaticApi()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            var ct = Asherah.Encrypt("empty-bytes-static", Array.Empty<byte>());
            Assert.NotEmpty(ct);
            Assert.Empty(Asherah.Decrypt("empty-bytes-static", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public void Session_EmptyString_RoundTrip_StaticApi()
    {
        Asherah.Setup(CreateConfig());
        try
        {
            var ct = Asherah.EncryptString("empty-string-static", string.Empty);
            Assert.NotEqual(string.Empty, ct);
            Assert.Equal(string.Empty, Asherah.DecryptString("empty-string-static", ct));
        }
        finally { Asherah.Shutdown(); }
    }

    [Fact]
    public async Task Session_EmptyBytes_RoundTripAsync()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("empty-bytes-async");

        var ct = await session.EncryptBytesAsync(Array.Empty<byte>());
        Assert.NotEmpty(ct);
        Assert.Empty(await session.DecryptBytesAsync(ct));
    }

    [Fact]
    public async Task Session_EmptyString_RoundTripAsync()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("empty-string-async");

        var ct = await session.EncryptStringAsync(string.Empty);
        Assert.NotEqual(string.Empty, ct);
        Assert.Equal(string.Empty, await session.DecryptStringAsync(ct));
    }

    [Fact]
    public void Session_DecryptEmptyString_Throws()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("decrypt-empty");

        // Empty input is not a valid DataRowRecord — must throw, not return empty.
        Assert.ThrowsAny<Exception>(() => session.DecryptString(string.Empty));
    }

    [Fact]
    public void Session_DecryptEmptyBytes_Throws()
    {
        using var factory = Asherah.FactoryFromConfig(CreateConfig());
        using var session = factory.GetSession("decrypt-empty-bytes");

        Assert.ThrowsAny<Exception>(() => session.DecryptBytes(Array.Empty<byte>()));
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
