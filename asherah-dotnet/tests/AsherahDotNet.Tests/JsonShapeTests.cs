using System;
using System.IO;
using System.Text;
using System.Text.Json;
using GoDaddy.Asherah;
using Xunit;

namespace AsherahDotNet.Tests;

public class JsonShapeTests
{
    static JsonShapeTests()
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
    public void Encrypt_EmitsDataRowRecordJsonShape()
    {
        using var factory = Asherah.FactoryFromEnv();
        using var session = factory.GetSession("dotnet-json-shape");

        var jsonBytes = session.EncryptBytes(Encoding.UTF8.GetBytes("shape test"));
        using var doc = JsonDocument.Parse(jsonBytes);

        Assert.True(doc.RootElement.TryGetProperty("Data", out var data));
        Assert.Equal(JsonValueKind.String, data.ValueKind);
        _ = Convert.FromBase64String(data.GetString()!);

        Assert.True(doc.RootElement.TryGetProperty("Key", out var key));
        Assert.Equal(JsonValueKind.Object, key.ValueKind);
        Assert.True(key.TryGetProperty("Created", out _));
        Assert.True(key.TryGetProperty("Key", out _));
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
