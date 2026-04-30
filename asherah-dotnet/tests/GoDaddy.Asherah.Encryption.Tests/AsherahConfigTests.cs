using System.Text.Json;
using GoDaddy.Asherah;
using GoDaddy.Asherah.Encryption;
using Xunit;

namespace GoDaddy.Asherah.Encryption.Tests;

/// <summary>
/// Unit tests for config serialization (native JSON contract); does not call native FFI.
/// Optional fields are omitted from JSON when unset so the Rust FFI layer treats them as absent
/// (same effect as serde <c>None</c> for optional config fields).
/// </summary>
public class AsherahConfigTests
{
    private static AsherahConfig BuildMinimal(Action<AsherahConfig.Builder>? configure = null)
    {
        var b = AsherahConfig.CreateBuilder()
            .WithServiceName("svc")
            .WithProductId("prod")
            .WithMetastore(MetastoreKind.Memory)
            .WithKms(KmsKind.Static);
        configure?.Invoke(b);
        return b.Build();
    }

    [Fact]
    public void BuiltConfig_AwsProfileName_IsNull_WhenNotSet()
    {
        var cfg = BuildMinimal();
        Assert.Null(cfg.AwsProfileName);
    }

    [Fact]
    public void BuiltConfig_AwsProfileName_IsSet_WhenProvided()
    {
        var cfg = BuildMinimal(b => b.WithAwsProfileName("prod"));
        Assert.Equal("prod", cfg.AwsProfileName);
    }

    [Fact]
    public void BuiltConfig_AwsProfileName_Cleared_WhenSetToNull()
    {
        var cfg = BuildMinimal(b => b.WithAwsProfileName("staging").WithAwsProfileName(null));
        Assert.Null(cfg.AwsProfileName);
    }

    [Fact]
    public void ToJson_OmitsAwsProfileName_WhenUnset()
    {
        var json = BuildMinimal().ToJson();
        using var doc = JsonDocument.Parse(json);
        Assert.False(doc.RootElement.TryGetProperty("AwsProfileName", out _));
    }

    [Fact]
    public void ToJson_AwsProfileName_IsString_WhenSet()
    {
        var json = BuildMinimal(b => b.WithAwsProfileName("prod")).ToJson();
        using var doc = JsonDocument.Parse(json);
        Assert.True(doc.RootElement.TryGetProperty("AwsProfileName", out var prop));
        Assert.Equal(JsonValueKind.String, prop.ValueKind);
        Assert.Equal("prod", prop.GetString());
    }

    [Fact]
    public void ToJson_OmitsAwsProfileName_WhenClearedWithNull()
    {
        var json = BuildMinimal(b => b.WithAwsProfileName("staging").WithAwsProfileName(null)).ToJson();
        using var doc = JsonDocument.Parse(json);
        Assert.False(doc.RootElement.TryGetProperty("AwsProfileName", out _));
    }
}
