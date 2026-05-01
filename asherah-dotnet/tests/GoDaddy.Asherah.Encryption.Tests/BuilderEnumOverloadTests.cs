using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using GoDaddy.Asherah;
using Xunit;

namespace GoDaddy.Asherah.Encryption.Tests;

/// <summary>
/// Asserts emitted native JSON matches expected wire values when building with
/// <see cref="TimeSpan"/> durations (truncated toward whole seconds), nullable enums,
/// and <see cref="IReadOnlyDictionary{TKey,TValue}"/> for region maps — the shapes the FFI layer consumes.
///
/// Enum-only settings (e.g. <see cref="MetastoreKind"/>, <see cref="KmsKind"/>,
/// <see cref="ReplicaReadConsistency"/>, <see cref="VaultAuthMethod"/>)
/// are covered by explicit wire-string assertions earlier in this suite.
///
/// The wire format is what the Rust core actually consumes, so a
/// JSON-equality assertion is the strongest possible compatibility check
/// — any divergence (typo in the wire string, conversion bug in the
/// TimeSpan→seconds math, wrong RegionMap wiring) would
/// immediately surface here.
/// </summary>
public class BuilderEnumOverloadTests
{
    /// <summary>Internal accessor for the JSON the builder serialises into the FFI call.</summary>
    private static string ConfigToJson(AsherahConfig config)
    {
        var method = typeof(AsherahConfig).GetMethod(
            "ToJson", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new MissingMethodException(nameof(AsherahConfig), "ToJson");
        return (string)method.Invoke(config, null)!;
    }

    private static AsherahConfig.Builder BaseBuilder() =>
        AsherahConfig.CreateBuilder()
            .WithServiceName("svc")
            .WithProductId("prod")
            .WithMetastore(MetastoreKind.Memory)
            .WithKms(KmsKind.Static);

    private static void AssertJsonEqual(string a, string b)
    {
        using var da = JsonDocument.Parse(a);
        using var db = JsonDocument.Parse(b);
        AssertJsonElementsEqual(da.RootElement, db.RootElement, path: "$");
    }

    /// <summary>
    /// Structural JSON equality. Object members are compared key-by-key
    /// (insensitive to declaration order). Arrays are compared positionally.
    /// Necessary because Dictionary iteration order is unspecified and
    /// differs between Dictionary&lt;,&gt; and ImmutableDictionary&lt;,&gt;
    /// (and across .NET runtimes), so JSON-text equality would fail on
    /// equivalent RegionMap inputs.
    /// </summary>
    private static void AssertJsonElementsEqual(JsonElement a, JsonElement b, string path)
    {
        Assert.True(a.ValueKind == b.ValueKind,
            $"ValueKind differs at {path}: {a.ValueKind} vs {b.ValueKind}");
        switch (a.ValueKind)
        {
            case JsonValueKind.Object:
                var aProps = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                foreach (var p in a.EnumerateObject()) aProps[p.Name] = p.Value;
                var bProps = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
                foreach (var p in b.EnumerateObject()) bProps[p.Name] = p.Value;
                Assert.Equal(aProps.Keys.OrderBy(k => k), bProps.Keys.OrderBy(k => k));
                foreach (var k in aProps.Keys)
                {
                    AssertJsonElementsEqual(aProps[k], bProps[k], $"{path}.{k}");
                }
                break;
            case JsonValueKind.Array:
                var aArr = a.EnumerateArray().ToArray();
                var bArr = b.EnumerateArray().ToArray();
                Assert.True(aArr.Length == bArr.Length,
                    $"Array length differs at {path}: {aArr.Length} vs {bArr.Length}");
                for (int i = 0; i < aArr.Length; i++)
                {
                    AssertJsonElementsEqual(aArr[i], bArr[i], $"{path}[{i}]");
                }
                break;
            default:
                Assert.Equal(a.GetRawText(), b.GetRawText());
                break;
        }
    }

    // ───── Metastore ─────────────────────────────────────────────────

    [Theory]
    [InlineData(MetastoreKind.Memory, "memory")]
    [InlineData(MetastoreKind.Rdbms, "rdbms")]
    [InlineData(MetastoreKind.DynamoDb, "dynamodb")]
    [InlineData(MetastoreKind.Sqlite, "sqlite")]
    public void WithMetastore_SerializesExpectedWire(MetastoreKind kind, string expectedMetastore)
    {
        var cfg = BaseBuilder().WithMetastore(kind).Build();
        using var doc = JsonDocument.Parse(ConfigToJson(cfg));
        Assert.Equal(expectedMetastore, doc.RootElement.GetProperty("Metastore").GetString());
    }

    // ───── Kms ───────────────────────────────────────────────────────

    [Theory]
    [InlineData(KmsKind.Static, "static")]
    [InlineData(KmsKind.Aws, "aws")]
    [InlineData(KmsKind.SecretsManager, "secrets-manager")]
    [InlineData(KmsKind.Vault, "vault")]
    public void WithKms_SerializesExpectedWire(KmsKind kind, string expectedKms)
    {
        var cfg = BaseBuilder().WithKms(kind).Build();
        using var doc = JsonDocument.Parse(ConfigToJson(cfg));
        Assert.Equal(expectedKms, doc.RootElement.GetProperty("KMS").GetString());
    }

    // ───── ReplicaReadConsistency ────────────────────────────────────

    [Theory]
    [InlineData(ReplicaReadConsistency.Eventual, "eventual")]
    [InlineData(ReplicaReadConsistency.Global, "global")]
    [InlineData(ReplicaReadConsistency.Session, "session")]
    public void WithReplicaReadConsistency_SerializesExpectedWire(
        ReplicaReadConsistency value, string expectedWire)
    {
        var cfg = BaseBuilder().WithReplicaReadConsistency(value).Build();
        using var doc = JsonDocument.Parse(ConfigToJson(cfg));
        Assert.Equal(expectedWire, doc.RootElement.GetProperty("ReplicaReadConsistency").GetString());
    }

    [Fact]
    public void WithReplicaReadConsistency_NullEnum_OmitsField()
    {
        var fromEnum = BaseBuilder()
            .WithReplicaReadConsistency((ReplicaReadConsistency?)null).Build();
        var fromBase = BaseBuilder().Build();
        AssertJsonEqual(ConfigToJson(fromEnum), ConfigToJson(fromBase));
    }

    // ───── VaultAuthMethod ───────────────────────────────────────────

    [Theory]
    [InlineData(VaultAuthMethod.Kubernetes, "kubernetes")]
    [InlineData(VaultAuthMethod.AppRole, "approle")]
    [InlineData(VaultAuthMethod.Cert, "cert")]
    public void WithVaultAuthMethod_SerializesExpectedWire(VaultAuthMethod value, string expectedWire)
    {
        var cfg = BaseBuilder().WithKms(KmsKind.Vault).WithVaultAuthMethod(value).Build();
        using var doc = JsonDocument.Parse(ConfigToJson(cfg));
        Assert.Equal(expectedWire, doc.RootElement.GetProperty("VaultAuthMethod").GetString());
    }

    [Fact]
    public void WithVaultAuthMethod_NullEnum_OmitsField()
    {
        var fromEnum = BaseBuilder().WithVaultAuthMethod((VaultAuthMethod?)null).Build();
        var fromBase = BaseBuilder().Build();
        AssertJsonEqual(ConfigToJson(fromEnum), ConfigToJson(fromBase));
    }

    // ───── TimeSpan durations (truncated → whole-second JSON integers) ─

    [Fact]
    public void WithExpireAfter_NullTimeSpan_OmitsField()
    {
        var cfg = BaseBuilder().WithExpireAfter((TimeSpan?)null).Build();
        using var doc = JsonDocument.Parse(ConfigToJson(cfg));
        Assert.False(doc.RootElement.TryGetProperty("ExpireAfter", out _));
    }

    [Fact]
    public void WithExpireAfter_TruncatesSubsecond_Portions_ToWholeSecondsJson()
    {
        var cfg = BaseBuilder().WithExpireAfter(TimeSpan.FromMilliseconds(1500)).Build();
        Assert.Equal(1L, cfg.ExpireAfter);
        using var doc = JsonDocument.Parse(ConfigToJson(cfg));
        Assert.Equal(1, doc.RootElement.GetProperty("ExpireAfter").GetInt64());
    }

    [Fact]
    public void WithCheckInterval_SerializesWholeSeconds_FromTimeSpan()
    {
        var cfg = BaseBuilder().WithCheckInterval(TimeSpan.FromMinutes(60)).Build();
        using var doc = JsonDocument.Parse(ConfigToJson(cfg));
        Assert.Equal(3600, doc.RootElement.GetProperty("CheckInterval").GetInt64());
    }

    [Fact]
    public void WithSessionCacheDuration_SerializesWholeSeconds_FromTimeSpan()
    {
        var cfg = BaseBuilder().WithSessionCacheDuration(TimeSpan.FromMinutes(15)).Build();
        using var doc = JsonDocument.Parse(ConfigToJson(cfg));
        Assert.Equal(900, doc.RootElement.GetProperty("SessionCacheDuration").GetInt64());
    }

    [Fact]
    public void WithPoolMaxLifetime_AndPoolMaxIdleTime_SerializeTruncatedWholeSeconds()
    {
        var cfg = BaseBuilder()
            .WithPoolMaxLifetime(TimeSpan.FromMinutes(30))
            .WithPoolMaxIdleTime(TimeSpan.FromMinutes(5))
            .Build();
        using var doc = JsonDocument.Parse(ConfigToJson(cfg));
        Assert.Equal(1800, doc.RootElement.GetProperty("PoolMaxLifetime").GetInt64());
        Assert.Equal(300, doc.RootElement.GetProperty("PoolMaxIdleTime").GetInt64());
    }

    // ───── WithRegionMap (IReadOnlyDictionary) ─────────────────

    [Fact]
    public void WithRegionMap_Dictionary_AndImmutableDictionary_SameWireJson()
    {
        var src = new Dictionary<string, string>
        {
            ["us-east-1"] = "arn:aws:kms:us-east-1:111111111111:key/abc",
            ["us-west-2"] = "arn:aws:kms:us-west-2:111111111111:key/def",
        };
        var fromDict = BaseBuilder()
            .WithKms(KmsKind.Aws)
            .WithRegionMap(src)
            .Build();
        var fromImm = BaseBuilder()
            .WithKms(KmsKind.Aws)
            .WithRegionMap(src.ToImmutableDictionary())
            .Build();
        AssertJsonEqual(ConfigToJson(fromDict), ConfigToJson(fromImm));
    }

    [Fact]
    public void WithRegionMap_NullReadOnlyDictionary_OmitsField()
    {
        var fromNull = BaseBuilder()
            .WithKms(KmsKind.Aws)
            .WithRegionMap((IReadOnlyDictionary<string, string>?)null)
            .Build();
        var fromBase = BaseBuilder().WithKms(KmsKind.Aws).Build();
        AssertJsonEqual(ConfigToJson(fromNull), ConfigToJson(fromBase));
    }

    [Fact]
    public void WithRegionMap_StoresReference_BuiltConfigAliasesSameInstance()
    {
        var src = new Dictionary<string, string> { ["us-east-1"] = "a" };
        var built = BaseBuilder()
            .WithKms(KmsKind.Aws)
            .WithRegionMap(src)
            .Build();
        Assert.Same(src, built.RegionMap);
        src["us-east-1"] = "b";
        Assert.Equal("b", built.RegionMap!["us-east-1"]);
    }
}
