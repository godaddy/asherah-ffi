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
/// Asserts that the strongly-typed enum / TimeSpan / IReadOnlyDictionary
/// overloads on <see cref="AsherahConfig.Builder"/> produce wire JSON
/// byte-identical to the existing string / long-seconds / IDictionary
/// overloads they delegate to.
///
/// The wire format is what the Rust core actually consumes, so a
/// JSON-equality assertion is the strongest possible compatibility check
/// — any divergence (typo in the wire string, conversion bug in the
/// TimeSpan→seconds math, missing key in the dictionary copy) would
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
            .WithMetastore("memory")
            .WithKms("static");

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
    public void WithMetastore_EnumOverload_MatchesStringOverload(MetastoreKind kind, string wire)
    {
        var fromEnum = AsherahConfig.CreateBuilder()
            .WithServiceName("svc").WithProductId("prod").WithKms("static")
            .WithMetastore(kind).Build();
        var fromString = AsherahConfig.CreateBuilder()
            .WithServiceName("svc").WithProductId("prod").WithKms("static")
            .WithMetastore(wire).Build();
        AssertJsonEqual(ConfigToJson(fromEnum), ConfigToJson(fromString));
    }

    // ───── Kms ───────────────────────────────────────────────────────

    [Theory]
    [InlineData(KmsKind.Static, "static")]
    [InlineData(KmsKind.Aws, "aws")]
    [InlineData(KmsKind.SecretsManager, "secrets-manager")]
    [InlineData(KmsKind.Vault, "vault")]
    public void WithKms_EnumOverload_MatchesStringOverload(KmsKind kind, string wire)
    {
        var fromEnum = BaseBuilder().WithKms(kind).Build();
        var fromString = BaseBuilder().WithKms(wire).Build();
        AssertJsonEqual(ConfigToJson(fromEnum), ConfigToJson(fromString));
    }

    // ───── ReplicaReadConsistency ────────────────────────────────────

    [Theory]
    [InlineData(ReplicaReadConsistency.Eventual, "eventual")]
    [InlineData(ReplicaReadConsistency.Global, "global")]
    [InlineData(ReplicaReadConsistency.Session, "session")]
    public void WithReplicaReadConsistency_EnumOverload_MatchesStringOverload(
        ReplicaReadConsistency value, string wire)
    {
        var fromEnum = BaseBuilder().WithReplicaReadConsistency(value).Build();
        var fromString = BaseBuilder().WithReplicaReadConsistency(wire).Build();
        AssertJsonEqual(ConfigToJson(fromEnum), ConfigToJson(fromString));
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
    public void WithVaultAuthMethod_EnumOverload_MatchesStringOverload(
        VaultAuthMethod value, string wire)
    {
        var fromEnum = BaseBuilder().WithKms(KmsKind.Vault).WithVaultAuthMethod(value).Build();
        var fromString = BaseBuilder().WithKms("vault").WithVaultAuthMethod(wire).Build();
        AssertJsonEqual(ConfigToJson(fromEnum), ConfigToJson(fromString));
    }

    [Fact]
    public void WithVaultAuthMethod_NullEnum_OmitsField()
    {
        var fromEnum = BaseBuilder().WithVaultAuthMethod((VaultAuthMethod?)null).Build();
        var fromBase = BaseBuilder().Build();
        AssertJsonEqual(ConfigToJson(fromEnum), ConfigToJson(fromBase));
    }

    // ───── TimeSpan overloads ────────────────────────────────────────

    [Fact]
    public void WithExpireAfter_TimeSpan_MatchesSecondsOverload()
    {
        var fromTs = BaseBuilder().WithExpireAfter(TimeSpan.FromDays(90)).Build();
        var fromLong = BaseBuilder().WithExpireAfter(90L * 24 * 60 * 60).Build();
        AssertJsonEqual(ConfigToJson(fromTs), ConfigToJson(fromLong));
    }

    [Fact]
    public void WithExpireAfter_NullTimeSpan_OmitsField()
    {
        var fromTs = BaseBuilder().WithExpireAfter((TimeSpan?)null).Build();
        var fromBase = BaseBuilder().Build();
        AssertJsonEqual(ConfigToJson(fromTs), ConfigToJson(fromBase));
    }

    [Fact]
    public void WithExpireAfter_TimeSpan_RoundsDownToWholeSeconds()
    {
        // 1.5s → 1s (truncated). Verifies the (long)TotalSeconds semantics.
        var fromTs = BaseBuilder().WithExpireAfter(TimeSpan.FromMilliseconds(1500)).Build();
        var fromLong = BaseBuilder().WithExpireAfter(1L).Build();
        AssertJsonEqual(ConfigToJson(fromTs), ConfigToJson(fromLong));
    }

    [Fact]
    public void WithCheckInterval_TimeSpan_MatchesSecondsOverload()
    {
        var fromTs = BaseBuilder().WithCheckInterval(TimeSpan.FromMinutes(60)).Build();
        var fromLong = BaseBuilder().WithCheckInterval(3600L).Build();
        AssertJsonEqual(ConfigToJson(fromTs), ConfigToJson(fromLong));
    }

    [Fact]
    public void WithSessionCacheDuration_TimeSpan_MatchesSecondsOverload()
    {
        var fromTs = BaseBuilder().WithSessionCacheDuration(TimeSpan.FromMinutes(15)).Build();
        var fromLong = BaseBuilder().WithSessionCacheDuration(900L).Build();
        AssertJsonEqual(ConfigToJson(fromTs), ConfigToJson(fromLong));
    }

    [Fact]
    public void WithPoolMaxLifetime_TimeSpan_MatchesSecondsOverload()
    {
        var fromTs = BaseBuilder().WithPoolMaxLifetime(TimeSpan.FromMinutes(30)).Build();
        var fromLong = BaseBuilder().WithPoolMaxLifetime(1800L).Build();
        AssertJsonEqual(ConfigToJson(fromTs), ConfigToJson(fromLong));
    }

    [Fact]
    public void WithPoolMaxIdleTime_TimeSpan_MatchesSecondsOverload()
    {
        var fromTs = BaseBuilder().WithPoolMaxIdleTime(TimeSpan.FromMinutes(5)).Build();
        var fromLong = BaseBuilder().WithPoolMaxIdleTime(300L).Build();
        AssertJsonEqual(ConfigToJson(fromTs), ConfigToJson(fromLong));
    }

    // ───── WithRegionMap IReadOnlyDictionary overload ────────────────

    [Fact]
    public void WithRegionMap_ReadOnlyDictionary_MatchesIDictionaryOverload()
    {
        var src = new Dictionary<string, string>
        {
            ["us-east-1"] = "arn:aws:kms:us-east-1:111111111111:key/abc",
            ["us-west-2"] = "arn:aws:kms:us-west-2:111111111111:key/def",
        };
        var fromReadOnly = BaseBuilder()
            .WithKms(KmsKind.Aws)
            .WithRegionMap((IReadOnlyDictionary<string, string>)src.ToImmutableDictionary())
            .Build();
        var fromIDict = BaseBuilder()
            .WithKms("aws")
            .WithRegionMap((IDictionary<string, string>)new Dictionary<string, string>(src))
            .Build();
        AssertJsonEqual(ConfigToJson(fromReadOnly), ConfigToJson(fromIDict));
    }

    [Fact]
    public void WithRegionMap_NullReadOnlyDictionary_OmitsField()
    {
        var fromNull = BaseBuilder()
            .WithKms(KmsKind.Aws)
            .WithRegionMap((IReadOnlyDictionary<string, string>?)null)
            .Build();
        var fromBase = BaseBuilder().WithKms("aws").Build();
        AssertJsonEqual(ConfigToJson(fromNull), ConfigToJson(fromBase));
    }

    [Fact]
    public void WithRegionMap_ReadOnlyDictionary_IsCopied()
    {
        // Mutate the source after Build(); the built config must not see it.
        var src = new Dictionary<string, string> { ["us-east-1"] = "a" };
        var built = BaseBuilder()
            .WithKms(KmsKind.Aws)
            .WithRegionMap((IReadOnlyDictionary<string, string>)src)
            .Build();
        src["us-east-1"] = "MUTATED";
        src["us-west-2"] = "ADDED";
        Assert.NotNull(built.RegionMap);
        Assert.Equal("a", built.RegionMap!["us-east-1"]);
        Assert.False(built.RegionMap.ContainsKey("us-west-2"));
    }
}
