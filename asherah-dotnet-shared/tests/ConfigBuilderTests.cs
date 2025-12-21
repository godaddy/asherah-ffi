using System;
using System.Data.Common;
using System.Reflection;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.Crypto;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AsherahDotNet.SharedTests;

public class ConfigBuilderTests
{
    [Fact]
    public void ConfigBuilder_MapsStaticKmsAndRdbms()
    {
        var metastore = AdoMetastoreImpl.NewBuilder(new DummyDbProviderFactory(), "Server=.;Database=asherah").Build();
        var policy = BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(1)
            .WithRevokeCheckMinutes(2)
            .WithCanCacheSessions(true)
            .WithSessionCacheMaxSize(123)
            .WithSessionCacheExpireMillis(4567)
            .Build();
        var kms = new StaticKeyManagementServiceImpl(new string('a', 32));

        object config = BuildConfig("svc", "prod", metastore, policy, kms);
        Assert.Equal("rdbms", GetProperty<string>(config, "Metastore"));
        Assert.Equal("Server=.;Database=asherah", GetProperty<string>(config, "ConnectionString"));
        Assert.Equal("static", GetProperty<string>(config, "Kms"));
        Assert.Equal(RepeatHex("61", 32), GetProperty<string>(config, "StaticMasterKeyHex"));
        Assert.Equal(86400, GetProperty<long?>(config, "ExpireAfter"));
        Assert.Equal(120, GetProperty<long?>(config, "CheckInterval"));
        Assert.Equal(123, GetProperty<int?>(config, "SessionCacheMaxSize"));
        Assert.Equal(4, GetProperty<long?>(config, "SessionCacheDuration"));
        Assert.True(GetProperty<bool?>(config, "EnableSessionCaching"));
    }

    [Fact]
    public void ConfigBuilder_MapsDynamoDb()
    {
        var metastore = DynamoDbMetastoreImpl.NewBuilder("us-west-2")
            .WithTableName("EncryptionKey")
            .WithKeySuffix()
            .Build();
        var policy = new NeverExpiredCryptoPolicy();
        var kms = new StaticKeyManagementServiceImpl(new string('a', 32));

        object config = BuildConfig("svc", "prod", metastore, policy, kms);
        Assert.Equal("dynamodb", GetProperty<string>(config, "Metastore"));
        Assert.Equal("EncryptionKey", GetProperty<string>(config, "DynamoDbTableName"));
        Assert.Equal("us-west-2", GetProperty<string>(config, "DynamoDbRegion"));
        Assert.True(GetProperty<bool?>(config, "EnableRegionSuffix"));
    }

    private static object BuildConfig(
        string serviceId,
        string productId,
        IMetastore<JObject> metastore,
        CryptoPolicy policy,
        IKeyManagementService kms)
    {
        var type = Type.GetType("GoDaddy.Asherah.Internal.ConfigBuilder, GoDaddy.Asherah.AppEncryption", throwOnError: true)!;
        var method = type.GetMethod("BuildConfig", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)!;
        return method.Invoke(null, new object[] { serviceId, productId, metastore, policy, kms })!;
    }

    private static T GetProperty<T>(object obj, string name)
    {
        var prop = obj.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!;
        return (T)prop.GetValue(obj)!;
    }

    private static string RepeatHex(string hexByte, int count)
    {
        return string.Concat(System.Linq.Enumerable.Repeat(hexByte, count));
    }

    private sealed class DummyDbProviderFactory : DbProviderFactory
    {
    }
}
