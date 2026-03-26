using System.Collections.Concurrent;
using System.Text;
using System.Threading.Tasks;
using GoDaddy.Asherah;
using GoDaddy.Asherah.AppEncryption;
using GoDaddy.Asherah.AppEncryption.Crypto;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using LanguageExt;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AsherahDotNet.Tests;

public class SessionFactoryCompatTests : IDisposable
{
    private SessionFactory? _factory;

    static SessionFactoryCompatTests()
    {
        Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX",
            Environment.GetEnvironmentVariable("STATIC_MASTER_KEY_HEX")
            ?? new string('2', 64));
    }

    public void Dispose()
    {
        _factory?.Dispose();
        _factory = null;
    }

    [Fact]
    public void CanonicalBuilderPatternRoundTrip()
    {
        _factory = SessionFactory.NewBuilder("product", "service")
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .Build();

        using var session = _factory.GetSessionJson("test-partition");
        var payload = new JObject { ["message"] = "hello from canonical API" };

        var encrypted = session.Encrypt(payload);
        Assert.NotNull(encrypted);

        var decrypted = session.Decrypt(encrypted);
        Assert.Equal("hello from canonical API", decrypted["message"]!.ToString());
    }

    [Fact]
    public void SessionBytesRoundTrip()
    {
        _factory = SessionFactory.NewBuilder("product", "service")
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .Build();

        using var session = _factory.GetSessionBytes("test-partition");
        var payload = Encoding.UTF8.GetBytes("binary payload test");

        var encrypted = session.Encrypt(payload);
        Assert.NotNull(encrypted);

        var decrypted = session.Decrypt(encrypted);
        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public void SessionJsonAsJsonRoundTrip()
    {
        _factory = SessionFactory.NewBuilder("product", "service")
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .Build();

        using var session = _factory.GetSessionJsonAsJson("test-partition");
        var payload = new JObject { ["key"] = "value" };

        var encrypted = session.Encrypt(payload);
        Assert.NotNull(encrypted);
        Assert.NotNull(encrypted["Key"]); // DRR has Key field

        var decrypted = session.Decrypt(encrypted);
        Assert.Equal("value", decrypted["key"]!.ToString());
    }

    [Fact]
    public void BasicExpiringCryptoPolicyWorks()
    {
        _factory = SessionFactory.NewBuilder("product", "service")
            .WithInMemoryMetastore()
            .WithCryptoPolicy(
                BasicExpiringCryptoPolicy.NewBuilder()
                    .WithKeyExpirationDays(90)
                    .WithRevokeCheckMinutes(60)
                    .WithCanCacheSessions(true)
                    .WithSessionCacheMaxSize(500)
                    .WithSessionCacheExpireMillis(1800000)
                    .Build())
            .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .Build();

        using var session = _factory.GetSessionBytes("policy-test");
        var payload = Encoding.UTF8.GetBytes("policy test");
        var encrypted = session.Encrypt(payload);
        var decrypted = session.Decrypt(encrypted);
        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public void WithMetastoreAcceptsBuiltIn()
    {
        var metastore = new InMemoryMetastoreImpl<JObject>();
        _factory = SessionFactory.NewBuilder("product", "service")
            .WithMetastore(metastore)
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .Build();

        using var session = _factory.GetSessionBytes("metastore-test");
        var ct = session.Encrypt(Encoding.UTF8.GetBytes("test"));
        Assert.Equal("test", Encoding.UTF8.GetString(session.Decrypt(ct)));
    }

    [Fact]
    public void WithKeyManagementServiceAcceptsStaticKms()
    {
        _factory = SessionFactory.NewBuilder("product", "service")
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithKeyManagementService(new StaticKeyManagementServiceImpl("thisIsAStaticMasterKeyForTesting"))
            .Build();

        using var session = _factory.GetSessionBytes("kms-test");
        var ct = session.Encrypt(Encoding.UTF8.GetBytes("kms test"));
        Assert.Equal("kms test", Encoding.UTF8.GetString(session.Decrypt(ct)));
    }

    [Fact]
    public void PersistenceLoadStore()
    {
        _factory = SessionFactory.NewBuilder("product", "service")
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .Build();

        var storage = new ConcurrentDictionary<string, byte[]>();
        var persistence = new AdhocPersistence<byte[]>(
            key => storage.TryGetValue(key, out var v) ? Option<byte[]>.Some(v) : Option<byte[]>.None,
            (key, value) => storage[key] = value);

        using var session = _factory.GetSessionBytes("persist-test");
        var payload = Encoding.UTF8.GetBytes("persist me");

        var key = session.Store(payload, persistence);
        Assert.NotNull(key);
        Assert.True(storage.ContainsKey(key));

        var loaded = session.Load(key, persistence);
        Assert.True(loaded.IsSome);
        loaded.IfSome(v => Assert.Equal(payload, v));
    }

    [Fact]
    public void DynamoDbMetastoreBuilder()
    {
        var metastore = DynamoDbMetastoreImpl.NewBuilder("us-east-1")
            .WithTableName("CustomTable")
            .WithEndPointConfiguration("http://localhost:4566", "us-west-2")
            .WithKeySuffix()
            .Build();

        Assert.Equal("_us-east-1", metastore.GetKeySuffix());
    }

    [Fact]
    public void NeverExpiredCryptoPolicyValues()
    {
        var p = new NeverExpiredCryptoPolicy();
        Assert.False(p.IsKeyExpired(DateTimeOffset.UnixEpoch));
        Assert.True(p.CanCacheSystemKeys());
        Assert.True(p.CanCacheIntermediateKeys());
        Assert.False(p.CanCacheSessions());
        Assert.True(p.IsInlineKeyRotation());
        Assert.False(p.IsQueuedKeyRotation());
    }

    [Fact]
    public void BasicExpiringCryptoPolicyFullBuilder()
    {
        var p = BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(30)
            .WithRevokeCheckMinutes(10)
            .WithRotationStrategy(KeyRotationStrategy.Queued)
            .WithCanCacheSystemKeys(false)
            .WithCanCacheIntermediateKeys(false)
            .WithCanCacheSessions(true)
            .WithSessionCacheMaxSize(100)
            .WithSessionCacheExpireMillis(300000)
            .WithNotifyExpiredSystemKeyOnRead(true)
            .WithNotifyExpiredIntermediateKeyOnRead(true)
            .Build();

        Assert.False(p.CanCacheSystemKeys());
        Assert.False(p.CanCacheIntermediateKeys());
        Assert.True(p.CanCacheSessions());
        Assert.Equal(100, p.GetSessionCacheMaxSize());
        Assert.True(p.NotifyExpiredSystemKeyOnRead());
        Assert.True(p.NotifyExpiredIntermediateKeyOnRead());
        Assert.True(p.IsQueuedKeyRotation());
    }

    [Fact]
    public void AwsKmsBuilder()
    {
        var regionMap = new Dictionary<string, string> { ["us-east-1"] = "arn:aws:kms:us-east-1:123:key/abc" };
        var kms = AwsKeyManagementServiceImpl.NewBuilder(regionMap, "us-east-1").Build();
        Assert.NotNull(kms);
    }

    [Fact]
    public async Task AsyncSessionMethods()
    {
        _factory = SessionFactory.NewBuilder("product", "service")
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .Build();

        using var session = _factory.GetSessionBytes("async-test");
        var payload = Encoding.UTF8.GetBytes("async test");
        var ct = await session.EncryptAsync(payload);
        var pt = await session.DecryptAsync(ct);
        Assert.Equal(payload, pt);
    }

    [Fact]
    public void MultipleSessionsSameFactory()
    {
        _factory = SessionFactory.NewBuilder("product", "service")
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .Build();

        using var s1 = _factory.GetSessionBytes("partition-1");
        using var s2 = _factory.GetSessionBytes("partition-2");

        var ct1 = s1.Encrypt(Encoding.UTF8.GetBytes("data1"));
        var ct2 = s2.Encrypt(Encoding.UTF8.GetBytes("data2"));

        Assert.Equal("data1", Encoding.UTF8.GetString(s1.Decrypt(ct1)));
        Assert.Equal("data2", Encoding.UTF8.GetString(s2.Decrypt(ct2)));
    }
}
