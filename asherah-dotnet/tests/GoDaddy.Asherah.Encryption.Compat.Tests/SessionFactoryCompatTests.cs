using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using GoDaddy.Asherah.Encryption;
using GoDaddy.Asherah.AppEncryption;
using GoDaddy.Asherah.AppEncryption.Crypto;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using LanguageExt;
using Newtonsoft.Json.Linq;
using Xunit;
using static LanguageExt.Prelude;

namespace GoDaddy.Asherah.Encryption.Compat.Tests;

public class SessionFactoryCompatTests : IDisposable
{
    private SessionFactory? _factory;

    static SessionFactoryCompatTests()
    {
        Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX",
            Environment.GetEnvironmentVariable("STATIC_MASTER_KEY_HEX")
            ?? new string('2', 64));

        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASHERAH_DOTNET_NATIVE")))
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null)
            {
                if (File.Exists(Path.Join(dir.FullName, "Cargo.toml")))
                {
                    Environment.SetEnvironmentVariable("ASHERAH_DOTNET_NATIVE",
                        Path.Join(dir.FullName, "target", "debug"));
                    break;
                }
                dir = dir.Parent;
            }
        }
    }

    public void Dispose()
    {
        _factory?.Dispose();
        _factory = null;
    }

    private SessionFactory BuildFactory()
    {
        return SessionFactory.NewBuilder("product", "service")
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .Build();
    }

    // ============================================================
    // Session variants
    // ============================================================

    [Fact]
    public void GetSessionJson_RoundTrip()
    {
        _factory = BuildFactory();
        using var session = _factory.GetSessionJson("json-test");
        var payload = new JObject { ["message"] = "hello from canonical API" };

        var encrypted = session.Encrypt(payload);
        Assert.NotNull(encrypted);

        var decrypted = session.Decrypt(encrypted);
        Assert.Equal("hello from canonical API", decrypted["message"]!.ToString());
    }

    [Fact]
    public void GetSessionBytes_RoundTrip()
    {
        _factory = BuildFactory();
        using var session = _factory.GetSessionBytes("bytes-test");
        var payload = Encoding.UTF8.GetBytes("binary payload test");

        var encrypted = session.Encrypt(payload);
        var decrypted = session.Decrypt(encrypted);
        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public void GetSessionJsonAsJson_RoundTrip()
    {
        _factory = BuildFactory();
        using var session = _factory.GetSessionJsonAsJson("json-as-json");
        var payload = new JObject { ["key"] = "value" };

        var encrypted = session.Encrypt(payload);
        Assert.NotNull(encrypted);
        Assert.NotNull(encrypted["Key"]); // DRR has Key field

        var decrypted = session.Decrypt(encrypted);
        Assert.Equal("value", decrypted["key"]!.ToString());
    }

    [Fact]
    public void GetSessionBytesAsJson_RoundTrip()
    {
        _factory = BuildFactory();
        using var session = _factory.GetSessionBytesAsJson("bytes-as-json");
        var payload = Encoding.UTF8.GetBytes("bytes as json test");

        var encrypted = session.Encrypt(payload);
        Assert.NotNull(encrypted);
        Assert.NotNull(encrypted["Key"]);

        var decrypted = session.Decrypt(encrypted);
        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public void MultipleSessions_SameFactory()
    {
        _factory = BuildFactory();
        using var s1 = _factory.GetSessionBytes("partition-1");
        using var s2 = _factory.GetSessionBytes("partition-2");

        var ct1 = s1.Encrypt(Encoding.UTF8.GetBytes("data1"));
        var ct2 = s2.Encrypt(Encoding.UTF8.GetBytes("data2"));

        Assert.Equal("data1", Encoding.UTF8.GetString(s1.Decrypt(ct1)));
        Assert.Equal("data2", Encoding.UTF8.GetString(s2.Decrypt(ct2)));
    }

    // ============================================================
    // Async session methods
    // ============================================================

    [Fact]
    public async Task Session_EncryptAsync_DecryptAsync()
    {
        _factory = BuildFactory();
        using var session = _factory.GetSessionBytes("async-test");
        var payload = Encoding.UTF8.GetBytes("async test");
        var ct = await session.EncryptAsync(payload);
        var pt = await session.DecryptAsync(ct);
        Assert.Equal(payload, pt);
    }

    // ============================================================
    // Persistence
    // ============================================================

    [Fact]
    public void Persistence_StoreAutoKey_Load()
    {
        _factory = BuildFactory();

        var storage = new ConcurrentDictionary<string, byte[]>();
        var persistence = new AdhocPersistence<byte[]>(
            key => storage.TryGetValue(key, out var v) ? Some(v) : Option<byte[]>.None,
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
    public void Persistence_StoreWithKey()
    {
        _factory = BuildFactory();

        var storage = new ConcurrentDictionary<string, byte[]>();
        var persistence = new AdhocPersistence<byte[]>(
            key => storage.TryGetValue(key, out var v) ? Some(v) : Option<byte[]>.None,
            (key, value) => storage[key] = value);

        using var session = _factory.GetSessionBytes("persist-key");
        var payload = Encoding.UTF8.GetBytes("keyed data");

        session.Store("my-key", payload, persistence);
        Assert.True(storage.ContainsKey("my-key"));

        var loaded = session.Load("my-key", persistence);
        Assert.True(loaded.IsSome);
        loaded.IfSome(v => Assert.Equal(payload, v));
    }

    [Fact]
    public void Persistence_LoadMissing_ReturnsNone()
    {
        _factory = BuildFactory();

        var persistence = new AdhocPersistence<byte[]>(
            _ => Option<byte[]>.None,
            (_, _) => { });

        using var session = _factory.GetSessionBytes("persist-miss");
        var loaded = session.Load("nonexistent", persistence);
        Assert.True(loaded.IsNone);
    }

    // ============================================================
    // Option<T> API surface
    // ============================================================

    [Fact]
    public void Option_Some_HasValue()
    {
        var opt = Option<int>.Some(42);
        Assert.True(opt.IsSome);
        Assert.False(opt.IsNone);
    }

    [Fact]
    public void Option_None_IsEmpty()
    {
        var opt = Option<int>.None;
        Assert.True(opt.IsNone);
        Assert.False(opt.IsSome);
    }

    [Fact]
    public void Option_Map()
    {
        var opt = Option<int>.Some(10);
        var mapped = opt.Map(x => x * 2);
        Assert.True(mapped.IsSome);
        mapped.IfSome(v => Assert.Equal(20, v));

        var none = Option<int>.None;
        Assert.True(none.Map(x => x * 2).IsNone);
    }

    [Fact]
    public void Option_Bind()
    {
        var opt = Option<int>.Some(5);
        var bound = opt.Bind(x => x > 3 ? Option<string>.Some($"big:{x}") : Option<string>.None);
        Assert.True(bound.IsSome);
        bound.IfSome(v => Assert.Equal("big:5", v));

        var small = Option<int>.Some(2);
        Assert.True(small.Bind(x => x > 3 ? Option<string>.Some($"big:{x}") : Option<string>.None).IsNone);
    }

    [Fact]
    public void Option_Match()
    {
        var some = Option<int>.Some(7);
        var result = some.Match(v => $"got:{v}", () => "none");
        Assert.Equal("got:7", result);

        var none = Option<int>.None;
        Assert.Equal("none", none.Match(v => $"got:{v}", () => "none"));
    }

    [Fact]
    public void Option_MatchAction()
    {
        var some = Option<int>.Some(7);
        int? captured = null;
        some.Match(v => captured = v, () => captured = -1);
        Assert.Equal(7, captured);

        var none = Option<int>.None;
        none.Match(v => captured = v, () => captured = -1);
        Assert.Equal(-1, captured);
    }

    [Fact]
    public void Option_IfNone_DefaultValue()
    {
        Assert.Equal(42, Option<int>.Some(42).IfNone(0));
        Assert.Equal(0, Option<int>.None.IfNone(0));
    }

    [Fact]
    public void Option_IfNone_Factory()
    {
        Assert.Equal(42, Option<int>.Some(42).IfNone(() => 0));
        Assert.Equal(99, Option<int>.None.IfNone(() => 99));
    }

    [Fact]
    public void Prelude_Some_And_None()
    {
        // using static LanguageExt.Prelude; provides Some() and None
        var opt = Some(42);
        Assert.True(opt.IsSome);

        Option<int> empty = None;
        Assert.True(empty.IsNone);
    }

    // ============================================================
    // Metastore builders
    // ============================================================

    [Fact]
    public void WithMetastore_InMemory()
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
    public void DynamoDbMetastoreBuilder_Config()
    {
        var metastore = DynamoDbMetastoreImpl.NewBuilder("us-east-1")
            .WithTableName("CustomTable")
            .WithEndPointConfiguration("http://localhost:4566", "us-west-2")
            .WithKeySuffix()
            .Build();

        Assert.Equal("_us-east-1", metastore.GetKeySuffix());
    }

    [Fact]
    public void DynamoDbMetastoreBuilder_NoSuffix()
    {
        var metastore = DynamoDbMetastoreImpl.NewBuilder("eu-west-1").Build();
        Assert.Equal("", metastore.GetKeySuffix());
    }

    [Fact]
    public void AdoMetastoreBuilder()
    {
        var metastore = AdoMetastoreImpl.NewBuilder("Server=localhost;Database=test").Build();
        Assert.NotNull(metastore);
    }

    // ============================================================
    // KMS builders
    // ============================================================

    [Fact]
    public void WithKeyManagementService_StaticKms()
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
    public void AwsKmsBuilder_Constructs()
    {
        var regionMap = new Dictionary<string, string> { ["us-east-1"] = "arn:aws:kms:us-east-1:123:key/abc" };
        var kms = AwsKeyManagementServiceImpl.NewBuilder(regionMap, "us-east-1").Build();
        Assert.NotNull(kms);
    }

    // ============================================================
    // Crypto policies
    // ============================================================

    [Fact]
    public void NeverExpiredCryptoPolicy_Values()
    {
        var p = new NeverExpiredCryptoPolicy();
        Assert.False(p.IsKeyExpired(DateTimeOffset.UnixEpoch));
        Assert.False(p.IsKeyExpired(DateTimeOffset.UtcNow.AddYears(-100)));
        Assert.True(p.CanCacheSystemKeys());
        Assert.True(p.CanCacheIntermediateKeys());
        Assert.False(p.CanCacheSessions());
        Assert.True(p.IsInlineKeyRotation());
        Assert.False(p.IsQueuedKeyRotation());
    }

    [Fact]
    public void BasicExpiringCryptoPolicy_FullBuilder()
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
        Assert.Equal(300000, p.GetSessionCacheExpireMillis());
        Assert.True(p.NotifyExpiredSystemKeyOnRead());
        Assert.True(p.NotifyExpiredIntermediateKeyOnRead());
        Assert.True(p.IsQueuedKeyRotation());
        Assert.False(p.IsInlineKeyRotation());
    }

    [Fact]
    public void BasicExpiringCryptoPolicy_IsKeyExpired()
    {
        var p = BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(1)
            .WithRevokeCheckMinutes(5)
            .Build();

        Assert.False(p.IsKeyExpired(DateTimeOffset.UtcNow));
        Assert.True(p.IsKeyExpired(DateTimeOffset.UtcNow.AddDays(-2)));
    }

    [Fact]
    public void BasicExpiringCryptoPolicy_Functional()
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
        Assert.Equal(payload, session.Decrypt(encrypted));
    }

    // ============================================================
    // Builder: WithMetrics / WithLogger (accept-and-ignore)
    // ============================================================

    [Fact]
    public void WithMetrics_AcceptsNull()
    {
        _factory = SessionFactory.NewBuilder("product", "service")
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .WithMetrics(null)
            .Build();

        using var session = _factory.GetSessionBytes("metrics-null");
        var ct = session.Encrypt(Encoding.UTF8.GetBytes("ok"));
        Assert.NotNull(ct);
    }

    [Fact]
    public void WithLogger_AcceptsNull()
    {
        _factory = SessionFactory.NewBuilder("product", "service")
            .WithInMemoryMetastore()
            .WithNeverExpiredCryptoPolicy()
            .WithStaticKeyManagementService("thisIsAStaticMasterKeyForTesting")
            .WithLogger(null)
            .Build();

        using var session = _factory.GetSessionBytes("logger-null");
        var ct = session.Encrypt(Encoding.UTF8.GetBytes("ok"));
        Assert.NotNull(ct);
    }
}
