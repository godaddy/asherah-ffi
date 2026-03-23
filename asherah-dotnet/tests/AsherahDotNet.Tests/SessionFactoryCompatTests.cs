using System.Text;
using GoDaddy.Asherah;
using GoDaddy.Asherah.AppEncryption;
using GoDaddy.Asherah.AppEncryption.Crypto;
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
