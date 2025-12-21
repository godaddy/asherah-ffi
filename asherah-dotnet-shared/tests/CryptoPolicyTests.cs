using GoDaddy.Asherah.Crypto;
using Xunit;

namespace AsherahDotNet.SharedTests;

public class CryptoPolicyTests
{
    [Fact]
    public void BasicExpiringCryptoPolicy_Defaults()
    {
        var policy = BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(1)
            .WithRevokeCheckMinutes(2)
            .Build();

        Assert.True(policy.CanCacheSystemKeys());
        Assert.True(policy.CanCacheIntermediateKeys());
        Assert.False(policy.CanCacheSessions());
        Assert.Equal(1000, policy.GetSessionCacheMaxSize());
        Assert.Equal(120000, policy.GetSessionCacheExpireMillis());
        Assert.False(policy.NotifyExpiredSystemKeyOnRead());
        Assert.False(policy.NotifyExpiredIntermediateKeyOnRead());
        Assert.Equal(CryptoPolicy.KeyRotationStrategy.Inline, policy.GetKeyRotationStrategy());
    }

    [Fact]
    public void BasicExpiringCryptoPolicy_Customizations()
    {
        var policy = BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(1)
            .WithRevokeCheckMinutes(2)
            .WithRotationStrategy(CryptoPolicy.KeyRotationStrategy.Queued)
            .WithCanCacheSystemKeys(false)
            .WithCanCacheIntermediateKeys(false)
            .WithCanCacheSessions(true)
            .WithSessionCacheMaxSize(55)
            .WithSessionCacheExpireMillis(1234)
            .WithNotifyExpiredSystemKeyOnRead(true)
            .WithNotifyExpiredIntermediateKeyOnRead(true)
            .Build();

        Assert.False(policy.CanCacheSystemKeys());
        Assert.False(policy.CanCacheIntermediateKeys());
        Assert.True(policy.CanCacheSessions());
        Assert.Equal(55, policy.GetSessionCacheMaxSize());
        Assert.Equal(1234, policy.GetSessionCacheExpireMillis());
        Assert.True(policy.NotifyExpiredSystemKeyOnRead());
        Assert.True(policy.NotifyExpiredIntermediateKeyOnRead());
        Assert.Equal(CryptoPolicy.KeyRotationStrategy.Queued, policy.GetKeyRotationStrategy());
    }

    [Fact]
    public void NeverExpiredCryptoPolicy_Values()
    {
        var policy = new NeverExpiredCryptoPolicy();
        Assert.False(policy.IsKeyExpired(default));
        Assert.True(policy.CanCacheSystemKeys());
        Assert.True(policy.CanCacheIntermediateKeys());
        Assert.False(policy.CanCacheSessions());
        Assert.Equal(long.MaxValue, policy.GetSessionCacheMaxSize());
        Assert.Equal(long.MaxValue, policy.GetSessionCacheExpireMillis());
        Assert.True(policy.NotifyExpiredSystemKeyOnRead());
        Assert.True(policy.NotifyExpiredIntermediateKeyOnRead());
        Assert.Equal(CryptoPolicy.KeyRotationStrategy.Inline, policy.GetKeyRotationStrategy());
    }
}
