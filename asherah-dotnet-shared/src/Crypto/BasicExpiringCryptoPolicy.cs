using System;

namespace GoDaddy.Asherah.Crypto;

public class BasicExpiringCryptoPolicy : CryptoPolicy
{
    private readonly long keyExpirationMillis;
    private readonly long revokeCheckMillis;

    private readonly KeyRotationStrategy keyRotationStrategy;
    private readonly bool canCacheSystemKeys;
    private readonly bool canCacheIntermediateKeys;
    private readonly bool canCacheSessions;
    private readonly long sessionCacheMaxSize;
    private readonly long sessionCacheExpireMillis;
    private readonly bool notifyExpiredSystemKeyOnRead;
    private readonly bool notifyExpiredIntermediateKeyOnRead;

    private BasicExpiringCryptoPolicy(Builder builder)
    {
        keyExpirationMillis = (long)TimeSpan.FromDays(builder.KeyExpirationDays).TotalMilliseconds;
        revokeCheckMillis = (long)TimeSpan.FromMinutes(builder.RevokeCheckMinutes).TotalMilliseconds;
        keyRotationStrategy = builder.KeyRotationStrategy;
        canCacheSystemKeys = builder.CanCacheSystemKeys;
        canCacheIntermediateKeys = builder.CanCacheIntermediateKeys;
        canCacheSessions = builder.CanCacheSessions;
        sessionCacheMaxSize = builder.SessionCacheMaxSize;
        sessionCacheExpireMillis = builder.SessionCacheExpireMillis;
        notifyExpiredSystemKeyOnRead = builder.NotifyExpiredSystemKeyOnRead;
        notifyExpiredIntermediateKeyOnRead = builder.NotifyExpiredIntermediateKeyOnRead;
    }

    public interface IKeyExpirationDaysStep
    {
        IRevokeCheckMinutesStep WithKeyExpirationDays(int days);
    }

    public interface IRevokeCheckMinutesStep
    {
        IBuildStep WithRevokeCheckMinutes(int minutes);
    }

    public interface IBuildStep
    {
        IBuildStep WithRotationStrategy(KeyRotationStrategy rotationStrategy);
        IBuildStep WithCanCacheSystemKeys(bool cacheSystemKeys);
        IBuildStep WithCanCacheIntermediateKeys(bool cacheIntermediateKeys);
        IBuildStep WithCanCacheSessions(bool cacheSessions);
        IBuildStep WithSessionCacheMaxSize(long sessionCacheMaxSize);
        IBuildStep WithSessionCacheExpireMillis(long sessionCacheExpireMillis);
        IBuildStep WithNotifyExpiredSystemKeyOnRead(bool notify);
        IBuildStep WithNotifyExpiredIntermediateKeyOnRead(bool notify);
        BasicExpiringCryptoPolicy Build();
    }

    public static IKeyExpirationDaysStep NewBuilder() => new Builder();

    public override bool IsKeyExpired(DateTimeOffset keyCreationDate)
    {
        long currentUnixTimeMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        long expiredMillis = keyCreationDate.ToUnixTimeMilliseconds() + keyExpirationMillis;
        return currentUnixTimeMillis > expiredMillis;
    }

    public override long GetRevokeCheckPeriodMillis() => revokeCheckMillis;
    public override bool CanCacheSystemKeys() => canCacheSystemKeys;
    public override bool CanCacheIntermediateKeys() => canCacheIntermediateKeys;
    public override bool CanCacheSessions() => canCacheSessions;
    public override long GetSessionCacheMaxSize() => sessionCacheMaxSize;
    public override long GetSessionCacheExpireMillis() => sessionCacheExpireMillis;
    public override bool NotifyExpiredIntermediateKeyOnRead() => notifyExpiredIntermediateKeyOnRead;
    public override bool NotifyExpiredSystemKeyOnRead() => notifyExpiredSystemKeyOnRead;
    public override KeyRotationStrategy GetKeyRotationStrategy() => keyRotationStrategy;

    internal long KeyExpirationMillis => keyExpirationMillis;
    internal long RevokeCheckMillis => revokeCheckMillis;

    private class Builder : IKeyExpirationDaysStep, IRevokeCheckMinutesStep, IBuildStep
    {
        private int keyExpirationDays;
        private int revokeCheckMinutes;

        private KeyRotationStrategy keyRotationStrategy = DefaultKeyRotationStrategy;
        private bool canCacheSystemKeys = DefaultCanCacheSystemKeys;
        private bool canCacheIntermediateKeys = DefaultCanCacheIntermediateKeys;
        private bool canCacheSessions = DefaultCanCacheSessions;
        private long sessionCacheMaxSize = DefaultSessionCacheSize;
        private long sessionCacheExpireMillis = DefaultSessionCacheExpiryMillis;
        private bool notifyExpiredSystemKeyOnRead = DefaultNotifyExpiredSystemKeyOnRead;
        private bool notifyExpiredIntermediateKeyOnRead = DefaultNotifyExpiredIntermediateKeyOnRead;

        internal int KeyExpirationDays => keyExpirationDays;
        internal int RevokeCheckMinutes => revokeCheckMinutes;
        internal KeyRotationStrategy KeyRotationStrategy => keyRotationStrategy;
        internal bool CanCacheSystemKeys => canCacheSystemKeys;
        internal bool CanCacheIntermediateKeys => canCacheIntermediateKeys;
        internal bool CanCacheSessions => canCacheSessions;
        internal long SessionCacheMaxSize => sessionCacheMaxSize;
        internal long SessionCacheExpireMillis => sessionCacheExpireMillis;
        internal bool NotifyExpiredSystemKeyOnRead => notifyExpiredSystemKeyOnRead;
        internal bool NotifyExpiredIntermediateKeyOnRead => notifyExpiredIntermediateKeyOnRead;

        private const KeyRotationStrategy DefaultKeyRotationStrategy = KeyRotationStrategy.Inline;
        private const bool DefaultCanCacheSystemKeys = true;
        private const bool DefaultCanCacheIntermediateKeys = true;
        private const bool DefaultCanCacheSessions = false;
        private const long DefaultSessionCacheSize = 1000;
        private const long DefaultSessionCacheExpiryMillis = 120000;
        private const bool DefaultNotifyExpiredSystemKeyOnRead = false;
        private const bool DefaultNotifyExpiredIntermediateKeyOnRead = false;

        public IRevokeCheckMinutesStep WithKeyExpirationDays(int days)
        {
            keyExpirationDays = days;
            return this;
        }

        public IBuildStep WithRevokeCheckMinutes(int minutes)
        {
            revokeCheckMinutes = minutes;
            return this;
        }

        public IBuildStep WithRotationStrategy(KeyRotationStrategy rotationStrategy)
        {
            keyRotationStrategy = rotationStrategy;
            return this;
        }

        public IBuildStep WithCanCacheSystemKeys(bool cacheSystemKeys)
        {
            canCacheSystemKeys = cacheSystemKeys;
            return this;
        }

        public IBuildStep WithCanCacheIntermediateKeys(bool cacheIntermediateKeys)
        {
            canCacheIntermediateKeys = cacheIntermediateKeys;
            return this;
        }

        public IBuildStep WithCanCacheSessions(bool cacheSessions)
        {
            canCacheSessions = cacheSessions;
            return this;
        }

        public IBuildStep WithSessionCacheMaxSize(long sessionCacheMaxSize)
        {
            this.sessionCacheMaxSize = sessionCacheMaxSize;
            return this;
        }

        public IBuildStep WithSessionCacheExpireMillis(long sessionCacheExpireMillis)
        {
            this.sessionCacheExpireMillis = sessionCacheExpireMillis;
            return this;
        }

        public IBuildStep WithNotifyExpiredSystemKeyOnRead(bool notify)
        {
            notifyExpiredSystemKeyOnRead = notify;
            return this;
        }

        public IBuildStep WithNotifyExpiredIntermediateKeyOnRead(bool notify)
        {
            notifyExpiredIntermediateKeyOnRead = notify;
            return this;
        }

        public BasicExpiringCryptoPolicy Build() => new(this);
    }
}
