using GoDaddy.Asherah.Encryption;

namespace GoDaddy.Asherah.AppEncryption.Crypto;

public enum KeyRotationStrategy { Inline, Queued }

/// <summary>
/// Abstract crypto policy. Compatible with the canonical godaddy/asherah CryptoPolicy.
/// </summary>
public abstract class CryptoPolicy
{
    public abstract bool IsKeyExpired(DateTimeOffset keyCreationDate);
    public abstract long GetRevokeCheckPeriodMillis();
    public abstract bool CanCacheSystemKeys();
    public abstract bool CanCacheIntermediateKeys();
    public abstract bool CanCacheSessions();
    public abstract long GetSessionCacheMaxSize();
    public abstract long GetSessionCacheExpireMillis();
    public abstract bool NotifyExpiredIntermediateKeyOnRead();
    public abstract bool NotifyExpiredSystemKeyOnRead();
    public abstract KeyRotationStrategy GetKeyRotationStrategy();

    public virtual bool IsInlineKeyRotation() => GetKeyRotationStrategy() == KeyRotationStrategy.Inline;
    public virtual bool IsQueuedKeyRotation() => GetKeyRotationStrategy() == KeyRotationStrategy.Queued;

    internal virtual void ApplyConfig(AsherahConfig.Builder builder)
    {
        if (CanCacheSessions())
        {
            builder.WithEnableSessionCaching(true)
                   .WithSessionCacheMaxSize((int)GetSessionCacheMaxSize())
                   .WithSessionCacheDuration(GetSessionCacheExpireMillis() / 1000);
        }
        else
        {
            builder.WithEnableSessionCaching(false);
        }
    }
}

/// <summary>Keys never expire. Maps to default native config.</summary>
public class NeverExpiredCryptoPolicy : CryptoPolicy
{
    public override bool IsKeyExpired(DateTimeOffset keyCreationDate) => false;
    public override long GetRevokeCheckPeriodMillis() => long.MaxValue;
    public override bool CanCacheSystemKeys() => true;
    public override bool CanCacheIntermediateKeys() => true;
    public override bool CanCacheSessions() => false;
    public override long GetSessionCacheMaxSize() => long.MaxValue;
    public override long GetSessionCacheExpireMillis() => long.MaxValue;
    public override bool NotifyExpiredIntermediateKeyOnRead() => false;
    public override bool NotifyExpiredSystemKeyOnRead() => false;
    public override KeyRotationStrategy GetKeyRotationStrategy() => KeyRotationStrategy.Inline;
}

/// <summary>Configurable expiring crypto policy.</summary>
public class BasicExpiringCryptoPolicy : CryptoPolicy
{
    private readonly long _keyExpirationMillis;
    private readonly long _revokeCheckPeriodMillis;
    private readonly KeyRotationStrategy _rotationStrategy;
    private readonly bool _cacheSystemKeys;
    private readonly bool _cacheIntermediateKeys;
    private readonly bool _cacheSessions;
    private readonly long _sessionCacheMaxSize;
    private readonly long _sessionCacheExpireMillis;
    private readonly bool _notifyExpiredSystemKey;
    private readonly bool _notifyExpiredIntermediateKey;

    private BasicExpiringCryptoPolicy(Builder b)
    {
        _keyExpirationMillis = b.KeyExpirationDays * 24L * 60 * 60 * 1000;
        _revokeCheckPeriodMillis = b.RevokeCheckMinutes * 60L * 1000;
        _rotationStrategy = b.RotationStrategy;
        _cacheSystemKeys = b.CacheSystemKeys;
        _cacheIntermediateKeys = b.CacheIntermediateKeys;
        _cacheSessions = b.CacheSessions;
        _sessionCacheMaxSize = b.SessionCacheMaxSize;
        _sessionCacheExpireMillis = b.SessionCacheExpireMinutes * 60L * 1000;
        _notifyExpiredSystemKey = b.NotifyExpiredSystemKey;
        _notifyExpiredIntermediateKey = b.NotifyExpiredIntermediateKey;
    }

    internal override void ApplyConfig(AsherahConfig.Builder builder)
    {
        base.ApplyConfig(builder);
        builder.WithExpireAfter(_keyExpirationMillis / 1000);
        builder.WithCheckInterval(_revokeCheckPeriodMillis / 1000);
    }

    public override bool IsKeyExpired(DateTimeOffset keyCreationDate) =>
        keyCreationDate.AddMilliseconds(_keyExpirationMillis) < DateTimeOffset.UtcNow;
    public override long GetRevokeCheckPeriodMillis() => _revokeCheckPeriodMillis;
    public override bool CanCacheSystemKeys() => _cacheSystemKeys;
    public override bool CanCacheIntermediateKeys() => _cacheIntermediateKeys;
    public override bool CanCacheSessions() => _cacheSessions;
    public override long GetSessionCacheMaxSize() => _sessionCacheMaxSize;
    public override long GetSessionCacheExpireMillis() => _sessionCacheExpireMillis;
    public override bool NotifyExpiredIntermediateKeyOnRead() => _notifyExpiredIntermediateKey;
    public override bool NotifyExpiredSystemKeyOnRead() => _notifyExpiredSystemKey;
    public override KeyRotationStrategy GetKeyRotationStrategy() => _rotationStrategy;

    public static IKeyExpirationDaysStep NewBuilder() => new Builder();

    public interface IKeyExpirationDaysStep { IRevokeCheckMinutesStep WithKeyExpirationDays(int days); }
    public interface IRevokeCheckMinutesStep { IBuildStep WithRevokeCheckMinutes(int minutes); }
    public interface IBuildStep
    {
        IBuildStep WithRotationStrategy(KeyRotationStrategy strategy);
        IBuildStep WithCanCacheSystemKeys(bool cache);
        IBuildStep WithCanCacheIntermediateKeys(bool cache);
        IBuildStep WithCanCacheSessions(bool cache);
        IBuildStep WithSessionCacheMaxSize(long size);
        IBuildStep WithSessionCacheExpireMillis(long millis);
        IBuildStep WithNotifyExpiredSystemKeyOnRead(bool notify);
        IBuildStep WithNotifyExpiredIntermediateKeyOnRead(bool notify);
        BasicExpiringCryptoPolicy Build();
    }

    private class Builder : IKeyExpirationDaysStep, IRevokeCheckMinutesStep, IBuildStep
    {
        internal int KeyExpirationDays;
        internal int RevokeCheckMinutes;
        internal KeyRotationStrategy RotationStrategy = KeyRotationStrategy.Inline;
        internal bool CacheSystemKeys = true;
        internal bool CacheIntermediateKeys = true;
        internal bool CacheSessions;
        internal long SessionCacheMaxSize = 1000;
        internal int SessionCacheExpireMinutes = 120;
        internal bool NotifyExpiredSystemKey;
        internal bool NotifyExpiredIntermediateKey;

        public IRevokeCheckMinutesStep WithKeyExpirationDays(int days) { KeyExpirationDays = days; return this; }
        public IBuildStep WithRevokeCheckMinutes(int minutes) { RevokeCheckMinutes = minutes; return this; }
        public IBuildStep WithRotationStrategy(KeyRotationStrategy strategy) { RotationStrategy = strategy; return this; }
        public IBuildStep WithCanCacheSystemKeys(bool cache) { CacheSystemKeys = cache; return this; }
        public IBuildStep WithCanCacheIntermediateKeys(bool cache) { CacheIntermediateKeys = cache; return this; }
        public IBuildStep WithCanCacheSessions(bool cache) { CacheSessions = cache; return this; }
        public IBuildStep WithSessionCacheMaxSize(long size) { SessionCacheMaxSize = size; return this; }
        public IBuildStep WithSessionCacheExpireMillis(long millis) { SessionCacheExpireMinutes = (int)(millis / 60000); return this; }
        public IBuildStep WithNotifyExpiredSystemKeyOnRead(bool notify) { NotifyExpiredSystemKey = notify; return this; }
        public IBuildStep WithNotifyExpiredIntermediateKeyOnRead(bool notify) { NotifyExpiredIntermediateKey = notify; return this; }
        public BasicExpiringCryptoPolicy Build() => new(this);
    }
}
