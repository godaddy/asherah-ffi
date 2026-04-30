using GoDaddy.Asherah.Encryption;

namespace GoDaddy.Asherah.AppEncryption.Crypto;

/// <summary>How intermediate/system key rotation is scheduled when encryption keys expire.</summary>
public enum KeyRotationStrategy
{
    /// <summary>Perform rotation-related work synchronously.</summary>
    Inline,

    /// <summary>Defer rotation work to an asynchronous pipeline.</summary>
    Queued
}

/// <summary>
/// Abstract crypto policy. Compatible with the canonical godaddy/asherah CryptoPolicy.
/// </summary>
public abstract class CryptoPolicy
{
    /// <summary>Returns whether a key created at <paramref name="keyCreationDate"/> is treated as expired.</summary>
    public abstract bool IsKeyExpired(DateTimeOffset keyCreationDate);

    /// <summary>Interval between metastore revocation checks in milliseconds.</summary>
    public abstract long GetRevokeCheckPeriodMillis();

    /// <summary>Whether root/system keys may be cached locally.</summary>
    public abstract bool CanCacheSystemKeys();

    /// <summary>Whether intermediate keys may be cached locally.</summary>
    public abstract bool CanCacheIntermediateKeys();

    /// <summary>Whether session objects may be cached.</summary>
    public abstract bool CanCacheSessions();

    /// <summary>Maximum session cache entries when caching is enabled.</summary>
    public abstract long GetSessionCacheMaxSize();

    /// <summary>Session cache entry lifetime in milliseconds when caching is enabled.</summary>
    public abstract long GetSessionCacheExpireMillis();

    /// <summary>Whether to notify when reading an expired intermediate key.</summary>
    public abstract bool NotifyExpiredIntermediateKeyOnRead();

    /// <summary>Whether to notify when reading an expired system key.</summary>
    public abstract bool NotifyExpiredSystemKeyOnRead();

    /// <summary>Rotation strategy preference for expired keys.</summary>
    public abstract KeyRotationStrategy GetKeyRotationStrategy();

    /// <summary>True when <see cref="GetKeyRotationStrategy"/> is <see cref="KeyRotationStrategy.Inline"/>.</summary>
    public virtual bool IsInlineKeyRotation() => GetKeyRotationStrategy() == KeyRotationStrategy.Inline;

    /// <summary>True when <see cref="GetKeyRotationStrategy"/> is <see cref="KeyRotationStrategy.Queued"/>.</summary>
    public virtual bool IsQueuedKeyRotation() => GetKeyRotationStrategy() == KeyRotationStrategy.Queued;

    internal virtual void ApplyConfig(AsherahConfig.Builder builder)
    {
        if (CanCacheSessions())
        {
            builder.WithEnableSessionCaching(true)
                   .WithSessionCacheMaxSize((int)GetSessionCacheMaxSize())
                   .WithSessionCacheDuration(TimeSpan.FromMilliseconds(GetSessionCacheExpireMillis()));
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
    /// <inheritdoc />
    public override bool IsKeyExpired(DateTimeOffset keyCreationDate) => false;

    /// <inheritdoc />
    public override long GetRevokeCheckPeriodMillis() => long.MaxValue;

    /// <inheritdoc />
    public override bool CanCacheSystemKeys() => true;

    /// <inheritdoc />
    public override bool CanCacheIntermediateKeys() => true;

    /// <inheritdoc />
    public override bool CanCacheSessions() => false;

    /// <inheritdoc />
    public override long GetSessionCacheMaxSize() => long.MaxValue;

    /// <inheritdoc />
    public override long GetSessionCacheExpireMillis() => long.MaxValue;

    /// <inheritdoc />
    public override bool NotifyExpiredIntermediateKeyOnRead() => false;

    /// <inheritdoc />
    public override bool NotifyExpiredSystemKeyOnRead() => false;

    /// <inheritdoc />
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
        builder.WithExpireAfter(TimeSpan.FromMilliseconds(_keyExpirationMillis));
        builder.WithCheckInterval(TimeSpan.FromMilliseconds(_revokeCheckPeriodMillis));
    }

    /// <inheritdoc />
    public override bool IsKeyExpired(DateTimeOffset keyCreationDate) =>
        keyCreationDate.AddMilliseconds(_keyExpirationMillis) < DateTimeOffset.UtcNow;

    /// <inheritdoc />
    public override long GetRevokeCheckPeriodMillis() => _revokeCheckPeriodMillis;

    /// <inheritdoc />
    public override bool CanCacheSystemKeys() => _cacheSystemKeys;

    /// <inheritdoc />
    public override bool CanCacheIntermediateKeys() => _cacheIntermediateKeys;

    /// <inheritdoc />
    public override bool CanCacheSessions() => _cacheSessions;

    /// <inheritdoc />
    public override long GetSessionCacheMaxSize() => _sessionCacheMaxSize;

    /// <inheritdoc />
    public override long GetSessionCacheExpireMillis() => _sessionCacheExpireMillis;

    /// <inheritdoc />
    public override bool NotifyExpiredIntermediateKeyOnRead() => _notifyExpiredIntermediateKey;

    /// <inheritdoc />
    public override bool NotifyExpiredSystemKeyOnRead() => _notifyExpiredSystemKey;

    /// <inheritdoc />
    public override KeyRotationStrategy GetKeyRotationStrategy() => _rotationStrategy;

    /// <summary>Begins a fluent builder for an expiring policy.</summary>
    public static IKeyExpirationDaysStep NewBuilder() => new Builder();

    /// <summary>Builder step: set key expiration in calendar days.</summary>
    public interface IKeyExpirationDaysStep
    {
        /// <summary>Sets envelope key lifetime.</summary>
        IRevokeCheckMinutesStep WithKeyExpirationDays(int days);
    }

    /// <summary>Builder step: set metastore revoke check cadence.</summary>
    public interface IRevokeCheckMinutesStep
    {
        /// <summary>Minutes between revocation checks.</summary>
        IBuildStep WithRevokeCheckMinutes(int minutes);
    }

    /// <summary>Builder step: optional tuning and materialization.</summary>
    public interface IBuildStep
    {
        /// <summary>Selects synchronous vs queued rotation semantics.</summary>
        IBuildStep WithRotationStrategy(KeyRotationStrategy strategy);

        /// <summary>Enables or disables system-key caching.</summary>
        IBuildStep WithCanCacheSystemKeys(bool cache);

        /// <summary>Enables or disables intermediate-key caching.</summary>
        IBuildStep WithCanCacheIntermediateKeys(bool cache);

        /// <summary>Enables or disables session caching.</summary>
        IBuildStep WithCanCacheSessions(bool cache);

        /// <summary>Maximum session cache entries when session caching is on.</summary>
        IBuildStep WithSessionCacheMaxSize(long size);

        /// <summary>Session cache duration in milliseconds (converted to whole minutes).</summary>
        IBuildStep WithSessionCacheExpireMillis(long millis);

        /// <summary>Notify when encountering an expired system key on read paths.</summary>
        IBuildStep WithNotifyExpiredSystemKeyOnRead(bool notify);

        /// <summary>Notify when encountering an expired intermediate key on read paths.</summary>
        IBuildStep WithNotifyExpiredIntermediateKeyOnRead(bool notify);

        /// <summary>Builds the immutable policy.</summary>
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
