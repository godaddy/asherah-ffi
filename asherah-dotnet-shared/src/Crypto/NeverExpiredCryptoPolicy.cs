using System;

namespace GoDaddy.Asherah.Crypto;

public class NeverExpiredCryptoPolicy : CryptoPolicy
{
    public override bool IsKeyExpired(DateTimeOffset keyCreationDate) => false;
    public override long GetRevokeCheckPeriodMillis() => long.MaxValue;
    public override bool CanCacheSystemKeys() => true;
    public override bool CanCacheIntermediateKeys() => true;
    public override bool CanCacheSessions() => false;
    public override long GetSessionCacheMaxSize() => long.MaxValue;
    public override long GetSessionCacheExpireMillis() => long.MaxValue;
    public override bool NotifyExpiredIntermediateKeyOnRead() => true;
    public override bool NotifyExpiredSystemKeyOnRead() => true;
    public override KeyRotationStrategy GetKeyRotationStrategy() => KeyRotationStrategy.Inline;
}
