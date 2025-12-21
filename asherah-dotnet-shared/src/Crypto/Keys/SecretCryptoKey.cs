using System;
using GoDaddy.Asherah.SecureMemory;

namespace GoDaddy.Asherah.Crypto.Keys;

public class SecretCryptoKey : CryptoKey
{
    private readonly DateTimeOffset _created;
    private volatile bool _revoked;

    public SecretCryptoKey(CryptoKey otherKey)
    {
        Secret = ((SecretCryptoKey)otherKey).Secret.CopySecret();
        _created = ((SecretCryptoKey)otherKey)._created;
        _revoked = ((SecretCryptoKey)otherKey)._revoked;
    }

    public SecretCryptoKey(Secret secret, DateTimeOffset created, bool revoked)
    {
        Secret = secret;
        _created = created;
        _revoked = revoked;
    }

    internal virtual Secret Secret { get; }

    public override DateTimeOffset GetCreated() => _created;

    public override void WithKey(Action<byte[]> actionWithKey)
    {
        Secret.WithSecretBytes(actionWithKey);
    }

    public override TResult WithKey<TResult>(Func<byte[], TResult> actionWithKey)
    {
        return Secret.WithSecretBytes(actionWithKey);
    }

    public override void Dispose()
    {
        Secret.Dispose();
    }

    public override bool IsRevoked() => _revoked;

    public override void MarkRevoked() => _revoked = true;
}
