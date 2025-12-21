using System;

namespace GoDaddy.Asherah.Crypto.Keys;

public class SharedCryptoKey : CryptoKey
{
    internal SharedCryptoKey(CryptoKey sharedKey)
    {
        SharedKey = sharedKey;
    }

    internal CryptoKey SharedKey { get; }

    public override DateTimeOffset GetCreated() => SharedKey.GetCreated();

    public override void WithKey(Action<byte[]> actionWithKey) => SharedKey.WithKey(actionWithKey);

    public override TResult WithKey<TResult>(Func<byte[], TResult> actionWithKey) =>
        SharedKey.WithKey(actionWithKey);

    public override void Dispose()
    {
    }

    public override bool IsRevoked() => SharedKey.IsRevoked();

    public override void MarkRevoked() => SharedKey.MarkRevoked();
}
