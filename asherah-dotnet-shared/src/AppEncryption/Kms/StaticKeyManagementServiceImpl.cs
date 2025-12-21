using System;
using GoDaddy.Asherah.Crypto.Keys;

namespace GoDaddy.Asherah.AppEncryption.Kms;

public class StaticKeyManagementServiceImpl : KeyManagementService, IDisposable
{
    public StaticKeyManagementServiceImpl(string key)
    {
        StaticMasterKey = key;
    }

    internal string StaticMasterKey { get; }

    public override byte[] EncryptKey(CryptoKey key) =>
        throw new NotSupportedException("StaticKeyManagementServiceImpl is configuration-only when using native core");

    public override CryptoKey DecryptKey(byte[] keyCipherText, DateTimeOffset keyCreated, bool revoked) =>
        throw new NotSupportedException("StaticKeyManagementServiceImpl is configuration-only when using native core");

    public void Dispose()
    {
    }
}
