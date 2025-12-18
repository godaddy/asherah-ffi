using System;
using System.Threading.Tasks;
using GoDaddy.Asherah.Crypto.Keys;

namespace GoDaddy.Asherah.AppEncryption.Kms;

public interface IKeyManagementService
{
    byte[] EncryptKey(CryptoKey key);
    CryptoKey DecryptKey(byte[] keyCipherText, DateTimeOffset keyCreated, bool revoked);
    Task<byte[]> EncryptKeyAsync(CryptoKey key);
    Task<CryptoKey> DecryptKeyAsync(byte[] keyCipherText, DateTimeOffset keyCreated, bool revoked);
}
