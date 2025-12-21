using System;
using GoDaddy.Asherah.Crypto.BufferUtils;
using GoDaddy.Asherah.Crypto.Keys;

namespace GoDaddy.Asherah.Crypto.Envelope;

public abstract class AeadEnvelopeCrypto : AeadCrypto
{
    public virtual byte[] EncryptKey(CryptoKey key, CryptoKey keyEncryptionKey)
    {
        return key.WithKey(keyBytes => Encrypt(keyBytes, keyEncryptionKey));
    }

    public virtual CryptoKey DecryptKey(byte[] encryptedKey, DateTimeOffset encryptedKeyCreated, CryptoKey keyEncryptionKey)
    {
        return DecryptKey(encryptedKey, encryptedKeyCreated, keyEncryptionKey, false);
    }

    public virtual CryptoKey DecryptKey(
        byte[] encryptedKey,
        DateTimeOffset encryptedKeyCreated,
        CryptoKey keyEncryptionKey,
        bool revoked)
    {
        byte[] decryptedKey = Decrypt(encryptedKey, keyEncryptionKey);
        try
        {
            return GenerateKeyFromBytes(decryptedKey, encryptedKeyCreated, revoked);
        }
        finally
        {
            ManagedBufferUtils.WipeByteArray(decryptedKey);
        }
    }

    public virtual EnvelopeEncryptResult<T> EnvelopeEncrypt<T>(byte[] plainText, CryptoKey keyEncryptionKey) where T : class
    {
        return EnvelopeEncrypt<T>(plainText, keyEncryptionKey, null);
    }

    public virtual EnvelopeEncryptResult<T> EnvelopeEncrypt<T>(
        byte[] plainText,
        CryptoKey keyEncryptionKey,
        T? userState) where T : class
    {
        using (CryptoKey dataEncryptionKey = GenerateKey())
        {
            EnvelopeEncryptResult<T> result = new()
            {
                CipherText = Encrypt(plainText, dataEncryptionKey),
                EncryptedKey = EncryptKey(dataEncryptionKey, keyEncryptionKey),
                UserState = userState,
            };
            return result;
        }
    }

    public virtual byte[] EnvelopeDecrypt(
        byte[] cipherText,
        byte[] encryptedKey,
        DateTimeOffset keyCreated,
        CryptoKey keyEncryptionKey)
    {
        using (CryptoKey plaintextKey = DecryptKey(encryptedKey, keyCreated, keyEncryptionKey))
        {
            return Decrypt(cipherText, plaintextKey);
        }
    }
}
