using System;
using System.Security.Cryptography;
using GoDaddy.Asherah.Crypto.BufferUtils;
using GoDaddy.Asherah.Crypto.Keys;
using GoDaddy.Asherah.SecureMemory;

namespace GoDaddy.Asherah.Crypto;

public abstract class AeadCrypto : IDisposable
{
    private const int BitsPerByte = 8;
    private static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();

    private readonly NonceGenerator _nonceGenerator;
    private readonly TransientSecretFactory _secretFactory;

    protected AeadCrypto()
    {
        _secretFactory = new TransientSecretFactory();
        _nonceGenerator = new NonceGenerator();
    }

    public abstract byte[] Encrypt(byte[] input, CryptoKey key);
    public abstract byte[] Decrypt(byte[] input, CryptoKey key);

    public virtual CryptoKey GenerateKey()
    {
        return GenerateRandomCryptoKey();
    }

    public virtual CryptoKey GenerateKey(DateTimeOffset created)
    {
        return GenerateRandomCryptoKey(created);
    }

    public virtual CryptoKey GenerateKeyFromBytes(byte[] sourceBytes)
    {
        return GenerateKeyFromBytes(sourceBytes, DateTimeOffset.UtcNow);
    }

    public virtual CryptoKey GenerateKeyFromBytes(byte[] sourceBytes, DateTimeOffset created)
    {
        return GenerateKeyFromBytes(sourceBytes, created, false);
    }

    public virtual CryptoKey GenerateKeyFromBytes(byte[] sourceBytes, DateTimeOffset created, bool revoked)
    {
        byte[] clonedBytes = (byte[])sourceBytes.Clone();
        Secret newKeySecret = GetSecretFactory().CreateSecret(clonedBytes);
        return new SecretCryptoKey(newKeySecret, created, revoked);
    }

    protected internal virtual CryptoKey GenerateRandomCryptoKey()
    {
        return GenerateRandomCryptoKey(DateTimeOffset.UtcNow);
    }

    protected internal virtual CryptoKey GenerateRandomCryptoKey(DateTimeOffset created)
    {
        int keyLengthBits = GetKeySizeBits();
        if (keyLengthBits % BitsPerByte != 0)
        {
            throw new ArgumentException("Invalid key length: " + keyLengthBits);
        }

        byte[] keyBytes = new byte[keyLengthBits / BitsPerByte];
        CryptoRandom.GetBytes(keyBytes);
        try
        {
            return GenerateKeyFromBytes(keyBytes, created);
        }
        finally
        {
            ManagedBufferUtils.WipeByteArray(keyBytes);
        }
    }

    protected internal abstract int GetKeySizeBits();

    protected internal virtual ISecretFactory GetSecretFactory()
    {
        return _secretFactory;
    }

    protected abstract int GetNonceSizeBits();

    protected abstract int GetMacSizeBits();

    protected byte[] GetAppendedNonce(byte[] cipherTextAndNonce)
    {
        int nonceByteSize = GetNonceSizeBits() / BitsPerByte;
        byte[] nonce = new byte[nonceByteSize];
        Array.Copy(cipherTextAndNonce, cipherTextAndNonce.Length - nonceByteSize, nonce, 0, nonceByteSize);
        return nonce;
    }

    protected static void AppendNonce(byte[] cipherText, byte[] nonce)
    {
        Array.Copy(nonce, 0, cipherText, cipherText.Length - nonce.Length, nonce.Length);
    }

    protected byte[] GenerateNonce()
    {
        return _nonceGenerator.CreateNonce(GetNonceSizeBits());
    }

    public void Dispose()
    {
        _secretFactory.Dispose();
    }
}
