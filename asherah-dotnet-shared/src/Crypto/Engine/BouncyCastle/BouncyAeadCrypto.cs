using System;
using System.Security.Cryptography;
using GoDaddy.Asherah.Crypto.BufferUtils;
using GoDaddy.Asherah.Crypto.Envelope;
using GoDaddy.Asherah.Crypto.Exceptions;
using GoDaddy.Asherah.Crypto.Keys;

namespace GoDaddy.Asherah.Crypto.Engine.BouncyCastle;

public abstract class BouncyAeadCrypto : AeadEnvelopeCrypto
{
    public override byte[] Encrypt(byte[] input, CryptoKey key)
    {
        byte[] nonce = GenerateNonce();
        int tagSize = GetMacSizeBits() / 8;
        byte[] cipherText = new byte[input.Length];
        byte[] tag = new byte[tagSize];

        byte[]? keyCopy = null;
        try
        {
            key.WithKey(keyBytes =>
            {
                keyCopy = (byte[])keyBytes.Clone();
                using var aes = new AesGcm(keyCopy, tagSize);
                aes.Encrypt(nonce, input, cipherText, tag);
            });

            byte[] output = new byte[cipherText.Length + tag.Length + nonce.Length];
            Buffer.BlockCopy(cipherText, 0, output, 0, cipherText.Length);
            Buffer.BlockCopy(tag, 0, output, cipherText.Length, tag.Length);
            AppendNonce(output, nonce);
            return output;
        }
        catch (Exception e)
        {
            throw new AppEncryptionException("unexpected error during encrypt cipher finalization", e);
        }
        finally
        {
            if (keyCopy != null)
            {
                ManagedBufferUtils.WipeByteArray(keyCopy);
            }
        }
    }

    public override byte[] Decrypt(byte[] input, CryptoKey key)
    {
        byte[] nonce = GetAppendedNonce(input);
        int tagSize = GetMacSizeBits() / 8;
        int cipherTextLength = input.Length - nonce.Length - tagSize;
        if (cipherTextLength < 0)
        {
            throw new AppEncryptionException("unexpected error during decrypt cipher finalization");
        }

        byte[] cipherText = new byte[cipherTextLength];
        byte[] tag = new byte[tagSize];
        Buffer.BlockCopy(input, 0, cipherText, 0, cipherTextLength);
        Buffer.BlockCopy(input, cipherTextLength, tag, 0, tagSize);

        byte[] plainText = new byte[cipherTextLength];
        byte[]? keyCopy = null;
        try
        {
            key.WithKey(keyBytes =>
            {
                keyCopy = (byte[])keyBytes.Clone();
                using var aes = new AesGcm(keyCopy, tagSize);
                aes.Decrypt(nonce, cipherText, tag, plainText);
            });

            return plainText;
        }
        catch (Exception e)
        {
            throw new AppEncryptionException("unexpected error during decrypt cipher finalization", e);
        }
        finally
        {
            if (keyCopy != null)
            {
                ManagedBufferUtils.WipeByteArray(keyCopy);
            }
        }
    }
}
