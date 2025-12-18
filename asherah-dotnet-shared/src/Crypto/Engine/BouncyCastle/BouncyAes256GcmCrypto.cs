namespace GoDaddy.Asherah.Crypto.Engine.BouncyCastle;

public class BouncyAes256GcmCrypto : BouncyAeadCrypto
{
    private const int NonceSizeBits = 96;
    private const int KeySizeBits = 256;
    private const int MacSizeBits = 128;

    protected internal override int GetKeySizeBits()
    {
        return KeySizeBits;
    }

    protected override int GetNonceSizeBits()
    {
        return NonceSizeBits;
    }

    protected override int GetMacSizeBits()
    {
        return MacSizeBits;
    }
}
