using GoDaddy.Asherah.Crypto.Exceptions;

namespace GoDaddy.Asherah.AppEncryption.Exceptions;

public class KmsException : AppEncryptionException
{
    public KmsException(string message)
        : base(message)
    {
    }
}

public class MetadataMissingException : AppEncryptionException
{
    public MetadataMissingException(string message)
        : base(message)
    {
    }
}
