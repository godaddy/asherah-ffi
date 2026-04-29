using System;

namespace GoDaddy.Asherah.Encryption;

public sealed class AsherahException : Exception
{
    public AsherahException(string message)
        : base(message)
    {
    }
}
