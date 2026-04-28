using System;

namespace GoDaddy.Asherah;

public sealed class AsherahException : Exception
{
    public AsherahException(string message)
        : base(message)
    {
    }
}
