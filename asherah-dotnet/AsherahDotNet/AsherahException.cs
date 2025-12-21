using System;

namespace GoDaddy.Asherah;

public sealed class AsherahException : Exception
{
    public AsherahException(string message, int? errorCode = null)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    public int? ErrorCode { get; }
}
