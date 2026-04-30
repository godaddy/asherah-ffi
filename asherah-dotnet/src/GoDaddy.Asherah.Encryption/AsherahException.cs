using System;

namespace GoDaddy.Asherah.Encryption;

/// <summary>
/// Binding-specific exception surfaced when native Asherah returns an error message.
/// </summary>
public sealed class AsherahException : Exception
{
    /// <summary>Creates an exception with a caller-safe diagnostic (no secrets).</summary>
    public AsherahException(string message)
        : base(message)
    {
    }
}
