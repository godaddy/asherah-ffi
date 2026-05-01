using System;

namespace GoDaddy.Asherah.Encryption;

/// <summary>
/// FFI-backed factory for per-partition sessions. Implemented by <see cref="AsherahFactory"/>.
/// </summary>
public interface IAsherahFactory : IDisposable
{
    /// <inheritdoc cref="AsherahFactory.GetSession(string)"/>
    IAsherahSession GetSession(string partitionId);
}
