using System;
using System.Threading.Tasks;

namespace GoDaddy.Asherah.Encryption;

/// <summary>
/// Per-partition encrypt/decrypt session. Implemented by <see cref="AsherahSession"/>.
/// </summary>
public interface IAsherahSession : IDisposable
{
    /// <inheritdoc cref="AsherahSession.EncryptBytes(byte[])"/>
    byte[] EncryptBytes(byte[] plaintext);

    /// <inheritdoc cref="AsherahSession.EncryptString(string)"/>
    string EncryptString(string plaintext);

    /// <inheritdoc cref="AsherahSession.DecryptBytes(byte[])"/>
    byte[] DecryptBytes(byte[] ciphertextJson);

    /// <inheritdoc cref="AsherahSession.DecryptString(string)"/>
    string DecryptString(string ciphertextJson);

    /// <inheritdoc cref="AsherahSession.EncryptBytesAsync(byte[])"/>
    Task<byte[]> EncryptBytesAsync(byte[] plaintext);

    /// <inheritdoc cref="AsherahSession.EncryptStringAsync(string)"/>
    Task<string> EncryptStringAsync(string plaintext);

    /// <inheritdoc cref="AsherahSession.DecryptBytesAsync(byte[])"/>
    Task<byte[]> DecryptBytesAsync(byte[] ciphertextJson);

    /// <inheritdoc cref="AsherahSession.DecryptStringAsync(string)"/>
    Task<string> DecryptStringAsync(string ciphertextJson);
}
