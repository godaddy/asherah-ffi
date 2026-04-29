using System;
using System.Text;

namespace GoDaddy.Asherah.Encryption;

public sealed class AsherahFactory : IAsherahFactory
{
    private readonly SafeFactoryHandle _handle;
    private bool _disposed;

    internal AsherahFactory(SafeFactoryHandle handle)
    {
        _handle = handle;
    }

    public unsafe AsherahSession GetSession(string partitionId)
    {
        if (partitionId is null)
        {
            throw new ArgumentNullException(nameof(partitionId));
        }
        EnsureNotDisposed();

        var maxBytes = Encoding.UTF8.GetMaxByteCount(partitionId.Length) + 1; // +1 for null terminator
        Span<byte> buf = maxBytes <= 256 ? stackalloc byte[maxBytes] : new byte[maxBytes];
        var written = Encoding.UTF8.GetBytes(partitionId.AsSpan(), buf);
        buf[written] = 0; // null-terminate

        IntPtr sessionPtr;
        fixed (byte* ptr = buf)
        {
            sessionPtr = NativeMethods.asherah_factory_get_session(_handle.DangerousGetHandle(), ptr);
        }
        if (sessionPtr == IntPtr.Zero)
        {
            throw NativeError.Create("Failed to get session");
        }
        return new AsherahSession(new SafeSessionHandle(sessionPtr));
    }

    IAsherahSession IAsherahFactory.GetSession(string partitionId) => GetSession(partitionId);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _handle.Dispose();
        _disposed = true;
    }

    private void EnsureNotDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(AsherahFactory));
        }
    }

}
