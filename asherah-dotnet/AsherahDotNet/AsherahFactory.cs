using System;

namespace GoDaddy.Asherah;

public sealed class AsherahFactory : IDisposable
{
    private SafeFactoryHandle _handle;
    private bool _disposed;

    internal AsherahFactory(SafeFactoryHandle handle)
    {
        _handle = handle;
    }

    public AsherahSession GetSession(string partitionId)
    {
        if (partitionId is null)
        {
            throw new ArgumentNullException(nameof(partitionId));
        }
        EnsureNotDisposed();

        using var partition = new Utf8String(partitionId);
        var sessionPtr = NativeMethods.asherah_factory_get_session(_handle.DangerousGetHandle(), partition.Pointer);
        if (sessionPtr == IntPtr.Zero)
        {
            throw NativeError.Create("Failed to get session");
        }
        return new AsherahSession(new SafeSessionHandle(sessionPtr));
    }

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
