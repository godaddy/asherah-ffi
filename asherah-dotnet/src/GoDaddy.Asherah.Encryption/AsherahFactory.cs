using System;
using System.Text;

namespace GoDaddy.Asherah.Encryption;

/// <summary>
/// Native-backed session factory (<c>asherah_factory_*</c>). Prefer
/// <see cref="FromConfig"/> for programmatic configuration or <see cref="FromEnv"/> for environment variables.
/// </summary>
public sealed class AsherahFactory : IAsherahFactory
{
    private readonly SafeFactoryHandle _handle;
    private bool _disposed;

    internal AsherahFactory(SafeFactoryHandle handle)
    {
        _handle = handle;
    }

    /// <summary>
    /// Create a factory from environment-variable configuration. The Rust
    /// core reads <c>SERVICE_NAME</c>, <c>PRODUCT_ID</c>, <c>METASTORE</c>
    /// (etc.) from the process environment.
    /// </summary>
    /// <exception cref="AsherahException">
    /// Thrown if the native call fails (missing required env vars,
    /// metastore connection failure, etc.).
    /// </exception>
    public static AsherahFactory FromEnv()
    {
        var ptr = NativeMethods.asherah_factory_new_from_env();
        if (ptr == IntPtr.Zero)
        {
            throw NativeError.Create("factory_from_env");
        }

        return new AsherahFactory(new SafeFactoryHandle(ptr));
    }

    /// <summary>
    /// Create a factory from an explicit <see cref="AsherahConfig"/>.
    /// Preferred over <see cref="FromEnv"/> when configuration comes from
    /// app config / DI / a builder rather than environment variables.
    /// </summary>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="config"/> is <c>null</c>.
    /// </exception>
    /// <exception cref="AsherahException">
    /// Thrown if the native call fails (invalid config, metastore
    /// connection failure, etc.).
    /// </exception>
    public static AsherahFactory FromConfig(AsherahConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        using var json = new Utf8String(config.ToJson());
        var ptr = NativeMethods.asherah_factory_new_with_config(json.Pointer);
        if (ptr == IntPtr.Zero)
        {
            throw NativeError.Create("factory_from_config");
        }

        return new AsherahFactory(new SafeFactoryHandle(ptr));
    }

    /// <summary>
    /// Acquires or creates an <see cref="AsherahSession"/> bound to <paramref name="partitionId"/>.
    /// </summary>
    /// <param name="partitionId">Logical tenant or user partition (<c>null</c> rejected).</param>
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

    /// <inheritdoc />
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
