using System;
using System.Runtime.InteropServices;
using System.Text;

namespace GoDaddy.Asherah;

public sealed class AsherahSession : IDisposable
{
    private SafeSessionHandle _handle;
    private bool _disposed;

    internal AsherahSession(SafeSessionHandle handle)
    {
        _handle = handle;
    }

    public byte[] EncryptBytes(byte[] plaintext)
    {
        if (plaintext is null)
        {
            throw new ArgumentNullException(nameof(plaintext));
        }
        EnsureNotDisposed();

        var buffer = default(AsherahBuffer);
        var status = NativeMethods.asherah_encrypt_to_json(_handle.DangerousGetHandle(), plaintext, new UIntPtr((ulong)plaintext.LongLength), ref buffer);
        if (status != 0)
        {
            throw NativeError.Create("encrypt_to_json");
        }

        try
        {
            return ExtractAndFree(ref buffer);
        }
        finally
        {
            NativeMethods.asherah_buffer_free(ref buffer);
        }
    }

    public string EncryptString(string plaintext)
    {
        if (plaintext is null)
        {
            throw new ArgumentNullException(nameof(plaintext));
        }
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        return Encoding.UTF8.GetString(EncryptBytes(bytes));
    }

    public byte[] DecryptBytes(byte[] ciphertextJson)
    {
        if (ciphertextJson is null)
        {
            throw new ArgumentNullException(nameof(ciphertextJson));
        }
        EnsureNotDisposed();

        var buffer = default(AsherahBuffer);
        var status = NativeMethods.asherah_decrypt_from_json(_handle.DangerousGetHandle(), ciphertextJson, new UIntPtr((ulong)ciphertextJson.LongLength), ref buffer);
        if (status != 0)
        {
            throw NativeError.Create("decrypt_from_json");
        }

        try
        {
            return ExtractAndFree(ref buffer);
        }
        finally
        {
            NativeMethods.asherah_buffer_free(ref buffer);
        }
    }

    public string DecryptString(string ciphertextJson)
    {
        if (ciphertextJson is null)
        {
            throw new ArgumentNullException(nameof(ciphertextJson));
        }
        var bytes = Encoding.UTF8.GetBytes(ciphertextJson);
        var plaintext = DecryptBytes(bytes);
        return Encoding.UTF8.GetString(plaintext);
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
            throw new ObjectDisposedException(nameof(AsherahSession));
        }
    }

    private static byte[] ExtractAndFree(ref AsherahBuffer buffer)
    {
        if (buffer.data == IntPtr.Zero || buffer.len == UIntPtr.Zero)
        {
            return Array.Empty<byte>();
        }

        var length = checked((int)buffer.len.ToUInt64());
        var managed = new byte[length];
        Marshal.Copy(buffer.data, managed, 0, length);
        return managed;
    }
}
