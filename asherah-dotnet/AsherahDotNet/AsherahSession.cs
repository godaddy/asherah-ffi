using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace GoDaddy.Asherah;

public sealed class AsherahSession : IAsherahSession
{
    private readonly SafeSessionHandle _handle;
    private bool _disposed;

    internal AsherahSession(SafeSessionHandle handle)
    {
        _handle = handle;
    }

    public unsafe byte[] EncryptBytes(byte[] plaintext)
    {
        if (plaintext is null)
        {
            throw new ArgumentNullException(nameof(plaintext));
        }
        EnsureNotDisposed();

        var buffer = default(AsherahBuffer);
        int status;
        fixed (byte* ptr = plaintext)
        {
            status = NativeMethods.asherah_encrypt_to_json(_handle.DangerousGetHandle(), ptr, new UIntPtr((ulong)plaintext.LongLength), ref buffer);
        }
        if (status != 0)
        {
            throw NativeError.Create("encrypt_to_json");
        }

        try
        {
            return Extract(ref buffer);
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

    public unsafe byte[] DecryptBytes(byte[] ciphertextJson)
    {
        if (ciphertextJson is null)
        {
            throw new ArgumentNullException(nameof(ciphertextJson));
        }
        EnsureNotDisposed();

        var buffer = default(AsherahBuffer);
        int status;
        fixed (byte* ptr = ciphertextJson)
        {
            status = NativeMethods.asherah_decrypt_from_json(_handle.DangerousGetHandle(), ptr, new UIntPtr((ulong)ciphertextJson.LongLength), ref buffer);
        }
        if (status != 0)
        {
            throw NativeError.Create("decrypt_from_json");
        }

        try
        {
            return Extract(ref buffer);
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

    /// <summary>
    /// True async encrypt — runs on Rust's tokio runtime, does not block a .NET thread pool thread.
    /// </summary>
    public unsafe Task<byte[]> EncryptBytesAsync(byte[] plaintext)
    {
        if (plaintext is null)
        {
            throw new ArgumentNullException(nameof(plaintext));
        }
        EnsureNotDisposed();

        var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var gcHandle = GCHandle.Alloc(tcs);

        fixed (byte* ptr = plaintext)
        {
            var status = NativeMethods.asherah_encrypt_to_json_async(
                _handle.DangerousGetHandle(),
                ptr,
                new UIntPtr((ulong)plaintext.LongLength),
                &AsyncCompletionCallback,
                GCHandle.ToIntPtr(gcHandle));

            if (status != 0)
            {
                gcHandle.Free();
                throw NativeError.Create("encrypt_to_json_async");
            }
        }

        return tcs.Task;
    }

    public async Task<string> EncryptStringAsync(string plaintext)
    {
        if (plaintext is null)
        {
            throw new ArgumentNullException(nameof(plaintext));
        }
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        var result = await EncryptBytesAsync(bytes).ConfigureAwait(false);
        return Encoding.UTF8.GetString(result);
    }

    /// <summary>
    /// True async decrypt — runs on Rust's tokio runtime, does not block a .NET thread pool thread.
    /// </summary>
    public unsafe Task<byte[]> DecryptBytesAsync(byte[] ciphertextJson)
    {
        if (ciphertextJson is null)
        {
            throw new ArgumentNullException(nameof(ciphertextJson));
        }
        EnsureNotDisposed();

        var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var gcHandle = GCHandle.Alloc(tcs);

        fixed (byte* ptr = ciphertextJson)
        {
            var status = NativeMethods.asherah_decrypt_from_json_async(
                _handle.DangerousGetHandle(),
                ptr,
                new UIntPtr((ulong)ciphertextJson.LongLength),
                &AsyncCompletionCallback,
                GCHandle.ToIntPtr(gcHandle));

            if (status != 0)
            {
                gcHandle.Free();
                throw NativeError.Create("decrypt_from_json_async");
            }
        }

        return tcs.Task;
    }

    public async Task<string> DecryptStringAsync(string ciphertextJson)
    {
        if (ciphertextJson is null)
        {
            throw new ArgumentNullException(nameof(ciphertextJson));
        }
        var bytes = Encoding.UTF8.GetBytes(ciphertextJson);
        var result = await DecryptBytesAsync(bytes).ConfigureAwait(false);
        return Encoding.UTF8.GetString(result);
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

    private static byte[] Extract(ref AsherahBuffer buffer)
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

    /// <summary>
    /// Callback invoked by Rust on a tokio worker thread when an async operation completes.
    /// Resolves the TaskCompletionSource stored in userData.
    /// </summary>
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AsyncCompletionCallback(
        IntPtr userData,
        IntPtr resultData,
        UIntPtr resultLen,
        IntPtr errorMessage)
    {
        var gcHandle = GCHandle.FromIntPtr(userData);
        var tcs = (TaskCompletionSource<byte[]>)gcHandle.Target!;
        gcHandle.Free();

        if (errorMessage != IntPtr.Zero)
        {
            var error = Marshal.PtrToStringUTF8(errorMessage) ?? "unknown async error";
            tcs.SetException(new AsherahException(error));
        }
        else if (resultData == IntPtr.Zero || resultLen == UIntPtr.Zero)
        {
            tcs.SetResult(Array.Empty<byte>());
        }
        else
        {
            var length = checked((int)resultLen.ToUInt64());
            var managed = new byte[length];
            Marshal.Copy(resultData, managed, 0, length);
            tcs.SetResult(managed);
        }
    }
}
