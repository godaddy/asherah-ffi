using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace GoDaddy.Asherah.Encryption;

public sealed class AsherahSession : IAsherahSession
{
    private readonly SafeSessionHandle _handle;
    private int _pendingOps;
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
        if (ciphertextJson.Length == 0)
        {
            // Pre-FFI guard: empty input cannot be a valid DataRowRecord
            // envelope (a real envelope is ~241+ bytes). Reject before
            // crossing FFI to give a clear, actionable error instead of the
            // forwarded serde "expected value at line 1 column 1".
            throw new AsherahException(
                "decrypt: ciphertext is empty (expected a DataRowRecord JSON envelope)");
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
        if (ciphertextJson.Length == 0)
        {
            throw new AsherahException(
                "decrypt: ciphertext is empty (expected a DataRowRecord JSON envelope)");
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
        Interlocked.Increment(ref _pendingOps);

        var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var gcHandle = GCHandle.Alloc(new AsyncCallbackState(tcs, this));

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
                Interlocked.Decrement(ref _pendingOps);
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
        if (ciphertextJson.Length == 0)
        {
            // Surface as a faulted Task (consistent with how
            // the C ABI surfaces errors via the async callback path)
            // rather than throwing synchronously. ArgumentNullException
            // (above) does throw sync — that's the established C# contract
            // for null inputs across both sync and async APIs.
            return Task.FromException<byte[]>(new AsherahException(
                "decrypt: ciphertext is empty (expected a DataRowRecord JSON envelope)"));
        }
        EnsureNotDisposed();
        Interlocked.Increment(ref _pendingOps);

        var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var gcHandle = GCHandle.Alloc(new AsyncCallbackState(tcs, this));

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
                Interlocked.Decrement(ref _pendingOps);
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
        if (ciphertextJson.Length == 0)
        {
            throw new AsherahException(
                "decrypt: ciphertext is empty (expected a DataRowRecord JSON envelope)");
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
        // Wait for in-flight async operations before releasing the handle.
        var spin = new SpinWait();
        while (Volatile.Read(ref _pendingOps) > 0)
        {
            spin.SpinOnce();
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

    private sealed record AsyncCallbackState(TaskCompletionSource<byte[]> Tcs, AsherahSession Session);

    /// <summary>
    /// Callback invoked by Rust on a tokio worker thread when an async operation completes.
    /// Resolves the TaskCompletionSource and decrements the pending-ops counter.
    /// </summary>
    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void AsyncCompletionCallback(
        IntPtr userData,
        IntPtr resultData,
        UIntPtr resultLen,
        IntPtr errorMessage)
    {
        var gcHandle = GCHandle.FromIntPtr(userData);
        var state = (AsyncCallbackState)gcHandle.Target!;
        gcHandle.Free();

        try
        {
            if (errorMessage != IntPtr.Zero)
            {
                var error = Marshal.PtrToStringUTF8(errorMessage) ?? "unknown async error";
                state.Tcs.SetException(new AsherahException(error));
            }
            else if (resultData == IntPtr.Zero || resultLen == UIntPtr.Zero)
            {
                state.Tcs.SetResult(Array.Empty<byte>());
            }
            else
            {
                var length = checked((int)resultLen.ToUInt64());
                var managed = new byte[length];
                Marshal.Copy(resultData, managed, 0, length);
                state.Tcs.SetResult(managed);
            }
        }
        finally
        {
            Interlocked.Decrement(ref state.Session._pendingOps);
        }
    }
}
