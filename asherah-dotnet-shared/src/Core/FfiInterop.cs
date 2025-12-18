#if ASHERAH_FFI
using System;
using System.Runtime.InteropServices;
using GoDaddy.Asherah.AppEncryption.Exceptions;
using GoDaddy.Asherah.Crypto.Exceptions;

namespace GoDaddy.Asherah.Internal;

internal sealed class FfiCore : IAsherahCore
{
    private readonly SafeFactoryHandle _factory;

    public FfiCore(ConfigOptions config)
    {
        using var json = new Utf8String(config.ToJson());
        IntPtr factoryPtr = NativeMethods.asherah_factory_new_with_config(json.Pointer);
        if (factoryPtr == IntPtr.Zero)
        {
            throw NativeError.CreateException("factory_new_with_config");
        }

        _factory = new SafeFactoryHandle(factoryPtr);
    }

    public byte[] EncryptToJson(string partitionId, byte[] plaintext)
    {
        using SafeSessionHandle session = GetSession(partitionId);
        AsherahBuffer buffer = default;
        int result = NativeMethods.asherah_encrypt_to_json(
            session.DangerousGetHandle(),
            plaintext,
            (UIntPtr)plaintext.Length,
            ref buffer);
        if (result != 0)
        {
            throw NativeError.CreateException("encrypt_to_json");
        }

        try
        {
            return CopyBuffer(buffer);
        }
        finally
        {
            NativeMethods.asherah_buffer_free(ref buffer);
        }
    }

    public byte[] DecryptFromJson(string partitionId, byte[] json)
    {
        using SafeSessionHandle session = GetSession(partitionId);
        AsherahBuffer buffer = default;
        int result = NativeMethods.asherah_decrypt_from_json(
            session.DangerousGetHandle(),
            json,
            (UIntPtr)json.Length,
            ref buffer);
        if (result != 0)
        {
            throw NativeError.CreateException("decrypt_from_json");
        }

        try
        {
            return CopyBuffer(buffer);
        }
        finally
        {
            NativeMethods.asherah_buffer_free(ref buffer);
        }
    }

    public void Dispose()
    {
        _factory.Dispose();
    }

    private SafeSessionHandle GetSession(string partitionId)
    {
        using var partition = new Utf8String(partitionId);
        IntPtr sessionPtr = NativeMethods.asherah_factory_get_session(_factory.DangerousGetHandle(), partition.Pointer);
        if (sessionPtr == IntPtr.Zero)
        {
            throw NativeError.CreateException("factory_get_session");
        }
        return new SafeSessionHandle(sessionPtr);
    }

    private static byte[] CopyBuffer(AsherahBuffer buffer)
    {
        if (buffer.data == IntPtr.Zero || buffer.len == UIntPtr.Zero)
        {
            return Array.Empty<byte>();
        }

        int length = checked((int)buffer.len);
        byte[] result = new byte[length];
        Marshal.Copy(buffer.data, result, 0, length);
        return result;
    }
}

internal static class NativeError
{
    public static AppEncryptionException CreateException(string operation)
    {
        string message = GetLastErrorMessage();
        int? code = GetLastErrorCode();
        string suffix = code.HasValue ? $" (code {code.Value})" : string.Empty;
        string full = string.IsNullOrWhiteSpace(message)
            ? $"Native error during {operation}{suffix}"
            : $"Native error during {operation}: {message}{suffix}";
        return MapException(full, code);
    }

    private static AppEncryptionException MapException(string message, int? code)
    {
        if (code.HasValue)
        {
            if (code.Value == ErrMetadata)
            {
                return new MetadataMissingException(message);
            }
            if (code.Value == ErrKms)
            {
                return new KmsException(message);
            }
        }

        if (IsMetadataMissing(message))
        {
            return new MetadataMissingException(message);
        }

        if (IsKmsFailure(message))
        {
            return new KmsException(message);
        }

        return new AppEncryptionException(message);
    }

    private static bool IsMetadataMissing(string message)
    {
        return Contains(message, "metadata missing")
            || Contains(message, "system key not found")
            || Contains(message, "latest not found");
    }

    private static bool IsKmsFailure(string message)
    {
        return Contains(message, "kms encrypt")
            || Contains(message, "kms decrypt")
            || Contains(message, "kms");
    }

    private static bool Contains(string message, string token)
    {
        return message.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private const int ErrKms = 6;
    private const int ErrMetadata = 7;

    private static string GetLastErrorMessage()
    {
        IntPtr ptr = NativeMethods.asherah_last_error_message();
        if (ptr == IntPtr.Zero)
        {
            return string.Empty;
        }

        return Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
    }

    private static int? GetLastErrorCode()
    {
        int code = NativeMethods.asherah_last_error_code();
        return code == 0 ? null : code;
    }
}

internal static class NativeMethods
{
    private const string LibraryName = "asherah_ffi";

    static NativeMethods()
    {
        NativeLibraryLoader.EnsureRegistered();
    }

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr asherah_factory_new_with_config(IntPtr configJson);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void asherah_factory_free(IntPtr factory);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr asherah_factory_get_session(IntPtr factory, IntPtr partitionId);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void asherah_session_free(IntPtr session);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int asherah_encrypt_to_json(IntPtr session, byte[] data, UIntPtr length, ref AsherahBuffer buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int asherah_decrypt_from_json(IntPtr session, byte[] json, UIntPtr length, ref AsherahBuffer buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void asherah_buffer_free(ref AsherahBuffer buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr asherah_last_error_message();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int asherah_last_error_code();
}

[StructLayout(LayoutKind.Sequential)]
internal struct AsherahBuffer
{
    public IntPtr data;
    public UIntPtr len;
}

internal sealed class SafeFactoryHandle : SafeHandle
{
    public SafeFactoryHandle(IntPtr handle)
        : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        if (!IsInvalid)
        {
            NativeMethods.asherah_factory_free(handle);
        }
        return true;
    }
}

internal sealed class SafeSessionHandle : SafeHandle
{
    public SafeSessionHandle(IntPtr handle)
        : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        if (!IsInvalid)
        {
            NativeMethods.asherah_session_free(handle);
        }
        return true;
    }
}

internal sealed class Utf8String : IDisposable
{
    private IntPtr _pointer;

    public Utf8String(string value)
    {
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(value + "\0");
        _pointer = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, _pointer, bytes.Length);
    }

    public IntPtr Pointer => _pointer;

    public void Dispose()
    {
        if (_pointer != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(_pointer);
            _pointer = IntPtr.Zero;
        }
    }
}
#endif
