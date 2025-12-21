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
        IntPtr factoryPtr = IntPtr.Zero;
        try
        {
            factoryPtr = NativeMethods.asherah_factory_new_with_config(json.Pointer);
            if (factoryPtr == IntPtr.Zero)
            {
                throw NativeError.CreateException("factory_new_with_config");
            }

            _factory = new SafeFactoryHandle(factoryPtr);
        }
        catch
        {
            if (factoryPtr != IntPtr.Zero)
            {
                NativeMethods.asherah_factory_free(factoryPtr);
            }
            throw;
        }
    }

    public byte[] EncryptToJson(string partitionId, byte[] plaintext)
    {
        using SafeSessionHandle session = GetSession(partitionId);
        AsherahBuffer buffer = default;
        int result = NativeMethods.asherah_encrypt_to_json(
            session,
            plaintext,
            (UIntPtr)plaintext.Length,
            ref buffer);
        if (result != 0)
        {
            throw NativeError.CreateException("encrypt_to_json", session);
        }

        try
        {
            return CopyBuffer(buffer);
        }
        finally
        {
            SafeFreeBuffer(ref buffer);
        }
    }

    public byte[] DecryptFromJson(string partitionId, byte[] json)
    {
        using SafeSessionHandle session = GetSession(partitionId);
        AsherahBuffer buffer = default;
        int result = NativeMethods.asherah_decrypt_from_json(
            session,
            json,
            (UIntPtr)json.Length,
            ref buffer);
        if (result != 0)
        {
            throw NativeError.CreateException("decrypt_from_json", session);
        }

        try
        {
            return CopyBuffer(buffer);
        }
        finally
        {
            SafeFreeBuffer(ref buffer);
        }
    }

    public void Dispose()
    {
        _factory.Dispose();
    }

    private SafeSessionHandle GetSession(string partitionId)
    {
        using var partition = new Utf8String(partitionId);
        IntPtr sessionPtr = NativeMethods.asherah_factory_get_session(_factory, partition.Pointer);
        if (sessionPtr == IntPtr.Zero)
        {
            throw NativeError.CreateException("factory_get_session");
        }
        try
        {
            return new SafeSessionHandle(sessionPtr);
        }
        catch
        {
            NativeMethods.asherah_session_free(sessionPtr);
            throw;
        }
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

    private static void SafeFreeBuffer(ref AsherahBuffer buffer)
    {
        try
        {
            NativeMethods.asherah_buffer_free(ref buffer);
        }
        catch
        {
            buffer.data = IntPtr.Zero;
            buffer.len = UIntPtr.Zero;
            throw;
        }
        buffer.data = IntPtr.Zero;
        buffer.len = UIntPtr.Zero;
    }
}

internal static class NativeError
{
    public static AppEncryptionException CreateException(string operation, SafeSessionHandle? session = null)
    {
        string message = GetLastErrorMessage(session);
        int? code = GetLastErrorCode(session);
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

    private static string GetLastErrorMessage(SafeSessionHandle? session)
    {
        IntPtr ptr = session is not null
            ? NativeMethods.asherah_session_last_error_message(session)
            : NativeMethods.asherah_last_error_message();
        if (ptr == IntPtr.Zero && session is not null)
        {
            ptr = NativeMethods.asherah_last_error_message();
        }
        if (ptr == IntPtr.Zero)
        {
            return string.Empty;
        }

        return Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
    }

    private static int? GetLastErrorCode(SafeSessionHandle? session)
    {
        int code = session is not null
            ? NativeMethods.asherah_session_last_error_code(session)
            : NativeMethods.asherah_last_error_code();
        if (code == 0 && session is not null)
        {
            code = NativeMethods.asherah_last_error_code();
        }
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
    internal static extern IntPtr asherah_factory_get_session(SafeFactoryHandle factory, IntPtr partitionId);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void asherah_session_free(IntPtr session);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int asherah_encrypt_to_json(SafeSessionHandle session, byte[] data, UIntPtr length, ref AsherahBuffer buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int asherah_decrypt_from_json(SafeSessionHandle session, byte[] json, UIntPtr length, ref AsherahBuffer buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void asherah_buffer_free(ref AsherahBuffer buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr asherah_last_error_message();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int asherah_last_error_code();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr asherah_session_last_error_message(SafeSessionHandle session);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int asherah_session_last_error_code(SafeSessionHandle session);
}
