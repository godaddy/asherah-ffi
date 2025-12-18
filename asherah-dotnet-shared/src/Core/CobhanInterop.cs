#if ASHERAH_COBHAN
using System;
using System.Runtime.InteropServices;
using System.Text;
using GoDaddy.Asherah.AppEncryption.Exceptions;
using GoDaddy.Asherah.Crypto.Exceptions;

namespace GoDaddy.Asherah.Internal;

internal sealed class CobhanCore : IAsherahCore
{
    private static bool _initialized;
    private static readonly object InitLock = new();

    public CobhanCore(ConfigOptions config)
    {
        EnsureInitialized(config);
    }

    public byte[] EncryptToJson(string partitionId, byte[] plaintext)
    {
        using var partitionBuf = CobhanBuffer.FromString(partitionId);
        using var dataBuf = CobhanBuffer.FromBytes(plaintext);
        int capacity = EstimateCapacity(plaintext.Length, Encoding.UTF8.GetByteCount(partitionId));
        using var outputBuf = CobhanBuffer.Allocate(capacity);

        int result = NativeMethods.EncryptToJson(partitionBuf.Pointer, dataBuf.Pointer, outputBuf.Pointer);
        if (result != 0)
        {
            throw CobhanError.CreateException("EncryptToJson", result);
        }

        return outputBuf.ReadBytes();
    }

    public byte[] DecryptFromJson(string partitionId, byte[] json)
    {
        using var partitionBuf = CobhanBuffer.FromString(partitionId);
        using var jsonBuf = CobhanBuffer.FromBytes(json);
        int capacity = EstimateCapacity(json.Length, Encoding.UTF8.GetByteCount(partitionId));
        using var outputBuf = CobhanBuffer.Allocate(capacity);

        int result = NativeMethods.DecryptFromJson(partitionBuf.Pointer, jsonBuf.Pointer, outputBuf.Pointer);
        if (result != 0)
        {
            throw CobhanError.CreateException("DecryptFromJson", result);
        }

        return outputBuf.ReadBytes();
    }

    public void Dispose()
    {
    }

    private static void EnsureInitialized(ConfigOptions config)
    {
        lock (InitLock)
        {
            if (_initialized)
            {
                return;
            }

            using var jsonBuf = CobhanBuffer.FromString(config.ToJson());
            int result = NativeMethods.SetupJson(jsonBuf.Pointer);
            if (result != 0 && result != CobhanError.AlreadyInitialized)
            {
                throw CobhanError.CreateException("SetupJson", result);
            }

            _initialized = true;
        }
    }

    private static int EstimateCapacity(int dataLen, int partitionLen)
    {
        int estimated = NativeMethods.EstimateBuffer(dataLen, partitionLen);
        if (estimated <= 0)
        {
            estimated = Math.Max(256, dataLen + 256);
        }
        return estimated;
    }
}

internal static class CobhanError
{
    public const int AlreadyInitialized = -100;

    public static AppEncryptionException CreateException(string operation, int code)
    {
        string message = code switch
        {
            0 => "success",
            -1 => "null pointer",
            -2 => "buffer too large",
            -3 => "buffer too small",
            -4 => "copy failed",
            -5 => "json decode failed",
            -6 => "json encode failed",
            -100 => "already initialized",
            -101 => "bad config",
            -102 => "not initialized",
            -103 => "encrypt failed",
            -104 => "decrypt failed",
            _ => "unknown error",
        };

        string full = $"Cobhan error during {operation}: {message} (code {code})";
        return new AppEncryptionException(full);
    }
}

internal static class NativeMethods
{
    private const string LibraryName = "asherah_cobhan";

    static NativeMethods()
    {
        NativeLibraryLoader.EnsureRegistered();
    }

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int SetupJson(IntPtr configJson);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int EstimateBuffer(int dataLen, int partitionLen);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int EncryptToJson(IntPtr partitionIdPtr, IntPtr dataPtr, IntPtr jsonPtr);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int DecryptFromJson(IntPtr partitionIdPtr, IntPtr jsonPtr, IntPtr dataPtr);
}

internal sealed class CobhanBuffer : IDisposable
{
    private const int HeaderSize = 8;
    private IntPtr _ptr;
    private readonly int _capacity;

    private CobhanBuffer(IntPtr ptr, int capacity)
    {
        _ptr = ptr;
        _capacity = capacity;
    }

    public IntPtr Pointer => _ptr;

    public static CobhanBuffer FromBytes(byte[] data)
    {
        int capacity = data.Length;
        IntPtr ptr = Marshal.AllocHGlobal(HeaderSize + capacity);
        WriteHeader(ptr, data.Length, capacity);
        if (data.Length > 0)
        {
            Marshal.Copy(data, 0, IntPtr.Add(ptr, HeaderSize), data.Length);
        }
        return new CobhanBuffer(ptr, capacity);
    }

    public static CobhanBuffer FromString(string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        return FromBytes(bytes);
    }

    public static CobhanBuffer Allocate(int capacity)
    {
        IntPtr ptr = Marshal.AllocHGlobal(HeaderSize + capacity);
        WriteHeader(ptr, 0, capacity);
        return new CobhanBuffer(ptr, capacity);
    }

    public byte[] ReadBytes()
    {
        int length = ReadLength(_ptr);
        if (length <= 0)
        {
            return Array.Empty<byte>();
        }
        byte[] result = new byte[length];
        Marshal.Copy(IntPtr.Add(_ptr, HeaderSize), result, 0, length);
        return result;
    }

    public void Dispose()
    {
        if (_ptr != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(_ptr);
            _ptr = IntPtr.Zero;
        }
    }

    private static int ReadLength(IntPtr ptr)
    {
        return Marshal.ReadInt32(ptr, 0);
    }

    private static void WriteHeader(IntPtr ptr, int length, int capacity)
    {
        Marshal.WriteInt32(ptr, 0, length);
        Marshal.WriteInt32(ptr, 4, capacity);
    }
}
#endif
