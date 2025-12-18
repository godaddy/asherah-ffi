using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace GoDaddy.Asherah.Internal;

[StructLayout(LayoutKind.Sequential)]
internal struct AsherahBuffer
{
    public IntPtr data;
    public UIntPtr len;
}

internal sealed class SafeFactoryHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeFactoryHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

    protected override bool ReleaseHandle()
    {
        if (!IsInvalid)
        {
            NativeMethods.asherah_factory_free(handle);
        }
        return true;
    }
}

internal sealed class SafeSessionHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeSessionHandle(IntPtr handle)
        : base(ownsHandle: true)
    {
        SetHandle(handle);
    }

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
        IntPtr allocated = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, allocated, bytes.Length);
            _pointer = allocated;
        }
        catch
        {
            Marshal.FreeHGlobal(allocated);
            throw;
        }
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
