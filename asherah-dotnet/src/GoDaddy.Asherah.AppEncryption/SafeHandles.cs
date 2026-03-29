using System;
using System.Runtime.InteropServices;

namespace GoDaddy.Asherah;

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
