using System;
using System.Runtime.InteropServices;
using System.Text;

namespace GoDaddy.Asherah;

internal sealed class Utf8String : IDisposable
{
    private IntPtr _pointer;

    public Utf8String(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value + "\0");
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
