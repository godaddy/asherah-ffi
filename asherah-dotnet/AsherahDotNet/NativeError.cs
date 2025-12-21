using System;
using System.Runtime.InteropServices;

namespace GoDaddy.Asherah;

internal static class NativeError
{
    internal static AsherahException Create(string context)
    {
        var ptr = NativeMethods.asherah_last_error_message();
        var message = ptr != IntPtr.Zero ? Marshal.PtrToStringAnsi(ptr) : null;
        var code = NativeMethods.asherah_last_error_code();
        var suffix = string.IsNullOrWhiteSpace(message) ? "unknown error" : message;
        return new AsherahException($"{context}: {suffix}", code == 0 ? null : code);
    }

    internal static void ThrowIfNonZero(int status, string context)
    {
        if (status != 0)
        {
            throw Create(context);
        }
    }
}
