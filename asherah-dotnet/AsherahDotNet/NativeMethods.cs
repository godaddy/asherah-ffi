using System;
using System.Runtime.InteropServices;

namespace GoDaddy.Asherah;

internal static class NativeMethods
{
    private const string LibraryName = "asherah_ffi";

    static NativeMethods()
    {
        NativeLibraryLoader.EnsureRegistered();
    }

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr asherah_factory_new_from_env();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr asherah_factory_new_with_config(IntPtr configJson);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int asherah_apply_config_json(IntPtr configJson);

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
}

[StructLayout(LayoutKind.Sequential)]
internal struct AsherahBuffer
{
    public IntPtr data;
    public UIntPtr len;
}
