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
    internal static extern unsafe int asherah_encrypt_to_json(IntPtr session, byte* data, UIntPtr length, ref AsherahBuffer buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe int asherah_decrypt_from_json(IntPtr session, byte* json, UIntPtr length, ref AsherahBuffer buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe IntPtr asherah_factory_get_session(IntPtr factory, byte* partitionId);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void asherah_buffer_free(ref AsherahBuffer buffer);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr asherah_last_error_message();

    // Async FFI — callback-based
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe int asherah_encrypt_to_json_async(
        IntPtr session, byte* data, UIntPtr length,
        delegate* unmanaged[Cdecl]<IntPtr, IntPtr, UIntPtr, IntPtr, void> callback,
        IntPtr userData);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe int asherah_decrypt_from_json_async(
        IntPtr session, byte* json, UIntPtr length,
        delegate* unmanaged[Cdecl]<IntPtr, IntPtr, UIntPtr, IntPtr, void> callback,
        IntPtr userData);

    // Log / metrics hooks (C ABI exposed by asherah-ffi/src/hooks.rs).
    // Callback signatures:
    //   log:     (user_data, level: i32, target: *const c_char, message: *const c_char)
    //   metrics: (user_data, event_type: i32, duration_ns: u64, name: *const c_char)
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe int asherah_set_log_hook(
        delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr, IntPtr, void> callback,
        IntPtr userData);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int asherah_clear_log_hook();

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern unsafe int asherah_set_metrics_hook(
        delegate* unmanaged[Cdecl]<IntPtr, int, ulong, IntPtr, void> callback,
        IntPtr userData);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int asherah_clear_metrics_hook();
}

[StructLayout(LayoutKind.Sequential)]
internal struct AsherahBuffer
{
    public IntPtr data;
    public UIntPtr len;
}
