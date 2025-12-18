using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace GoDaddy.Asherah;

internal static class NativeLibraryLoader
{
    private const string LibraryName = "asherah_ffi";
    private static bool _registered;

    internal static void EnsureRegistered()
    {
        if (_registered)
        {
            return;
        }

        NativeLibrary.SetDllImportResolver(typeof(NativeLibraryLoader).Assembly, Resolve);
        _registered = true;
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (!string.Equals(libraryName, LibraryName, StringComparison.Ordinal))
        {
            return IntPtr.Zero;
        }

        var explicitPath = GetExplicitPath();
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            var candidate = BuildLibraryPath(explicitPath!);
            if (!File.Exists(candidate))
            {
                throw new AsherahException($"Asherah native library not found at {candidate}");
            }

            try
            {
                return NativeLibrary.Load(candidate);
            }
            catch (Exception ex)
            {
                throw new AsherahException($"Failed to load Asherah native library from {candidate}: {ex.Message}");
            }
        }

        var runtimePath = TryGetRuntimeNativePath(assembly);
        if (!string.IsNullOrWhiteSpace(runtimePath))
        {
            try
            {
                return NativeLibrary.Load(runtimePath!);
            }
            catch (Exception ex)
            {
                throw new AsherahException($"Failed to load Asherah native library from {runtimePath}: {ex.Message}");
            }
        }

        return NativeLibrary.Load(libraryName, assembly, searchPath);
    }

    private static string? GetExplicitPath()
    {
        var fromProperty = AppContext.GetData("asherah.dotnet.nativeLibraryPath") as string;
        if (!string.IsNullOrWhiteSpace(fromProperty))
        {
            return fromProperty;
        }

        var fromEnv = Environment.GetEnvironmentVariable("ASHERAH_DOTNET_NATIVE");
        if (!string.IsNullOrWhiteSpace(fromEnv))
        {
            return fromEnv;
        }

        return null;
    }

    private static string BuildLibraryPath(string root)
    {
        var candidate = root;
        if (Directory.Exists(root))
        {
            candidate = Path.Combine(root, GetPlatformLibraryName());
        }

        return Path.GetFullPath(candidate);
    }

    private static string GetPlatformLibraryName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return "asherah_ffi.dll";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return "libasherah_ffi.dylib";
        }

        return "libasherah_ffi.so";
    }

    private static string? TryGetRuntimeNativePath(Assembly assembly)
    {
        var rid = GetRuntimeIdentifier();
        if (string.IsNullOrWhiteSpace(rid))
        {
            return null;
        }

        var baseDir = Path.GetDirectoryName(assembly.Location);
        if (string.IsNullOrWhiteSpace(baseDir))
        {
            baseDir = AppContext.BaseDirectory;
        }

        var candidate = Path.Combine(baseDir!, "runtimes", rid, "native", GetPlatformLibraryName());
        return File.Exists(candidate) ? candidate : null;
    }

    private static string? GetRuntimeIdentifier()
    {
        var arch = RuntimeInformation.OSArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => null
        };

        if (arch is null)
        {
            return null;
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return $"win-{arch}";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return $"osx-{arch}";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return $"linux-{arch}";
        }

        return null;
    }
}
