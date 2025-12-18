using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using GoDaddy.Asherah.Crypto.Exceptions;

namespace GoDaddy.Asherah.Internal;

internal static partial class NativeLibraryLoader
{
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

        string? explicitPath = GetExplicitPath();
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            string candidate = BuildLibraryPath(explicitPath!);
            if (!File.Exists(candidate))
            {
                throw new AppEncryptionException($"Asherah native library not found at {candidate}");
            }

            return LoadOrThrow(candidate);
        }

        string? runtimePath = TryGetRuntimeNativePath(assembly);
        if (!string.IsNullOrWhiteSpace(runtimePath))
        {
            return LoadOrThrow(runtimePath!);
        }

        return NativeLibrary.Load(libraryName, assembly, searchPath);
    }

    private static IntPtr LoadOrThrow(string path)
    {
        try
        {
            return NativeLibrary.Load(path);
        }
        catch (Exception ex)
        {
            throw new AppEncryptionException($"Failed to load Asherah native library from {path}: {ex.Message}", ex);
        }
    }

    private static string? GetExplicitPath()
    {
        string? fromProperty = AppContext.GetData("asherah.dotnet.nativeLibraryPath") as string;
        if (!string.IsNullOrWhiteSpace(fromProperty))
        {
            return fromProperty;
        }

        string? fromEnv = Environment.GetEnvironmentVariable("ASHERAH_DOTNET_NATIVE");
        if (!string.IsNullOrWhiteSpace(fromEnv))
        {
            return fromEnv;
        }

        return null;
    }

    private static string BuildLibraryPath(string root)
    {
        string candidate = root;
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
            return $"{LibraryName}.dll";
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return $"lib{LibraryName}.dylib";
        }

        return $"lib{LibraryName}.so";
    }

    private static string? TryGetRuntimeNativePath(Assembly assembly)
    {
        string? rid = GetRuntimeIdentifier();
        if (string.IsNullOrWhiteSpace(rid))
        {
            return null;
        }

        string? baseDir = Path.GetDirectoryName(assembly.Location);
        if (string.IsNullOrWhiteSpace(baseDir))
        {
            baseDir = AppContext.BaseDirectory;
        }

        string candidate = Path.Combine(baseDir!, "runtimes", rid, "native", GetPlatformLibraryName());
        return File.Exists(candidate) ? candidate : null;
    }

    private static string? GetRuntimeIdentifier()
    {
        string? arch = RuntimeInformation.OSArchitecture switch
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

    private static readonly string LibraryName = GetLibraryName();

    private static partial string GetLibraryName();
}
