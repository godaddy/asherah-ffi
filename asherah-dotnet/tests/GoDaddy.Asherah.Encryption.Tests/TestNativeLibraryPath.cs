using System.IO;

namespace GoDaddy.Asherah.Encryption.Tests;

/// <summary>
/// Dev convenience: points <c>ASHERAH_DOTNET_NATIVE</c> at <c>{repo}/target/debug</c>
/// when unset, so FFI tests load the library from a normal <c>cargo build -p asherah-ffi</c>.
/// </summary>
internal static class TestNativeLibraryPath
{
    internal static void EnsureConfigured()
    {
        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASHERAH_DOTNET_NATIVE")))
        {
            return;
        }

        var root = LocateRepoRoot();
        Environment.SetEnvironmentVariable(
            "ASHERAH_DOTNET_NATIVE",
            Path.Join(root, "target", "debug"));
    }

    internal static string LocateRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Join(dir.FullName, "Cargo.toml")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }

        throw new InvalidOperationException("Unable to locate repository root");
    }
}
