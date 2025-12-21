using System;
using System.Data.Common;
using System.IO;
using GoDaddy.Asherah.AppEncryption;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.Crypto;

namespace AsherahDotNet.SharedTests;

public static class TestHelpers
{
    private const string DefaultServiceId = "svc";
    private const string DefaultProductId = "prod";
    private static readonly string StaticMasterKey = new string('a', 32);

    public static void EnsureNativeLibraryConfigured()
    {
        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASHERAH_DOTNET_NATIVE")))
        {
            return;
        }

        if (HasRuntimeNativeLibrary())
        {
            return;
        }

        var root = LocateRepoRoot();
        var nativeRoot = Path.Combine(root, "target", "debug");
        Environment.SetEnvironmentVariable("ASHERAH_DOTNET_NATIVE", nativeRoot);
    }

    public static SessionFactory CreateSessionFactory(
        bool enableSessionCache = false,
        long? sessionCacheMaxSize = null,
        long? sessionCacheExpireMillis = null)
    {
        IMetastore<Newtonsoft.Json.Linq.JObject> metastore = CreateMetastore();

        var policyBuilder = BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(90)
            .WithRevokeCheckMinutes(60);

        if (enableSessionCache)
        {
            policyBuilder = policyBuilder.WithCanCacheSessions(true);
            if (sessionCacheMaxSize.HasValue)
            {
                policyBuilder = policyBuilder.WithSessionCacheMaxSize(sessionCacheMaxSize.Value);
            }
            if (sessionCacheExpireMillis.HasValue)
            {
                policyBuilder = policyBuilder.WithSessionCacheExpireMillis(sessionCacheExpireMillis.Value);
            }
        }

        var cryptoPolicy = policyBuilder.Build();
        var builder = SessionFactory.NewBuilder(DefaultProductId, DefaultServiceId)
            .WithMetastore(metastore)
            .WithCryptoPolicy(cryptoPolicy)
            .WithStaticKeyManagementService(StaticMasterKey);

        return builder.Build();
    }

    private static IMetastore<Newtonsoft.Json.Linq.JObject> CreateMetastore()
    {
        var conn = Environment.GetEnvironmentVariable("MSSQL_URL");
        if (string.IsNullOrWhiteSpace(conn))
        {
            return new InMemoryMetastoreImpl<Newtonsoft.Json.Linq.JObject>();
        }

        return AdoMetastoreImpl.NewBuilder(new DummyDbProviderFactory(), conn).Build();
    }

    private static string LocateRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Cargo.toml")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Unable to locate repository root");
    }

    private static bool HasRuntimeNativeLibrary()
    {
        string? rid = GetRuntimeIdentifier();
        if (string.IsNullOrWhiteSpace(rid))
        {
            return false;
        }

        string baseDir = AppContext.BaseDirectory;
        string ffiPath = Path.Combine(baseDir, "runtimes", rid, "native", GetPlatformLibraryName("asherah_ffi"));
        if (File.Exists(ffiPath))
        {
            return true;
        }

        string cobhanPath = Path.Combine(baseDir, "runtimes", rid, "native", GetPlatformLibraryName("asherah_cobhan"));
        return File.Exists(cobhanPath);
    }

    private static string? GetRuntimeIdentifier()
    {
        string? arch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture switch
        {
            System.Runtime.InteropServices.Architecture.X64 => "x64",
            System.Runtime.InteropServices.Architecture.Arm64 => "arm64",
            _ => null
        };

        if (arch is null)
        {
            return null;
        }

        if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
        {
            return $"win-{arch}";
        }

        if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.OSX))
        {
            return $"osx-{arch}";
        }

        if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Linux))
        {
            return $"linux-{arch}";
        }

        return null;
    }

    private static string GetPlatformLibraryName(string baseName)
    {
        if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
        {
            return $"{baseName}.dll";
        }

        if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.OSX))
        {
            return $"lib{baseName}.dylib";
        }

        return $"lib{baseName}.so";
    }

    private sealed class DummyDbProviderFactory : DbProviderFactory
    {
    }
}
