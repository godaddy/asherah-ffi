using System;

namespace GoDaddy.Asherah;

/// <summary>
/// Strongly-typed KMS provider selector for
/// <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithKms(KmsKind)"/>.
/// Each value maps 1:1 to a wire string accepted by the native Rust core.
/// </summary>
public enum KmsKind
{
    /// <summary>Static master key from <c>STATIC_MASTER_KEY_HEX</c>. Wire value: <c>"static"</c>. Testing only — production must use AWS KMS.</summary>
    Static,
    /// <summary>AWS Key Management Service. Wire value: <c>"aws"</c>. Configure via <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithKmsKeyId(System.String)"/> and <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithRegionMap(System.Collections.Generic.IReadOnlyDictionary{System.String,System.String})"/>.</summary>
    Aws,
    /// <summary>AWS Secrets Manager. Wire value: <c>"secrets-manager"</c>.</summary>
    SecretsManager,
    /// <summary>HashiCorp Vault Transit. Wire value: <c>"vault"</c>.</summary>
    Vault,
}

internal static class KmsKindExtensions
{
    internal static string ToWireString(this KmsKind kind) => kind switch
    {
        KmsKind.Static => "static",
        KmsKind.Aws => "aws",
        KmsKind.SecretsManager => "secrets-manager",
        KmsKind.Vault => "vault",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown KmsKind"),
    };
}
