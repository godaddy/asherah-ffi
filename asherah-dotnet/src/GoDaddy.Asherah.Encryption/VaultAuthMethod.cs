using System;

namespace GoDaddy.Asherah;

/// <summary>
/// Strongly-typed HashiCorp Vault authentication method selector for
/// <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithVaultAuthMethod(System.Nullable{VaultAuthMethod})"/>.
///
/// Applies only when <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithKms(KmsKind)"/> is
/// <see cref="KmsKind.Vault"/>. If <c>VAULT_TOKEN</c> is set in the
/// environment, token auth is used and this setting is unused.
/// </summary>
public enum VaultAuthMethod
{
    /// <summary>Kubernetes service-account JWT auth. Wire value: <c>"kubernetes"</c>. Requires <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithVaultAuthRole(System.String)"/>; the JWT path defaults to the standard service-account mount but is overridable via <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithVaultK8sTokenPath(System.String)"/>.</summary>
    Kubernetes,
    /// <summary>AppRole auth. Wire value: <c>"approle"</c>. Requires <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithVaultApproleRoleId(System.String)"/> (and optionally <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithVaultApproleSecretId(System.String)"/>).</summary>
    AppRole,
    /// <summary>TLS client certificate auth. Wire value: <c>"cert"</c>. Requires <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithVaultClientCert(System.String)"/> and <see cref="GoDaddy.Asherah.Encryption.AsherahConfig.Builder.WithVaultClientKey(System.String)"/>.</summary>
    Cert,
}

internal static class VaultAuthMethodExtensions
{
    internal static string ToWireString(this VaultAuthMethod method) => method switch
    {
        VaultAuthMethod.Kubernetes => "kubernetes",
        VaultAuthMethod.AppRole => "approle",
        VaultAuthMethod.Cert => "cert",
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, "Unknown VaultAuthMethod"),
    };
}
