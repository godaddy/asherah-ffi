using System;

namespace GoDaddy.Asherah;

/// <summary>
/// Strongly-typed HashiCorp Vault authentication method selector for
/// <see cref="AsherahConfig.Builder.WithVaultAuthMethod(VaultAuthMethod?)"/>.
///
/// Applies only when <see cref="AsherahConfig.Builder.WithKms(KmsKind)"/> is
/// <see cref="KmsKind.Vault"/>. If <c>VAULT_TOKEN</c> is set in the
/// environment, token auth is used and this setting is unused.
/// </summary>
public enum VaultAuthMethod
{
    /// <summary>Kubernetes service-account JWT auth. Wire value: <c>"kubernetes"</c>. Requires <see cref="AsherahConfig.Builder.WithVaultAuthRole(string?)"/>; the JWT path defaults to the standard service-account mount but is overridable via <see cref="AsherahConfig.Builder.WithVaultK8sTokenPath(string?)"/>.</summary>
    Kubernetes,
    /// <summary>AppRole auth. Wire value: <c>"approle"</c>. Requires <see cref="AsherahConfig.Builder.WithVaultApproleRoleId(string?)"/> (and optionally <see cref="AsherahConfig.Builder.WithVaultApproleSecretId(string?)"/>).</summary>
    AppRole,
    /// <summary>TLS client certificate auth. Wire value: <c>"cert"</c>. Requires <see cref="AsherahConfig.Builder.WithVaultClientCert(string?)"/> and <see cref="AsherahConfig.Builder.WithVaultClientKey(string?)"/>.</summary>
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
