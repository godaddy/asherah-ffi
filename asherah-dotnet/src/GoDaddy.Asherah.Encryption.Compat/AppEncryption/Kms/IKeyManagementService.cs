using GoDaddy.Asherah;
using GoDaddy.Asherah.Encryption;

namespace GoDaddy.Asherah.AppEncryption.Kms;

/// <summary>KMS interface. In the FFI binding, KMS is handled by the native Rust layer.</summary>
public interface IKeyManagementService
{
    /// <summary>Merges this KMS adapter into <paramref name="builder"/>.</summary>
    void ApplyConfig(AsherahConfig.Builder builder);
}

/// <summary>Static key management service. Maps to kms="static".</summary>
public class StaticKeyManagementServiceImpl : IKeyManagementService
{
    private readonly string _masterKeyHex;

    /// <summary>Initializes static KMS using <paramref name="key"/> UTF-8 bytes as the master key material (testing).</summary>
    public StaticKeyManagementServiceImpl(string key)
    {
        _masterKeyHex = Convert.ToHexString(System.Text.Encoding.UTF8.GetBytes(key)).ToLowerInvariant();
    }

    /// <inheritdoc />
    public void ApplyConfig(AsherahConfig.Builder builder)
    {
        builder.WithKms(KmsKind.Static);
        Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX", _masterKeyHex);
    }

    internal string MasterKeyHex => _masterKeyHex;
}

/// <summary>AWS KMS adapter. Maps to kms="aws".</summary>
public class AwsKeyManagementServiceImpl : IKeyManagementService
{
    private readonly Dictionary<string, string> _regionToArnMap;
    private readonly string _preferredRegion;

    private AwsKeyManagementServiceImpl(Builder builder)
    {
        _regionToArnMap = new Dictionary<string, string>(builder.RegionToArnMap);
        _preferredRegion = builder.PreferredRegion;
    }

    /// <inheritdoc />
    public void ApplyConfig(AsherahConfig.Builder builder)
    {
        builder.WithKms(KmsKind.Aws)
               .WithRegionMap(_regionToArnMap)
               .WithPreferredRegion(_preferredRegion);
    }

    /// <summary>Creates a fluent builder from region-to-key-ARN mappings.</summary>
    public static Builder NewBuilder(Dictionary<string, string> regionToArnMap, string preferredRegion)
        => new(regionToArnMap, preferredRegion);

    /// <summary>Fluent builder for <see cref="AwsKeyManagementServiceImpl"/>.</summary>
    public class Builder
    {
        internal Dictionary<string, string> RegionToArnMap { get; }
        internal string PreferredRegion { get; }

        internal Builder(Dictionary<string, string> regionToArnMap, string preferredRegion)
        {
            RegionToArnMap = regionToArnMap ?? throw new ArgumentNullException(nameof(regionToArnMap));
            PreferredRegion = preferredRegion ?? throw new ArgumentNullException(nameof(preferredRegion));
        }

        /// <summary>Builds the AWS KMS adapter for use with <see cref="SessionFactory.IKeyManagementServiceStep.WithKeyManagementService"/>.</summary>
        public AwsKeyManagementServiceImpl Build() => new(this);
    }
}
