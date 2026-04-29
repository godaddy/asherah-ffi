using GoDaddy.Asherah.Encryption;

namespace GoDaddy.Asherah.AppEncryption.Kms;

/// <summary>KMS interface. In the FFI binding, KMS is handled by the native Rust layer.</summary>
public interface IKeyManagementService
{
    void ApplyConfig(AsherahConfig.Builder builder);
}

/// <summary>Static key management service. Maps to kms="static".</summary>
public class StaticKeyManagementServiceImpl : IKeyManagementService
{
    private readonly string _masterKeyHex;

    public StaticKeyManagementServiceImpl(string key)
    {
        _masterKeyHex = Convert.ToHexString(System.Text.Encoding.UTF8.GetBytes(key)).ToLowerInvariant();
    }

    public void ApplyConfig(AsherahConfig.Builder builder)
    {
        builder.WithKms("static");
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

    public void ApplyConfig(AsherahConfig.Builder builder)
    {
        // Cast disambiguates between the IDictionary and IReadOnlyDictionary
        // WithRegionMap overloads — Dictionary<,> implements both.
        builder.WithKms("aws")
               .WithRegionMap((IDictionary<string, string>)_regionToArnMap)
               .WithPreferredRegion(_preferredRegion);
    }

    public static Builder NewBuilder(Dictionary<string, string> regionToArnMap, string preferredRegion)
        => new(regionToArnMap, preferredRegion);

    public class Builder
    {
        internal Dictionary<string, string> RegionToArnMap { get; }
        internal string PreferredRegion { get; }

        internal Builder(Dictionary<string, string> regionToArnMap, string preferredRegion)
        {
            RegionToArnMap = regionToArnMap ?? throw new ArgumentNullException(nameof(regionToArnMap));
            PreferredRegion = preferredRegion ?? throw new ArgumentNullException(nameof(preferredRegion));
        }

        public AwsKeyManagementServiceImpl Build() => new(this);
    }
}
