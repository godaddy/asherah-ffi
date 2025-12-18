using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GoDaddy.Asherah.Internal;

internal sealed class ConfigOptions
{
    public string ServiceName { get; set; } = string.Empty;
    public string ProductId { get; set; } = string.Empty;
    public long? ExpireAfter { get; set; }
    public long? CheckInterval { get; set; }
    public string Metastore { get; set; } = "memory";
    public string? ConnectionString { get; set; }
    public string? ReplicaReadConsistency { get; set; }
    public string? DynamoDbEndpoint { get; set; }
    public string? DynamoDbRegion { get; set; }
    public string? DynamoDbTableName { get; set; }
    public int? SessionCacheMaxSize { get; set; }
    public long? SessionCacheDuration { get; set; }
    public string Kms { get; set; } = "static";
    public string? StaticMasterKeyHex { get; set; }
    public Dictionary<string, string>? RegionMap { get; set; }
    public string? PreferredRegion { get; set; }
    public bool? EnableRegionSuffix { get; set; }
    public bool? EnableSessionCaching { get; set; }
    public bool? Verbose { get; set; }

    public string ToJson()
    {
        var payload = new Dictionary<string, object?>
        {
            ["ServiceName"] = ServiceName,
            ["ProductID"] = ProductId,
            ["ExpireAfter"] = ExpireAfter,
            ["CheckInterval"] = CheckInterval,
            ["Metastore"] = Metastore,
            ["ConnectionString"] = ConnectionString,
            ["ReplicaReadConsistency"] = ReplicaReadConsistency,
            ["DynamoDBEndpoint"] = DynamoDbEndpoint,
            ["DynamoDBRegion"] = DynamoDbRegion,
            ["DynamoDBTableName"] = DynamoDbTableName,
            ["SessionCacheMaxSize"] = SessionCacheMaxSize,
            ["SessionCacheDuration"] = SessionCacheDuration,
            ["KMS"] = Kms,
            ["StaticMasterKeyHex"] = StaticMasterKeyHex,
            ["RegionMap"] = RegionMap,
            ["PreferredRegion"] = PreferredRegion,
            ["EnableRegionSuffix"] = EnableRegionSuffix,
            ["EnableSessionCaching"] = EnableSessionCaching,
            ["Verbose"] = Verbose,
        };

        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        return JsonSerializer.Serialize(payload, options);
    }
}
