using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GoDaddy.Asherah;

public sealed class AsherahConfig
{
    public string ServiceName { get; }
    public string ProductId { get; }
    public long? ExpireAfter { get; }
    public long? CheckInterval { get; }
    public string Metastore { get; }
    public string? ConnectionString { get; }
    public string? ReplicaReadConsistency { get; }
    public string? DynamoDbEndpoint { get; }
    public string? DynamoDbRegion { get; }
    public string? DynamoDbTableName { get; }
    public int? SessionCacheMaxSize { get; }
    public long? SessionCacheDuration { get; }
    public string Kms { get; }
    public string? StaticMasterKeyHex { get; }
    public IReadOnlyDictionary<string, string>? RegionMap { get; }
    public string? PreferredRegion { get; }
    public bool? EnableRegionSuffix { get; }
    public bool? EnableSessionCaching { get; }
    public bool? Verbose { get; }

    private AsherahConfig(Builder builder)
    {
        ServiceName = builder.ServiceName;
        ProductId = builder.ProductId;
        ExpireAfter = builder.ExpireAfter;
        CheckInterval = builder.CheckInterval;
        Metastore = builder.Metastore;
        ConnectionString = builder.ConnectionString;
        ReplicaReadConsistency = builder.ReplicaReadConsistency;
        DynamoDbEndpoint = builder.DynamoDbEndpoint;
        DynamoDbRegion = builder.DynamoDbRegion;
        DynamoDbTableName = builder.DynamoDbTableName;
        SessionCacheMaxSize = builder.SessionCacheMaxSize;
        SessionCacheDuration = builder.SessionCacheDuration;
        Kms = builder.Kms;
        StaticMasterKeyHex = builder.StaticMasterKeyHex;
        RegionMap = builder.RegionMap == null
            ? null
            : new Dictionary<string, string>(builder.RegionMap);
        PreferredRegion = builder.PreferredRegion;
        EnableRegionSuffix = builder.EnableRegionSuffix;
        EnableSessionCaching = builder.EnableSessionCaching;
        Verbose = builder.Verbose;
    }

    internal bool SessionCachingEnabled => EnableSessionCaching.GetValueOrDefault(true);

    internal string ToJson()
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

    public static Builder CreateBuilder() => new();

    public sealed class Builder
    {
        public string ServiceName { get; private set; } = null!;
        public string ProductId { get; private set; } = null!;
        public long? ExpireAfter { get; private set; }
        public long? CheckInterval { get; private set; }
        public string Metastore { get; private set; } = null!;
        public string? ConnectionString { get; private set; }
        public string? ReplicaReadConsistency { get; private set; }
        public string? DynamoDbEndpoint { get; private set; }
        public string? DynamoDbRegion { get; private set; }
        public string? DynamoDbTableName { get; private set; }
        public int? SessionCacheMaxSize { get; private set; }
        public long? SessionCacheDuration { get; private set; }
        public string Kms { get; private set; } = "static";
        public string? StaticMasterKeyHex { get; private set; }
        public IDictionary<string, string>? RegionMap { get; private set; }
        public string? PreferredRegion { get; private set; }
        public bool? EnableRegionSuffix { get; private set; }
        public bool? EnableSessionCaching { get; private set; } = true;
        public bool? Verbose { get; private set; } = false;

        internal Builder() {}

        public Builder WithServiceName(string value)
        {
            ServiceName = value;
            return this;
        }

        public Builder WithProductId(string value)
        {
            ProductId = value;
            return this;
        }

        public Builder WithExpireAfter(long? seconds)
        {
            ExpireAfter = seconds;
            return this;
        }

        public Builder WithCheckInterval(long? seconds)
        {
            CheckInterval = seconds;
            return this;
        }

        public Builder WithMetastore(string value)
        {
            Metastore = value;
            return this;
        }

        public Builder WithConnectionString(string? value)
        {
            ConnectionString = value;
            return this;
        }

        public Builder WithReplicaReadConsistency(string? value)
        {
            ReplicaReadConsistency = value;
            return this;
        }

        public Builder WithDynamoDbEndpoint(string? value)
        {
            DynamoDbEndpoint = value;
            return this;
        }

        public Builder WithDynamoDbRegion(string? value)
        {
            DynamoDbRegion = value;
            return this;
        }

        public Builder WithDynamoDbTableName(string? value)
        {
            DynamoDbTableName = value;
            return this;
        }

        public Builder WithSessionCacheMaxSize(int? value)
        {
            SessionCacheMaxSize = value;
            return this;
        }

        public Builder WithSessionCacheDuration(long? value)
        {
            SessionCacheDuration = value;
            return this;
        }

        public Builder WithKms(string value)
        {
            Kms = value;
            return this;
        }

        public Builder WithStaticMasterKey(string value)
        {
            if (value is null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            var bytes = System.Text.Encoding.UTF8.GetBytes(value);
            if (bytes.Length != 32)
            {
                throw new InvalidOperationException("Static master key must be 32 bytes when UTF-8 encoded");
            }
            StaticMasterKeyHex = BytesToHex(bytes);
            Kms = "static";
            return this;
        }

        public Builder WithRegionMap(IDictionary<string, string>? value)
        {
            RegionMap = value == null ? null : new Dictionary<string, string>(value);
            return this;
        }

        public Builder WithPreferredRegion(string? value)
        {
            PreferredRegion = value;
            return this;
        }

        public Builder WithEnableRegionSuffix(bool? value)
        {
            EnableRegionSuffix = value;
            return this;
        }

        public Builder WithEnableSessionCaching(bool? value)
        {
            EnableSessionCaching = value;
            return this;
        }

        public Builder WithVerbose(bool? value)
        {
            Verbose = value;
            return this;
        }

        public AsherahConfig Build()
        {
            if (ServiceName is null)
            {
                throw new InvalidOperationException("ServiceName is required");
            }
            if (ProductId is null)
            {
                throw new InvalidOperationException("ProductId is required");
            }
            if (Metastore is null)
            {
                throw new InvalidOperationException("Metastore is required");
            }
            if (string.Equals(Kms, "static", StringComparison.OrdinalIgnoreCase)
                && string.IsNullOrWhiteSpace(StaticMasterKeyHex)
                && string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("STATIC_MASTER_KEY_HEX")))
            {
                throw new InvalidOperationException("Static KMS requires WithStaticMasterKey or STATIC_MASTER_KEY_HEX");
            }
            return new AsherahConfig(this);
        }

        private static string BytesToHex(byte[] bytes)
        {
            var chars = new char[bytes.Length * 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                var b = bytes[i];
                var hi = b >> 4;
                var lo = b & 0xF;
                chars[i * 2] = (char)(hi < 10 ? '0' + hi : 'a' + (hi - 10));
                chars[i * 2 + 1] = (char)(lo < 10 ? '0' + lo : 'a' + (lo - 10));
            }
            return new string(chars);
        }
    }
}
