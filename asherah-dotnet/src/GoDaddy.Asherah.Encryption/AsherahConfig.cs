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
    public string? DynamoDbSigningRegion { get; }
    public string? DynamoDbTableName { get; }
    public int? SessionCacheMaxSize { get; }
    public long? SessionCacheDuration { get; }
    public string Kms { get; }
    public IReadOnlyDictionary<string, string>? RegionMap { get; }
    public string? PreferredRegion { get; }
    public bool? EnableRegionSuffix { get; }
    public bool? EnableSessionCaching { get; }
    public bool? Verbose { get; }
    public int? PoolMaxOpen { get; }
    public int? PoolMaxIdle { get; }
    public long? PoolMaxLifetime { get; }
    public long? PoolMaxIdleTime { get; }
    public string? KmsKeyId { get; }
    public string? SecretsManagerSecretId { get; }
    public string? VaultAddr { get; }
    public string? VaultToken { get; }
    public string? VaultAuthMethod { get; }
    public string? VaultAuthRole { get; }
    public string? VaultAuthMount { get; }
    public string? VaultApproleRoleId { get; }
    public string? VaultApproleSecretId { get; }
    public string? VaultClientCert { get; }
    public string? VaultClientKey { get; }
    public string? VaultK8sTokenPath { get; }
    public string? VaultTransitKey { get; }
    public string? VaultTransitMount { get; }

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
        DynamoDbSigningRegion = builder.DynamoDbSigningRegion;
        DynamoDbTableName = builder.DynamoDbTableName;
        SessionCacheMaxSize = builder.SessionCacheMaxSize;
        SessionCacheDuration = builder.SessionCacheDuration;
        Kms = builder.Kms;
        RegionMap = builder.RegionMap == null
            ? null
            : new Dictionary<string, string>(builder.RegionMap);
        PreferredRegion = builder.PreferredRegion;
        EnableRegionSuffix = builder.EnableRegionSuffix;
        EnableSessionCaching = builder.EnableSessionCaching;
        Verbose = builder.Verbose;
        PoolMaxOpen = builder.PoolMaxOpen;
        PoolMaxIdle = builder.PoolMaxIdle;
        PoolMaxLifetime = builder.PoolMaxLifetime;
        PoolMaxIdleTime = builder.PoolMaxIdleTime;
        KmsKeyId = builder.KmsKeyId;
        SecretsManagerSecretId = builder.SecretsManagerSecretId;
        VaultAddr = builder.VaultAddr;
        VaultToken = builder.VaultToken;
        VaultAuthMethod = builder.VaultAuthMethod;
        VaultAuthRole = builder.VaultAuthRole;
        VaultAuthMount = builder.VaultAuthMount;
        VaultApproleRoleId = builder.VaultApproleRoleId;
        VaultApproleSecretId = builder.VaultApproleSecretId;
        VaultClientCert = builder.VaultClientCert;
        VaultClientKey = builder.VaultClientKey;
        VaultK8sTokenPath = builder.VaultK8sTokenPath;
        VaultTransitKey = builder.VaultTransitKey;
        VaultTransitMount = builder.VaultTransitMount;
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
            ["DynamoDBSigningRegion"] = DynamoDbSigningRegion,
            ["DynamoDBTableName"] = DynamoDbTableName,
            ["SessionCacheMaxSize"] = SessionCacheMaxSize,
            ["SessionCacheDuration"] = SessionCacheDuration,
            ["KMS"] = Kms,
            ["RegionMap"] = RegionMap,
            ["PreferredRegion"] = PreferredRegion,
            ["EnableRegionSuffix"] = EnableRegionSuffix,
            ["EnableSessionCaching"] = EnableSessionCaching,
            ["Verbose"] = Verbose,
            ["PoolMaxOpen"] = PoolMaxOpen,
            ["PoolMaxIdle"] = PoolMaxIdle,
            ["PoolMaxLifetime"] = PoolMaxLifetime,
            ["PoolMaxIdleTime"] = PoolMaxIdleTime,
            ["KmsKeyId"] = KmsKeyId,
            ["SecretsManagerSecretId"] = SecretsManagerSecretId,
            ["VaultAddr"] = VaultAddr,
            ["VaultToken"] = VaultToken,
            ["VaultAuthMethod"] = VaultAuthMethod,
            ["VaultAuthRole"] = VaultAuthRole,
            ["VaultAuthMount"] = VaultAuthMount,
            ["VaultApproleRoleId"] = VaultApproleRoleId,
            ["VaultApproleSecretId"] = VaultApproleSecretId,
            ["VaultClientCert"] = VaultClientCert,
            ["VaultClientKey"] = VaultClientKey,
            ["VaultK8sTokenPath"] = VaultK8sTokenPath,
            ["VaultTransitKey"] = VaultTransitKey,
            ["VaultTransitMount"] = VaultTransitMount,
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
        public string? DynamoDbSigningRegion { get; private set; }
        public string? DynamoDbTableName { get; private set; }
        public int? SessionCacheMaxSize { get; private set; }
        public long? SessionCacheDuration { get; private set; }
        public string Kms { get; private set; } = "static";
        public IDictionary<string, string>? RegionMap { get; private set; }
        public string? PreferredRegion { get; private set; }
        public bool? EnableRegionSuffix { get; private set; }
        public bool? EnableSessionCaching { get; private set; } = true;
        public bool? Verbose { get; private set; } = false;
        public int? PoolMaxOpen { get; private set; }
        public int? PoolMaxIdle { get; private set; }
        public long? PoolMaxLifetime { get; private set; }
        public long? PoolMaxIdleTime { get; private set; }
        public string? KmsKeyId { get; private set; }
        public string? SecretsManagerSecretId { get; private set; }
        public string? VaultAddr { get; private set; }
        public string? VaultToken { get; private set; }
        public string? VaultAuthMethod { get; private set; }
        public string? VaultAuthRole { get; private set; }
        public string? VaultAuthMount { get; private set; }
        public string? VaultApproleRoleId { get; private set; }
        public string? VaultApproleSecretId { get; private set; }
        public string? VaultClientCert { get; private set; }
        public string? VaultClientKey { get; private set; }
        public string? VaultK8sTokenPath { get; private set; }
        public string? VaultTransitKey { get; private set; }
        public string? VaultTransitMount { get; private set; }

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

        public Builder WithDynamoDbSigningRegion(string? value)
        {
            DynamoDbSigningRegion = value;
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

        public Builder WithPoolMaxOpen(int? value)
        {
            PoolMaxOpen = value;
            return this;
        }

        public Builder WithPoolMaxIdle(int? value)
        {
            PoolMaxIdle = value;
            return this;
        }

        public Builder WithPoolMaxLifetime(long? seconds)
        {
            PoolMaxLifetime = seconds;
            return this;
        }

        public Builder WithPoolMaxIdleTime(long? seconds)
        {
            PoolMaxIdleTime = seconds;
            return this;
        }

        public Builder WithKmsKeyId(string? value)
        {
            KmsKeyId = value;
            return this;
        }

        public Builder WithSecretsManagerSecretId(string? value)
        {
            SecretsManagerSecretId = value;
            return this;
        }

        public Builder WithVaultAddr(string? value)
        {
            VaultAddr = value;
            return this;
        }

        public Builder WithVaultToken(string? value)
        {
            VaultToken = value;
            return this;
        }

        public Builder WithVaultAuthMethod(string? value)
        {
            VaultAuthMethod = value;
            return this;
        }

        public Builder WithVaultAuthRole(string? value)
        {
            VaultAuthRole = value;
            return this;
        }

        public Builder WithVaultAuthMount(string? value)
        {
            VaultAuthMount = value;
            return this;
        }

        public Builder WithVaultApproleRoleId(string? value)
        {
            VaultApproleRoleId = value;
            return this;
        }

        public Builder WithVaultApproleSecretId(string? value)
        {
            VaultApproleSecretId = value;
            return this;
        }

        public Builder WithVaultClientCert(string? value)
        {
            VaultClientCert = value;
            return this;
        }

        public Builder WithVaultClientKey(string? value)
        {
            VaultClientKey = value;
            return this;
        }

        public Builder WithVaultK8sTokenPath(string? value)
        {
            VaultK8sTokenPath = value;
            return this;
        }

        public Builder WithVaultTransitKey(string? value)
        {
            VaultTransitKey = value;
            return this;
        }

        public Builder WithVaultTransitMount(string? value)
        {
            VaultTransitMount = value;
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
            return new AsherahConfig(this);
        }
    }
}
