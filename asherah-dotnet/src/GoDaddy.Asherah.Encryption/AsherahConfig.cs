using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GoDaddy.Asherah.Encryption;

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

    /// <summary>
    /// Effective session cache bound. Matches the Rust core default
    /// (1000) and the other language bindings, so a value applied here is
    /// the same bound the native session cache enforces.
    /// </summary>
    internal int SessionCacheMaxSizeOrDefault =>
        SessionCacheMaxSize is { } v && v > 0 ? v : 1000;

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

        /// <summary>
        /// Required. Service identifier for the key hierarchy. The native
        /// core uses <c>service</c> + <c>product</c> as the partition prefix
        /// when generating intermediate-key IDs.
        /// </summary>
        public Builder WithServiceName(string value)
        {
            ServiceName = value;
            return this;
        }

        /// <summary>
        /// Required. Product identifier for the key hierarchy. The native
        /// core uses <c>service</c> + <c>product</c> as the partition prefix
        /// when generating intermediate-key IDs.
        /// </summary>
        public Builder WithProductId(string value)
        {
            ProductId = value;
            return this;
        }

        /// <summary>
        /// Intermediate-key expiration in seconds. After this duration a new
        /// IK is generated on the next encrypt; old IKs remain decryptable
        /// for revoke-checking purposes. Default: 90 days (when omitted, the
        /// Rust core supplies the default).
        /// </summary>
        public Builder WithExpireAfter(long? seconds)
        {
            ExpireAfter = seconds;
            return this;
        }

        /// <summary>
        /// Intermediate-key expiration as a <see cref="TimeSpan"/>. Convenience
        /// overload of <see cref="WithExpireAfter(long?)"/>; the value is
        /// rounded down to whole seconds.
        /// </summary>
        public Builder WithExpireAfter(TimeSpan? duration) =>
            WithExpireAfter(duration is null ? (long?)null : (long)duration.Value.TotalSeconds);

        /// <summary>
        /// How often the session checks whether its cached intermediate key
        /// has been revoked, in seconds. Default: 60 minutes.
        /// </summary>
        public Builder WithCheckInterval(long? seconds)
        {
            CheckInterval = seconds;
            return this;
        }

        /// <summary>
        /// Revoke-check interval as a <see cref="TimeSpan"/>. Convenience
        /// overload of <see cref="WithCheckInterval(long?)"/>; the value is
        /// rounded down to whole seconds.
        /// </summary>
        public Builder WithCheckInterval(TimeSpan? duration) =>
            WithCheckInterval(duration is null ? (long?)null : (long)duration.Value.TotalSeconds);

        /// <summary>
        /// Required. Metastore selector. Accepts <c>"memory"</c> (testing —
        /// keys are lost on process restart), <c>"rdbms"</c> (MySQL or
        /// PostgreSQL via <see cref="WithConnectionString"/>),
        /// <c>"dynamodb"</c>, or <c>"sqlite"</c>.
        /// </summary>
        public Builder WithMetastore(string value)
        {
            Metastore = value;
            return this;
        }

        /// <summary>
        /// Required. Strongly-typed metastore selector. Equivalent to
        /// <see cref="WithMetastore(string)"/> with the wire string mapped from
        /// <see cref="MetastoreKind"/>.
        /// </summary>
        public Builder WithMetastore(MetastoreKind kind) => WithMetastore(kind.ToWireString());

        /// <summary>
        /// SQL connection string for the <c>"rdbms"</c> metastore. Required
        /// when <see cref="WithMetastore"/> is <c>"rdbms"</c>; ignored
        /// otherwise. Connection-string format is the dialect's standard
        /// (e.g. <c>"mysql://user:pass@host:3306/db"</c>).
        /// </summary>
        public Builder WithConnectionString(string? value)
        {
            ConnectionString = value;
            return this;
        }

        /// <summary>
        /// Aurora MySQL read-replica consistency. Accepts <c>"eventual"</c>
        /// (default — read from the nearest replica without waiting),
        /// <c>"global"</c> (Aurora global-database read-after-write
        /// consistency), or <c>"session"</c> (session-level read-after-write
        /// consistency). Ignored for non-Aurora metastores.
        /// </summary>
        public Builder WithReplicaReadConsistency(string? value)
        {
            ReplicaReadConsistency = value;
            return this;
        }

        /// <summary>
        /// Strongly-typed read-replica consistency. Equivalent to
        /// <see cref="WithReplicaReadConsistency(string?)"/> with the wire
        /// string mapped from <see cref="GoDaddy.Asherah.ReplicaReadConsistency"/>.
        /// </summary>
        public Builder WithReplicaReadConsistency(ReplicaReadConsistency? value) =>
            WithReplicaReadConsistency(value?.ToWireString());

        /// <summary>
        /// DynamoDB endpoint URL. Set when targeting LocalStack or local
        /// DynamoDB (e.g. <c>"http://localhost:8000"</c>); leave unset for
        /// AWS DynamoDB (the SDK resolves the regional endpoint).
        /// </summary>
        public Builder WithDynamoDbEndpoint(string? value)
        {
            DynamoDbEndpoint = value;
            return this;
        }

        /// <summary>
        /// AWS region for the DynamoDB metastore client (e.g.
        /// <c>"us-east-1"</c>). Distinct from
        /// <see cref="WithDynamoDbSigningRegion"/>; used as the regional
        /// endpoint selector.
        /// </summary>
        public Builder WithDynamoDbRegion(string? value)
        {
            DynamoDbRegion = value;
            return this;
        }

        /// <summary>
        /// AWS region used for SigV4 request signing of DynamoDB calls.
        /// Distinct from <see cref="WithDynamoDbRegion"/> (the endpoint
        /// region) and from <see cref="WithPreferredRegion"/> (which
        /// AWS KMS uses to pick a region from <see cref="WithRegionMap"/>).
        /// In most setups the signing region equals the endpoint region;
        /// set explicitly only for cross-region signing scenarios.
        /// </summary>
        public Builder WithDynamoDbSigningRegion(string? value)
        {
            DynamoDbSigningRegion = value;
            return this;
        }

        /// <summary>
        /// DynamoDB table name. Default <c>"EncryptionKey"</c>. The schema
        /// is fixed (partition key <c>Id</c>, sort key <c>Created</c>); only
        /// the table name itself is configurable.
        /// </summary>
        public Builder WithDynamoDbTableName(string? value)
        {
            DynamoDbTableName = value;
            return this;
        }

        /// <summary>
        /// Maximum number of <see cref="AsherahSession"/> instances cached
        /// in the per-factory session cache (when
        /// <see cref="WithEnableSessionCaching"/> is <c>true</c>). Default
        /// 1000. LRU-evicted.
        /// </summary>
        public Builder WithSessionCacheMaxSize(int? value)
        {
            SessionCacheMaxSize = value;
            return this;
        }

        /// <summary>
        /// Session cache TTL in seconds. After this duration a cached
        /// session is treated as stale and recreated on the next
        /// <c>GetSession</c> call.
        /// </summary>
        public Builder WithSessionCacheDuration(long? value)
        {
            SessionCacheDuration = value;
            return this;
        }

        /// <summary>
        /// Session cache TTL as a <see cref="TimeSpan"/>. Convenience overload
        /// of <see cref="WithSessionCacheDuration(long?)"/>; rounded down to
        /// whole seconds.
        /// </summary>
        public Builder WithSessionCacheDuration(TimeSpan? duration) =>
            WithSessionCacheDuration(duration is null ? (long?)null : (long)duration.Value.TotalSeconds);

        /// <summary>
        /// KMS provider. Accepts <c>"static"</c> (default; testing only,
        /// uses <c>STATIC_MASTER_KEY_HEX</c>), <c>"aws"</c> (AWS KMS),
        /// <c>"secrets-manager"</c> (AWS Secrets Manager), or
        /// <c>"vault"</c> (HashiCorp Vault Transit).
        /// </summary>
        public Builder WithKms(string value)
        {
            Kms = value;
            return this;
        }

        /// <summary>
        /// Strongly-typed KMS provider. Equivalent to <see cref="WithKms(string)"/>
        /// with the wire string mapped from <see cref="KmsKind"/>.
        /// </summary>
        public Builder WithKms(KmsKind kind) => WithKms(kind.ToWireString());

        /// <summary>
        /// AWS KMS multi-region key-ARN map: region (e.g. <c>"us-east-1"</c>)
        /// → key ARN. Used with <see cref="WithKms"/> = <c>"aws"</c> for
        /// region-specific KMS keys; the active region is selected via
        /// <see cref="WithPreferredRegion"/>. The supplied dictionary is
        /// copied — subsequent edits to the caller's dictionary do not
        /// affect the built config.
        /// </summary>
        public Builder WithRegionMap(IDictionary<string, string>? value)
        {
            RegionMap = value == null ? null : new Dictionary<string, string>(value);
            return this;
        }

        /// <summary>
        /// Read-only overload of <see cref="WithRegionMap(IDictionary{string, string}?)"/>.
        /// Convenient for callers handing in <c>ImmutableDictionary</c>,
        /// <c>FrozenDictionary</c>, or other read-only collections.
        /// </summary>
        public Builder WithRegionMap(IReadOnlyDictionary<string, string>? value)
        {
            RegionMap = value == null ? null : new Dictionary<string, string>(
                value as IEnumerable<KeyValuePair<string, string>>);
            return this;
        }

        /// <summary>
        /// Preferred AWS region from <see cref="WithRegionMap"/>. The KMS
        /// client encrypts new envelope keys using this region's key ARN
        /// from the map; existing envelope keys may have been encrypted
        /// under any region in the map and are still decryptable.
        /// </summary>
        public Builder WithPreferredRegion(string? value)
        {
            PreferredRegion = value;
            return this;
        }

        /// <summary>
        /// When <c>true</c>, append the AWS region as a suffix to generated
        /// key IDs (e.g. <c>_IK_partition_service_product_us-east-1</c>).
        /// Used with multi-region setups to keep region-specific keys in
        /// distinct rows. Default <c>false</c>.
        /// </summary>
        public Builder WithEnableRegionSuffix(bool? value)
        {
            EnableRegionSuffix = value;
            return this;
        }

        /// <summary>
        /// Enable the per-partition <see cref="AsherahSession"/> cache.
        /// Default <c>true</c>. Disable for tests that need to observe
        /// session-creation overhead, or when sessions must be disposed
        /// promptly after each use.
        /// </summary>
        public Builder WithEnableSessionCaching(bool? value)
        {
            EnableSessionCaching = value;
            return this;
        }

        /// <summary>
        /// Toggle verbose log emission from the Rust core. Default
        /// <c>false</c>. When <c>true</c>, the Rust side emits
        /// <c>Trace</c>/<c>Debug</c> records on the encrypt/decrypt hot
        /// path; when <c>false</c>, only <c>Info</c>/<c>Warn</c>/<c>Error</c>
        /// records are produced. The producer-side log filter on
        /// <see cref="AsherahHooks"/> still applies on top of this — both
        /// must permit a record before the user callback fires.
        /// </summary>
        public Builder WithVerbose(bool? value)
        {
            Verbose = value;
            return this;
        }

        /// <summary>
        /// Maximum open DB connections in the metastore pool. <c>0</c> =
        /// unlimited. Affects <c>"rdbms"</c> only.
        /// </summary>
        public Builder WithPoolMaxOpen(int? value)
        {
            PoolMaxOpen = value;
            return this;
        }

        /// <summary>
        /// Maximum idle DB connections retained in the pool. Affects
        /// <c>"rdbms"</c> only.
        /// </summary>
        public Builder WithPoolMaxIdle(int? value)
        {
            PoolMaxIdle = value;
            return this;
        }

        /// <summary>
        /// Maximum lifetime of a DB connection in seconds. <c>0</c> =
        /// unlimited. Connections older than this are recycled on next
        /// release. Affects <c>"rdbms"</c> only.
        /// </summary>
        public Builder WithPoolMaxLifetime(long? seconds)
        {
            PoolMaxLifetime = seconds;
            return this;
        }

        /// <summary>
        /// Max DB connection lifetime as a <see cref="TimeSpan"/>. Convenience
        /// overload of <see cref="WithPoolMaxLifetime(long?)"/>; rounded down
        /// to whole seconds.
        /// </summary>
        public Builder WithPoolMaxLifetime(TimeSpan? duration) =>
            WithPoolMaxLifetime(duration is null ? (long?)null : (long)duration.Value.TotalSeconds);

        /// <summary>
        /// Maximum idle time of a DB connection in seconds before it's
        /// closed and removed from the pool. <c>0</c> = unlimited. Affects
        /// <c>"rdbms"</c> only.
        /// </summary>
        public Builder WithPoolMaxIdleTime(long? seconds)
        {
            PoolMaxIdleTime = seconds;
            return this;
        }

        /// <summary>
        /// Max DB connection idle time as a <see cref="TimeSpan"/>. Convenience
        /// overload of <see cref="WithPoolMaxIdleTime(long?)"/>; rounded down to
        /// whole seconds.
        /// </summary>
        public Builder WithPoolMaxIdleTime(TimeSpan? duration) =>
            WithPoolMaxIdleTime(duration is null ? (long?)null : (long)duration.Value.TotalSeconds);

        /// <summary>
        /// AWS KMS key ID or ARN for single-region KMS setups. Mutually
        /// exclusive with <see cref="WithRegionMap"/>; the latter takes
        /// precedence when both are set. Used with <see cref="WithKms"/>
        /// = <c>"aws"</c>.
        /// </summary>
        public Builder WithKmsKeyId(string? value)
        {
            KmsKeyId = value;
            return this;
        }

        /// <summary>
        /// AWS Secrets Manager secret ID for the master key, used with
        /// <see cref="WithKms"/> = <c>"secrets-manager"</c>.
        /// </summary>
        public Builder WithSecretsManagerSecretId(string? value)
        {
            SecretsManagerSecretId = value;
            return this;
        }

        /// <summary>
        /// HashiCorp Vault address (e.g. <c>"https://vault.example.com:8200"</c>).
        /// Required when <see cref="WithKms"/> = <c>"vault"</c>.
        /// </summary>
        public Builder WithVaultAddr(string? value)
        {
            VaultAddr = value;
            return this;
        }

        /// <summary>
        /// Pre-acquired Vault token. When set, Vault auth is skipped and
        /// this token is used directly. Equivalent to setting the
        /// <c>VAULT_TOKEN</c> environment variable.
        /// </summary>
        public Builder WithVaultToken(string? value)
        {
            VaultToken = value;
            return this;
        }

        /// <summary>
        /// Vault authentication method. Accepts <c>"kubernetes"</c>
        /// (service-account JWT), <c>"approle"</c>, or <c>"cert"</c>
        /// (TLS client cert). Ignored if <see cref="WithVaultToken"/> or
        /// the <c>VAULT_TOKEN</c> environment variable is set (token auth
        /// is implicit).
        /// </summary>
        public Builder WithVaultAuthMethod(string? value)
        {
            VaultAuthMethod = value;
            return this;
        }

        /// <summary>
        /// Strongly-typed Vault authentication method. Equivalent to
        /// <see cref="WithVaultAuthMethod(string?)"/> with the wire string
        /// mapped from <see cref="GoDaddy.Asherah.VaultAuthMethod"/>.
        /// </summary>
        public Builder WithVaultAuthMethod(VaultAuthMethod? value) =>
            WithVaultAuthMethod(value?.ToWireString());

        /// <summary>
        /// Vault role name for Kubernetes or AppRole auth. Required for
        /// <see cref="WithVaultAuthMethod"/> = <c>"kubernetes"</c>.
        /// </summary>
        public Builder WithVaultAuthRole(string? value)
        {
            VaultAuthRole = value;
            return this;
        }

        /// <summary>
        /// Vault auth backend mount path. Defaults to the auth method name
        /// (<c>"kubernetes"</c>, <c>"approle"</c>, <c>"cert"</c>); set
        /// explicitly when the backend is mounted at a non-default path.
        /// </summary>
        public Builder WithVaultAuthMount(string? value)
        {
            VaultAuthMount = value;
            return this;
        }

        /// <summary>
        /// AppRole role-id. Required when
        /// <see cref="WithVaultAuthMethod"/> = <c>"approle"</c>.
        /// </summary>
        public Builder WithVaultApproleRoleId(string? value)
        {
            VaultApproleRoleId = value;
            return this;
        }

        /// <summary>
        /// AppRole secret-id. Required for non-anonymous AppRole auth;
        /// pair with <see cref="WithVaultApproleRoleId"/>.
        /// </summary>
        public Builder WithVaultApproleSecretId(string? value)
        {
            VaultApproleSecretId = value;
            return this;
        }

        /// <summary>
        /// PEM-encoded client certificate for Vault TLS cert auth. Used
        /// when <see cref="WithVaultAuthMethod"/> = <c>"cert"</c>; pair
        /// with <see cref="WithVaultClientKey"/>.
        /// </summary>
        public Builder WithVaultClientCert(string? value)
        {
            VaultClientCert = value;
            return this;
        }

        /// <summary>
        /// PEM-encoded client private key for Vault TLS cert auth.
        /// </summary>
        public Builder WithVaultClientKey(string? value)
        {
            VaultClientKey = value;
            return this;
        }

        /// <summary>
        /// Path to the Kubernetes service-account JWT used by Vault
        /// Kubernetes auth. Defaults to
        /// <c>/var/run/secrets/kubernetes.io/serviceaccount/token</c> —
        /// override only for non-standard mount points.
        /// </summary>
        public Builder WithVaultK8sTokenPath(string? value)
        {
            VaultK8sTokenPath = value;
            return this;
        }

        /// <summary>
        /// Vault Transit key name used to wrap/unwrap Asherah envelope
        /// keys. Required when <see cref="WithKms"/> = <c>"vault"</c>.
        /// </summary>
        public Builder WithVaultTransitKey(string? value)
        {
            VaultTransitKey = value;
            return this;
        }

        /// <summary>
        /// Vault Transit secrets-engine mount path. Defaults to
        /// <c>"transit"</c>; override when the engine is mounted at a
        /// non-default path.
        /// </summary>
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
