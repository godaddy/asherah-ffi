using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GoDaddy.Asherah.Encryption;

/// <summary>
/// Immutable Asherah configuration snapshot produced by
/// <see cref="Builder.Build"/>. Holds JSON wire values sent to native FFI (<see cref="ToJson"/>).
/// Start with <see cref="CreateBuilder"/> and fluent <see cref="Builder"/> methods.
/// </summary>
public sealed class AsherahConfig
{
    /// <summary>Service identifier (JSON <c>ServiceName</c>).</summary>
    public string ServiceName { get; }

    /// <summary>Product identifier (JSON <c>ProductID</c>).</summary>
    public string ProductId { get; }

    /// <summary>
    /// Intermediate-key expiration in whole seconds, or <c>null</c> to omit and use the Rust default.
    /// Derived from fluent <see cref="Builder.WithExpireAfter"/>.
    /// </summary>
    public long? ExpireAfter { get; }

    /// <summary>
    /// Intermediate-key revocation check interval in whole seconds; <c>null</c> omits (Rust default).
    /// Fluent: <see cref="Builder.WithCheckInterval"/>.
    /// </summary>
    public long? CheckInterval { get; }

    /// <summary>KMS metastore discriminator string (<c>"memory"</c>, <c>"rdbms"</c>, <c>"dynamodb"</c>, <c>"sqlite"</c>).</summary>
    public string Metastore { get; }

    /// <summary>RDBMS connection string when <see cref="Metastore"/> is <c>"rdbms"</c>; otherwise unused.</summary>
    public string? ConnectionString { get; }

    /// <summary>Optional Aurora replica read-consistency wire value for RDBMS.</summary>
    public string? ReplicaReadConsistency { get; }

    /// <summary>DynamoDB endpoint override (<c>null</c> for default AWS).</summary>
    public string? DynamoDbEndpoint { get; }

    /// <summary>DynamoDB client region.</summary>
    public string? DynamoDbRegion { get; }

    /// <summary>DynamoDB SigV4 signing region.</summary>
    public string? DynamoDbSigningRegion { get; }

    /// <summary>DynamoDB table name.</summary>
    public string? DynamoDbTableName { get; }

    /// <summary>Session cache LRU bound (<c>null</c> omit → binding applies default).</summary>
    public int? SessionCacheMaxSize { get; }

    /// <summary>Session cache TTL in seconds; <c>null</c> omit.</summary>
    public long? SessionCacheDuration { get; }

    /// <summary>KMS discriminator string (<c>"static"</c>, <c>"aws"</c>, <c>"secrets-manager"</c>, <c>"vault"</c>).</summary>
    public string Kms { get; }

    /// <summary>AWS region→KMS ARN wire map (<c>null</c> omit). Same instance last passed to <see cref="Builder.WithRegionMap"/>.</summary>
    public IReadOnlyDictionary<string, string>? RegionMap { get; }

    /// <summary>Preferred region when using <see cref="RegionMap"/>.</summary>
    public string? PreferredRegion { get; }

    /// <summary>AWS shared-credentials profile applied by the Rust credential chain.</summary>
    public string? AwsProfileName { get; }

    /// <summary>Whether envelope key IDs append a region suffix in multi-region setups.</summary>
    public bool? EnableRegionSuffix { get; }

    /// <summary><c>false</c> disables per-process session caching in bindings that honor it.</summary>
    public bool? EnableSessionCaching { get; }

    /// <summary>Verbose diagnostics from Rust (filtered by hook <c>minLevel</c> until lowered).</summary>
    public bool? Verbose { get; }

    /// <summary>RDBMS pool maximum open connections; <c>0</c> unlimited.</summary>
    public int? PoolMaxOpen { get; }

    /// <summary>RDBMS pool maximum idle connections.</summary>
    public int? PoolMaxIdle { get; }

    /// <summary>RDBMS pool maximum connection lifetime in seconds.</summary>
    public long? PoolMaxLifetime { get; }

    /// <summary>RDBMS pool idle timeout in seconds.</summary>
    public long? PoolMaxIdleTime { get; }

    /// <summary>Single-region KMS key id/ARN (<c>null</c> when using <see cref="RegionMap"/> alone).</summary>
    public string? KmsKeyId { get; }

    /// <summary>Secrets Manager secret containing static master material.</summary>
    public string? SecretsManagerSecretId { get; }

    /// <summary>Vault listener URL (<c>http(s)://...</c>) for <c>kms=vault</c>.</summary>
    public string? VaultAddr { get; }

    /// <summary>Optional pre-created Vault token; bypasses mounted auth flows when set.</summary>
    public string? VaultToken { get; }

    /// <summary>Vault authentication method wire value.</summary>
    public string? VaultAuthMethod { get; }

    /// <summary>Kubernetes/AppRole Vault role binding.</summary>
    public string? VaultAuthRole { get; }

    /// <summary>Vault auth backend mount.</summary>
    public string? VaultAuthMount { get; }

    /// <summary>AppRole role-id.</summary>
    public string? VaultApproleRoleId { get; }

    /// <summary>AppRole secret-id.</summary>
    public string? VaultApproleSecretId { get; }

    /// <summary>PEM client certificate for Vault cert auth.</summary>
    public string? VaultClientCert { get; }

    /// <summary>PEM private key paired with <see cref="VaultClientCert"/>.</summary>
    public string? VaultClientKey { get; }

    /// <summary>Path to Kubernetes service-account JWT.</summary>
    public string? VaultK8sTokenPath { get; }

    /// <summary>Vault Transit wrapping key.</summary>
    public string? VaultTransitKey { get; }

    /// <summary>Vault Transit engine mount (<c>null</c> → default).</summary>
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
        RegionMap = builder.RegionMap;
        PreferredRegion = builder.PreferredRegion;
        AwsProfileName = builder.AwsProfileName;
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
            ["Metastore"] = Metastore,
            ["KMS"] = Kms,
        };

        void AddOptional(string key, object? value)
        {
            if (value is not null)
            {
                payload[key] = value;
            }
        }

        AddOptional("ExpireAfter", ExpireAfter);
        AddOptional("CheckInterval", CheckInterval);
        AddOptional("ConnectionString", ConnectionString);
        AddOptional("ReplicaReadConsistency", ReplicaReadConsistency);
        AddOptional("DynamoDBEndpoint", DynamoDbEndpoint);
        AddOptional("DynamoDBRegion", DynamoDbRegion);
        AddOptional("DynamoDBSigningRegion", DynamoDbSigningRegion);
        AddOptional("DynamoDBTableName", DynamoDbTableName);
        AddOptional("SessionCacheMaxSize", SessionCacheMaxSize);
        AddOptional("SessionCacheDuration", SessionCacheDuration);
        AddOptional("RegionMap", RegionMap);
        AddOptional("PreferredRegion", PreferredRegion);
        AddOptional("AwsProfileName", AwsProfileName);
        AddOptional("EnableRegionSuffix", EnableRegionSuffix);
        AddOptional("EnableSessionCaching", EnableSessionCaching);
        AddOptional("Verbose", Verbose);
        AddOptional("PoolMaxOpen", PoolMaxOpen);
        AddOptional("PoolMaxIdle", PoolMaxIdle);
        AddOptional("PoolMaxLifetime", PoolMaxLifetime);
        AddOptional("PoolMaxIdleTime", PoolMaxIdleTime);
        AddOptional("KmsKeyId", KmsKeyId);
        AddOptional("SecretsManagerSecretId", SecretsManagerSecretId);
        AddOptional("VaultAddr", VaultAddr);
        AddOptional("VaultToken", VaultToken);
        AddOptional("VaultAuthMethod", VaultAuthMethod);
        AddOptional("VaultAuthRole", VaultAuthRole);
        AddOptional("VaultAuthMount", VaultAuthMount);
        AddOptional("VaultApproleRoleId", VaultApproleRoleId);
        AddOptional("VaultApproleSecretId", VaultApproleSecretId);
        AddOptional("VaultClientCert", VaultClientCert);
        AddOptional("VaultClientKey", VaultClientKey);
        AddOptional("VaultK8sTokenPath", VaultK8sTokenPath);
        AddOptional("VaultTransitKey", VaultTransitKey);
        AddOptional("VaultTransitMount", VaultTransitMount);

        var options = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        return JsonSerializer.Serialize(payload, options);
    }

    /// <summary>Creates a fluent <see cref="Builder"/> for constructing an <see cref="AsherahConfig"/>.</summary>
    public static Builder CreateBuilder() => new();

    /// <summary>
    /// Mutable fluent configuration. Call <c>With*</c> methods, then <see cref="Build"/>.
    /// Public properties mirror current values while building (mostly for diagnostics).
    /// </summary>
    public sealed class Builder
    {
        /// <summary>Value set by <see cref="WithServiceName"/> (required before <see cref="Build"/>).</summary>
        public string ServiceName { get; private set; } = null!;

        /// <summary>Value set by <see cref="WithProductId"/>.</summary>
        public string ProductId { get; private set; } = null!;

        /// <summary>Seconds value from <see cref="WithExpireAfter"/>.</summary>
        public long? ExpireAfter { get; private set; }

        /// <summary>Seconds value from <see cref="WithCheckInterval"/>.</summary>
        public long? CheckInterval { get; private set; }

        /// <summary>Wire metastore discriminator from <see cref="WithMetastore"/>.</summary>
        public string Metastore { get; private set; } = null!;

        /// <summary>From <see cref="WithConnectionString"/>.</summary>
        public string? ConnectionString { get; private set; }

        /// <summary>From <see cref="WithReplicaReadConsistency"/>.</summary>
        public string? ReplicaReadConsistency { get; private set; }

        /// <summary>From <see cref="WithDynamoDbEndpoint"/>.</summary>
        public string? DynamoDbEndpoint { get; private set; }

        /// <summary>From <see cref="WithDynamoDbRegion"/>.</summary>
        public string? DynamoDbRegion { get; private set; }

        /// <summary>From <see cref="WithDynamoDbSigningRegion"/>.</summary>
        public string? DynamoDbSigningRegion { get; private set; }

        /// <summary>From <see cref="WithDynamoDbTableName"/>.</summary>
        public string? DynamoDbTableName { get; private set; }

        /// <summary>From <see cref="WithSessionCacheMaxSize"/>.</summary>
        public int? SessionCacheMaxSize { get; private set; }

        /// <summary>Seconds from <see cref="WithSessionCacheDuration"/>.</summary>
        public long? SessionCacheDuration { get; private set; }

        /// <summary>Wire KMS discriminator from <see cref="WithKms"/>.</summary>
        public string Kms { get; private set; } = "static";

        /// <summary>
        /// Same <see cref="IReadOnlyDictionary{TKey,TValue}"/> reference last passed to <see cref="WithRegionMap"/>.
        /// Surfaced unchanged on <see cref="AsherahConfig.RegionMap"/> after <see cref="Build"/>.
        /// </summary>
        public IReadOnlyDictionary<string, string>? RegionMap { get; private set; }

        /// <summary>From <see cref="WithPreferredRegion"/>.</summary>
        public string? PreferredRegion { get; private set; }

        /// <summary>From <see cref="WithAwsProfileName"/>.</summary>
        public string? AwsProfileName { get; private set; }

        /// <summary>From <see cref="WithEnableRegionSuffix"/>.</summary>
        public bool? EnableRegionSuffix { get; private set; }

        /// <summary>From <see cref="WithEnableSessionCaching"/>.</summary>
        public bool? EnableSessionCaching { get; private set; } = true;

        /// <summary>From <see cref="WithVerbose"/>.</summary>
        public bool? Verbose { get; private set; } = false;

        /// <summary>From <see cref="WithPoolMaxOpen"/>.</summary>
        public int? PoolMaxOpen { get; private set; }

        /// <summary>From <see cref="WithPoolMaxIdle"/>.</summary>
        public int? PoolMaxIdle { get; private set; }

        /// <summary>Seconds from <see cref="WithPoolMaxLifetime"/>.</summary>
        public long? PoolMaxLifetime { get; private set; }

        /// <summary>Seconds from <see cref="WithPoolMaxIdleTime"/>.</summary>
        public long? PoolMaxIdleTime { get; private set; }

        /// <summary>From <see cref="WithKmsKeyId"/>.</summary>
        public string? KmsKeyId { get; private set; }

        /// <summary>From <see cref="WithSecretsManagerSecretId"/>.</summary>
        public string? SecretsManagerSecretId { get; private set; }

        /// <summary>From <see cref="WithVaultAddr"/>.</summary>
        public string? VaultAddr { get; private set; }

        /// <summary>From <see cref="WithVaultToken"/>.</summary>
        public string? VaultToken { get; private set; }

        /// <summary>From <see cref="WithVaultAuthMethod"/>.</summary>
        public string? VaultAuthMethod { get; private set; }

        /// <summary>From <see cref="WithVaultAuthRole"/>.</summary>
        public string? VaultAuthRole { get; private set; }

        /// <summary>From <see cref="WithVaultAuthMount"/>.</summary>
        public string? VaultAuthMount { get; private set; }

        /// <summary>From <see cref="WithVaultApproleRoleId"/>.</summary>
        public string? VaultApproleRoleId { get; private set; }

        /// <summary>From <see cref="WithVaultApproleSecretId"/>.</summary>
        public string? VaultApproleSecretId { get; private set; }

        /// <summary>From <see cref="WithVaultClientCert"/>.</summary>
        public string? VaultClientCert { get; private set; }

        /// <summary>From <see cref="WithVaultClientKey"/>.</summary>
        public string? VaultClientKey { get; private set; }

        /// <summary>From <see cref="WithVaultK8sTokenPath"/>.</summary>
        public string? VaultK8sTokenPath { get; private set; }

        /// <summary>From <see cref="WithVaultTransitKey"/>.</summary>
        public string? VaultTransitKey { get; private set; }

        /// <summary>From <see cref="WithVaultTransitMount"/>.</summary>
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
        /// Intermediate-key expiration. After this duration a new IK is generated on the next encrypt;
        /// older IKs stay decryptable for revoke checking. Mapped to JSON as whole seconds at the FFI
        /// boundary (<see cref="TimeSpan.TotalSeconds"/> truncated toward zero).
        /// Pass <c>null</c> to omit the JSON field — the Rust core then applies its default (~90 days).
        /// </summary>
        public Builder WithExpireAfter(TimeSpan? duration)
        {
            ExpireAfter = duration is null ? null : (long)duration.Value.TotalSeconds;
            return this;
        }

        /// <summary>
        /// How often the session checks whether its cached intermediate key has been revoked.
        /// Stored as whole seconds (truncated). Pass <c>null</c> for the Rust core default (~60 minutes).
        /// </summary>
        public Builder WithCheckInterval(TimeSpan? duration)
        {
            CheckInterval = duration is null ? null : (long)duration.Value.TotalSeconds;
            return this;
        }

        /// <summary>
        /// Required. Metastore selector. Maps to the wire strings consumed by
        /// the native core: <see cref="MetastoreKind.Memory"/> (<c>"memory"</c>),
        /// <see cref="MetastoreKind.Rdbms"/> with <see cref="WithConnectionString"/>,
        /// <see cref="MetastoreKind.DynamoDb"/>, or <see cref="MetastoreKind.Sqlite"/>.
        /// </summary>
        public Builder WithMetastore(MetastoreKind kind)
        {
            Metastore = kind.ToWireString();
            return this;
        }

        /// <summary>
        /// SQL connection string for the relational metastore. Required when
        /// the metastore selector is <see cref="MetastoreKind.Rdbms"/>; ignored
        /// otherwise. Connection-string format is the dialect's standard
        /// (e.g. <c>"mysql://user:pass@host:3306/db"</c>).
        /// </summary>
        public Builder WithConnectionString(string? value)
        {
            ConnectionString = value;
            return this;
        }

        /// <summary>
        /// Aurora MySQL read-replica consistency selector. Ignored unless the metastore is
        /// <see cref="MetastoreKind.Rdbms"/> and the connection targets Aurora MySQL with replicas.
        /// Pass <c>null</c> to omit the JSON field so the Rust default applies.
        /// </summary>
        public Builder WithReplicaReadConsistency(ReplicaReadConsistency? value)
        {
            ReplicaReadConsistency = value?.ToWireString();
            return this;
        }

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
        /// Session cache TTL. Stored as whole seconds (truncated). After this duration a cached
        /// session is treated as stale on the next <c>GetSession</c>.
        /// Pass <c>null</c> to omit — the Rust core supplies a default TTL.
        /// </summary>
        public Builder WithSessionCacheDuration(TimeSpan? duration)
        {
            SessionCacheDuration = duration is null ? null : (long)duration.Value.TotalSeconds;
            return this;
        }

        /// <summary>
        /// KMS provider. Maps to the wire strings consumed by the native core:
        /// <see cref="KmsKind.Static"/> (<c>"static"</c>; testing only, uses <c>STATIC_MASTER_KEY_HEX</c>),
        /// <see cref="KmsKind.Aws"/> (<c>"aws"</c>),
        /// <see cref="KmsKind.SecretsManager"/> (<c>"secrets-manager"</c>),
        /// <see cref="KmsKind.Vault"/> (<c>"vault"</c>, HashiCorp Vault Transit).
        /// </summary>
        public Builder WithKms(KmsKind kind)
        {
            Kms = kind.ToWireString();
            return this;
        }

        /// <summary>
        /// AWS KMS multi-region key-ARN map: region (e.g. <c>"us-east-1"</c>)
        /// → ARN. Applies when KMS is <see cref="KmsKind.Aws"/> (active signing region via
        /// <see cref="WithPreferredRegion"/>). Stores the supplied reference as-is (no copy);
        /// factory JSON is derived from whatever the map contains when you call <see cref="Build"/>
        /// and the core reads the config. Assign <c>null</c> to clear. A later <see cref="WithRegionMap"/>
        /// replaces the stored reference without affecting configs already built from older references.
        /// </summary>
        public Builder WithRegionMap(IReadOnlyDictionary<string, string>? value)
        {
            RegionMap = value;
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
        /// Optional AWS shared-credentials profile name (typically from
        /// <c>~/.aws/credentials</c>). Passed to the Rust core's AWS SDK config
        /// when creating KMS, DynamoDB, and Secrets Manager clients. Omit or
        /// pass <c>null</c> to use the default credential chain.
        /// </summary>
        public Builder WithAwsProfileName(string? value)
        {
            AwsProfileName = value;
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
        /// unlimited. Applies when the metastore is <see cref="MetastoreKind.Rdbms"/> only.
        /// </summary>
        public Builder WithPoolMaxOpen(int? value)
        {
            PoolMaxOpen = value;
            return this;
        }

        /// <summary>
        /// Maximum idle DB connections retained in the pool. Affects
        /// <see cref="MetastoreKind.Rdbms"/> only.
        /// </summary>
        public Builder WithPoolMaxIdle(int? value)
        {
            PoolMaxIdle = value;
            return this;
        }

        /// <summary>
        /// Maximum lifetime of a pooled DB connection in whole seconds (<see cref="TimeSpan.TotalSeconds"/>
        /// truncated toward zero). <see cref="TimeSpan.Zero"/> writes <c>0</c>, which the Rust pool treats as
        /// unlimited lifetime. Pass <c>null</c> to omit the JSON field entirely.
        /// Applies when the metastore is <see cref="MetastoreKind.Rdbms"/> only.
        /// </summary>
        public Builder WithPoolMaxLifetime(TimeSpan? duration)
        {
            PoolMaxLifetime = duration is null ? null : (long)duration.Value.TotalSeconds;
            return this;
        }

        /// <summary>
        /// Maximum idle time before a pooled connection is discarded, in whole seconds (truncated toward zero).
        /// <see cref="TimeSpan.Zero"/> writes <c>0</c> for unlimited idle retention (Rust convention).
        /// Pass <c>null</c> to omit this JSON field entirely.
        /// Applies when the metastore is <see cref="MetastoreKind.Rdbms"/> only.
        /// </summary>
        public Builder WithPoolMaxIdleTime(TimeSpan? duration)
        {
            PoolMaxIdleTime = duration is null ? null : (long)duration.Value.TotalSeconds;
            return this;
        }

        /// <summary>
        /// AWS KMS key ID or ARN for single-region KMS setups. Mutually
        /// exclusive with <see cref="WithRegionMap"/>; the latter takes
        /// precedence when both are set. Used when the KMS selector is
        /// <see cref="KmsKind.Aws"/>.
        /// </summary>
        public Builder WithKmsKeyId(string? value)
        {
            KmsKeyId = value;
            return this;
        }

        /// <summary>
        /// AWS Secrets Manager secret ID for the master key,
        /// used when the KMS selector is <see cref="KmsKind.SecretsManager"/>.
        /// </summary>
        public Builder WithSecretsManagerSecretId(string? value)
        {
            SecretsManagerSecretId = value;
            return this;
        }

        /// <summary>
        /// HashiCorp Vault address (e.g. <c>"https://vault.example.com:8200"</c>).
        /// Required when the KMS selector is <see cref="KmsKind.Vault"/>.
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
        /// Vault authentication method selector. Ignored if <see cref="WithVaultToken"/> or the
        /// <c>VAULT_TOKEN</c> environment variable is set (implicit token auth). Pass <c>null</c>
        /// to omit the JSON field.
        /// </summary>
        public Builder WithVaultAuthMethod(VaultAuthMethod? value)
        {
            VaultAuthMethod = value?.ToWireString();
            return this;
        }

        /// <summary>
        /// Vault role name for Kubernetes or AppRole auth. Required when authentication uses
        /// <see cref="VaultAuthMethod.Kubernetes"/> or <see cref="VaultAuthMethod.AppRole"/>.
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
        /// AppRole role-id. Required when authentication uses <see cref="VaultAuthMethod.AppRole"/>.
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
        /// PEM-encoded client certificate for Vault TLS cert auth. Used when authentication uses
        /// <see cref="VaultAuthMethod.Cert"/>; pair with <see cref="WithVaultClientKey"/>.
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
        /// keys. Required when the KMS selector is <see cref="KmsKind.Vault"/>.
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

        /// <summary>
        /// Finalizes validation and builds an immutable <see cref="AsherahConfig"/> snapshot.
        /// </summary>
        /// <exception cref="InvalidOperationException">Required fields are missing.</exception>
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
