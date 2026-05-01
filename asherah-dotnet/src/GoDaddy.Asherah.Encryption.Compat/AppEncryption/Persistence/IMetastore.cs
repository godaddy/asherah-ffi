using GoDaddy.Asherah;
using GoDaddy.Asherah.Encryption;
using LanguageExt;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption.Persistence;

/// <summary>
/// Interface for key metastore implementations.
/// In the FFI binding, metastore operations are handled by the native Rust layer.
/// </summary>
public interface IMetastore<T>
{
    /// <summary>Loads a key envelope by id and creation time.</summary>
    Option<T> Load(string keyId, DateTimeOffset created);
    /// <summary>Loads the latest envelope for <paramref name="keyId"/>.</summary>
    Option<T> LoadLatest(string keyId);
    /// <summary>Persists an envelope for <paramref name="keyId"/> at <paramref name="created"/>.</summary>
    bool Store(string keyId, DateTimeOffset created, T value);
    /// <summary>Optional region suffix for partitioned keys; empty by default.</summary>
    string GetKeySuffix() => "";
}

/// <summary>In-memory metastore marker. Maps to metastore="memory".</summary>
public class InMemoryMetastoreImpl<T> : IMetastore<T>
{
    internal void ApplyConfig(AsherahConfig.Builder builder) => builder.WithMetastore(MetastoreKind.Memory);

    /// <inheritdoc />
    public Option<T> Load(string keyId, DateTimeOffset created) => throw new NotSupportedException("Handled by native layer");

    /// <inheritdoc />
    public Option<T> LoadLatest(string keyId) => throw new NotSupportedException("Handled by native layer");

    /// <inheritdoc />
    public bool Store(string keyId, DateTimeOffset created, T value) => throw new NotSupportedException("Handled by native layer");
}

/// <summary>ADO.NET/RDBMS metastore adapter. Maps to metastore="rdbms".</summary>
public class AdoMetastoreImpl : IMetastore<JObject>
{
    private readonly string? _connectionString;

    private AdoMetastoreImpl(Builder builder) { _connectionString = builder.ConnectionString; }

    internal void ApplyConfig(AsherahConfig.Builder builder)
    {
        builder.WithMetastore(MetastoreKind.Rdbms);
        if (_connectionString != null) builder.WithConnectionString(_connectionString);
    }

    /// <summary>Creates a builder for an ADO metastore with the given connection string.</summary>
    public static Builder NewBuilder(string connectionString) => new(connectionString);

    /// <inheritdoc />
    public Option<JObject> Load(string keyId, DateTimeOffset created) => throw new NotSupportedException("Handled by native layer");

    /// <inheritdoc />
    public Option<JObject> LoadLatest(string keyId) => throw new NotSupportedException("Handled by native layer");

    /// <inheritdoc />
    public bool Store(string keyId, DateTimeOffset created, JObject value) => throw new NotSupportedException("Handled by native layer");

    /// <summary>Fluent builder for <see cref="AdoMetastoreImpl"/>.</summary>
    public class Builder
    {
        internal string? ConnectionString { get; }
        internal Builder(string? connectionString) { ConnectionString = connectionString; }

        /// <summary>Builds the metastore adapter for use with <see cref="SessionFactory.IMetastoreStep.WithMetastore"/>.</summary>
        public AdoMetastoreImpl Build() => new(this);
    }
}

/// <summary>DynamoDB metastore adapter. Maps to metastore="dynamodb".</summary>
public class DynamoDbMetastoreImpl : IMetastore<JObject>
{
    private readonly string _region;
    private readonly string _tableName;
    private readonly string? _endPoint;
    private readonly string? _signingRegion;
    private readonly bool _keySuffix;

    private DynamoDbMetastoreImpl(Builder builder)
    {
        _region = builder.Region;
        _tableName = builder.TableName;
        _endPoint = builder.EndPoint;
        _signingRegion = builder.SigningRegion;
        _keySuffix = builder.KeySuffix;
    }

    internal void ApplyConfig(AsherahConfig.Builder builder)
    {
        builder.WithMetastore(MetastoreKind.DynamoDb).WithDynamoDbRegion(_region);
        if (_signingRegion != null) builder.WithDynamoDbSigningRegion(_signingRegion);
        if (_tableName != "EncryptionKey") builder.WithDynamoDbTableName(_tableName);
        if (_endPoint != null) builder.WithDynamoDbEndpoint(_endPoint);
        if (_keySuffix) builder.WithEnableRegionSuffix(true);
    }

    /// <summary>Creates a builder targeting the given AWS region.</summary>
    public static Builder NewBuilder(string region) => new(region);

    /// <inheritdoc />
    public Option<JObject> Load(string keyId, DateTimeOffset created) => throw new NotSupportedException("Handled by native layer");

    /// <inheritdoc />
    public Option<JObject> LoadLatest(string keyId) => throw new NotSupportedException("Handled by native layer");

    /// <inheritdoc />
    public bool Store(string keyId, DateTimeOffset created, JObject value) => throw new NotSupportedException("Handled by native layer");

    /// <inheritdoc />
    public string GetKeySuffix() => _keySuffix ? "_" + _region : "";

    /// <summary>Fluent builder for <see cref="DynamoDbMetastoreImpl"/>.</summary>
    public class Builder
    {
        internal string Region { get; }
        internal string TableName { get; private set; } = "EncryptionKey";
        internal string? EndPoint { get; private set; }
        internal string? SigningRegion { get; private set; }
        internal bool KeySuffix { get; private set; }

        internal Builder(string region) { Region = region; }

        /// <summary>Overrides the default DynamoDB table name.</summary>
        public Builder WithTableName(string tableName) { TableName = tableName; return this; }

        /// <summary>Configures a custom endpoint and signing region (e.g., LocalStack).</summary>
        public Builder WithEndPointConfiguration(string endPoint, string signingRegion) { EndPoint = endPoint; SigningRegion = signingRegion; return this; }

        /// <summary>Appends region suffix to stored keys.</summary>
        public Builder WithKeySuffix() { KeySuffix = true; return this; }

        /// <summary>Builds the metastore adapter for use with <see cref="SessionFactory.IMetastoreStep.WithMetastore"/>.</summary>
        public DynamoDbMetastoreImpl Build() => new(this);
    }
}
