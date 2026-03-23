using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption.Persistence;

/// <summary>
/// Interface for key metastore implementations.
/// In the FFI binding, metastore operations are handled by the native Rust layer.
/// </summary>
public interface IMetastore<T>
{
    Option<T> Load(string keyId, DateTimeOffset created);
    Option<T> LoadLatest(string keyId);
    bool Store(string keyId, DateTimeOffset created, T value);
    string GetKeySuffix() => "";
}

/// <summary>In-memory metastore marker. Maps to metastore="memory".</summary>
public class InMemoryMetastoreImpl<T> : IMetastore<T>
{
    internal void ApplyConfig(AsherahConfig.Builder builder) => builder.WithMetastore("memory");
    public Option<T> Load(string keyId, DateTimeOffset created) => throw new NotSupportedException("Handled by native layer");
    public Option<T> LoadLatest(string keyId) => throw new NotSupportedException("Handled by native layer");
    public bool Store(string keyId, DateTimeOffset created, T value) => throw new NotSupportedException("Handled by native layer");
}

/// <summary>ADO.NET/RDBMS metastore adapter. Maps to metastore="rdbms".</summary>
public class AdoMetastoreImpl : IMetastore<JObject>
{
    private readonly string? _connectionString;

    private AdoMetastoreImpl(Builder builder) { _connectionString = builder.ConnectionString; }

    internal void ApplyConfig(AsherahConfig.Builder builder)
    {
        builder.WithMetastore("rdbms");
        if (_connectionString != null) builder.WithConnectionString(_connectionString);
    }

    public static Builder NewBuilder(string connectionString) => new(connectionString);

    public Option<JObject> Load(string keyId, DateTimeOffset created) => throw new NotSupportedException("Handled by native layer");
    public Option<JObject> LoadLatest(string keyId) => throw new NotSupportedException("Handled by native layer");
    public bool Store(string keyId, DateTimeOffset created, JObject value) => throw new NotSupportedException("Handled by native layer");

    public class Builder
    {
        internal string? ConnectionString { get; }
        internal Builder(string? connectionString) { ConnectionString = connectionString; }
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
        builder.WithMetastore("dynamodb").WithDynamoDbRegion(_region);
        if (_signingRegion != null) builder.WithDynamoDbSigningRegion(_signingRegion);
        if (_tableName != "EncryptionKey") builder.WithDynamoDbTableName(_tableName);
        if (_endPoint != null) builder.WithDynamoDbEndpoint(_endPoint);
        if (_keySuffix) builder.WithEnableRegionSuffix(true);
    }

    public static Builder NewBuilder(string region) => new(region);

    public Option<JObject> Load(string keyId, DateTimeOffset created) => throw new NotSupportedException("Handled by native layer");
    public Option<JObject> LoadLatest(string keyId) => throw new NotSupportedException("Handled by native layer");
    public bool Store(string keyId, DateTimeOffset created, JObject value) => throw new NotSupportedException("Handled by native layer");
    public string GetKeySuffix() => _keySuffix ? "_" + _region : "";

    public class Builder
    {
        internal string Region { get; }
        internal string TableName { get; private set; } = "EncryptionKey";
        internal string? EndPoint { get; private set; }
        internal string? SigningRegion { get; private set; }
        internal bool KeySuffix { get; private set; }

        internal Builder(string region) { Region = region; }
        public Builder WithTableName(string tableName) { TableName = tableName; return this; }
        public Builder WithEndPointConfiguration(string endPoint, string signingRegion) { EndPoint = endPoint; SigningRegion = signingRegion; return this; }
        public Builder WithKeySuffix() { KeySuffix = true; return this; }
        public DynamoDbMetastoreImpl Build() => new(this);
    }
}
