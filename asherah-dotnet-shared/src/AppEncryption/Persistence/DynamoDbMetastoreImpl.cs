using System;
using Amazon.DynamoDBv2;
using Amazon.Runtime;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using LanguageExt;

namespace GoDaddy.Asherah.AppEncryption.Persistence;

public class DynamoDbMetastoreImpl : IMetastore<JObject>
{
    internal DynamoDbMetastoreImpl(Builder builder)
    {
        PreferredRegion = builder.PreferredRegion;
        HasKeySuffix = builder.HasKeySuffix;
        TableName = builder.TableName;
        Endpoint = builder.Endpoint;
        Region = builder.Region;
        Credentials = builder.Credentials;
        DbClient = builder.DbClient;
        Logger = builder.Logger;
    }

    internal string PreferredRegion { get; }
    internal bool HasKeySuffix { get; }
    internal string TableName { get; }
    internal string? Endpoint { get; }
    internal string? Region { get; }
    internal AWSCredentials? Credentials { get; }
    internal IAmazonDynamoDB? DbClient { get; }
    internal ILogger? Logger { get; }

    public static Builder NewBuilder(string region) => new(region);

    public Option<JObject> Load(string keyId, DateTimeOffset created) =>
        throw new NotSupportedException("DynamoDbMetastoreImpl is configuration-only when using native core");

    public Option<JObject> LoadLatest(string keyId) =>
        throw new NotSupportedException("DynamoDbMetastoreImpl is configuration-only when using native core");

    public bool Store(string keyId, DateTimeOffset created, JObject value) =>
        throw new NotSupportedException("DynamoDbMetastoreImpl is configuration-only when using native core");

    public string GetKeySuffix() => HasKeySuffix ? PreferredRegion : string.Empty;

    public interface IBuildStep
    {
        IBuildStep WithKeySuffix();
        IBuildStep WithTableName(string tableName);
        IBuildStep WithCredentials(AWSCredentials credentials);
        IBuildStep WithEndPointConfiguration(string endPoint, string signingRegion);
        IBuildStep WithRegion(string region);
        IBuildStep WithLogger(ILogger logger);
        IBuildStep WithDynamoDbClient(IAmazonDynamoDB client);
        DynamoDbMetastoreImpl Build();
    }

    public class Builder : IBuildStep
    {
        private const string DefaultTableName = "EncryptionKey";

        internal string PreferredRegion { get; }
        internal bool HasKeySuffix { get; private set; }
        internal string TableName { get; private set; } = DefaultTableName;
        internal string? Endpoint { get; private set; }
        internal string? Region { get; private set; }
        internal AWSCredentials? Credentials { get; private set; }
        internal IAmazonDynamoDB? DbClient { get; private set; }
        internal ILogger? Logger { get; private set; }

        public Builder(string region)
        {
            PreferredRegion = region;
        }

        public IBuildStep WithKeySuffix()
        {
            HasKeySuffix = true;
            return this;
        }

        public IBuildStep WithTableName(string tableName)
        {
            TableName = tableName;
            return this;
        }

        public IBuildStep WithCredentials(AWSCredentials credentials)
        {
            Credentials = credentials;
            return this;
        }

        public IBuildStep WithEndPointConfiguration(string endPoint, string signingRegion)
        {
            Endpoint = endPoint;
            Region = signingRegion;
            return this;
        }

        public IBuildStep WithRegion(string region)
        {
            Region = region;
            return this;
        }

        public IBuildStep WithLogger(ILogger logger)
        {
            Logger = logger;
            return this;
        }

        public IBuildStep WithDynamoDbClient(IAmazonDynamoDB client)
        {
            DbClient = client;
            return this;
        }

        public DynamoDbMetastoreImpl Build() => new(this);
    }
}
