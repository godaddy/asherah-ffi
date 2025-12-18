using System;
using System.Data.Common;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using LanguageExt;

namespace GoDaddy.Asherah.AppEncryption.Persistence;

public class AdoMetastoreImpl : IMetastore<JObject>
{
    internal AdoMetastoreImpl(DbProviderFactory dbProviderFactory, string connectionString, ILogger? logger)
    {
        DbProviderFactory = dbProviderFactory;
        ConnectionString = connectionString;
        Logger = logger;
    }

    internal DbProviderFactory DbProviderFactory { get; }
    internal string ConnectionString { get; }
    internal ILogger? Logger { get; }

    public static Builder NewBuilder(DbProviderFactory dbProviderFactory, string connectionString) =>
        new(dbProviderFactory, connectionString);

    public Option<JObject> Load(string keyId, DateTimeOffset created) =>
        throw new NotSupportedException("AdoMetastoreImpl is configuration-only when using native core");

    public Option<JObject> LoadLatest(string keyId) =>
        throw new NotSupportedException("AdoMetastoreImpl is configuration-only when using native core");

    public bool Store(string keyId, DateTimeOffset created, JObject value) =>
        throw new NotSupportedException("AdoMetastoreImpl is configuration-only when using native core");

    public string GetKeySuffix() => string.Empty;

    public class Builder
    {
        private readonly DbProviderFactory _dbProviderFactory;
        private readonly string _connectionString;
        private ILogger? _logger;

        internal Builder(DbProviderFactory dbProviderFactory, string connectionString)
        {
            _dbProviderFactory = dbProviderFactory;
            _connectionString = connectionString;
        }

        public Builder WithLogger(ILogger logger)
        {
            _logger = logger;
            return this;
        }

        public AdoMetastoreImpl Build() => new(_dbProviderFactory, _connectionString, _logger);
    }
}
