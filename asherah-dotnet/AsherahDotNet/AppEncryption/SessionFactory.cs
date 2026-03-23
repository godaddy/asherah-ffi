using GoDaddy.Asherah.AppEncryption.Crypto;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption;

/// <summary>
/// Factory for creating encryption sessions. Provides a builder API compatible
/// with the canonical godaddy/asherah SessionFactory.
/// </summary>
public class SessionFactory : IDisposable
{
    private readonly AsherahFactory _nativeFactory;

    private SessionFactory(AsherahFactory nativeFactory)
    {
        _nativeFactory = nativeFactory;
    }

    public Session<JObject, byte[]> GetSessionJson(string partitionId)
        => new SessionJsonImpl<byte[]>(_nativeFactory.GetSession(partitionId), false);

    public Session<byte[], byte[]> GetSessionBytes(string partitionId)
        => new SessionBytesImpl<byte[]>(_nativeFactory.GetSession(partitionId), false);

    public Session<JObject, JObject> GetSessionJsonAsJson(string partitionId)
        => new SessionJsonImpl<JObject>(_nativeFactory.GetSession(partitionId), true);

    public Session<byte[], JObject> GetSessionBytesAsJson(string partitionId)
        => new SessionBytesImpl<JObject>(_nativeFactory.GetSession(partitionId), true);

    public void Dispose() => _nativeFactory.Dispose();

    public static IMetastoreStep NewBuilder(string productId, string serviceId)
        => new FactoryBuilder(productId, serviceId);

    // --- Builder step interfaces ---

    public interface IMetastoreStep
    {
        ICryptoPolicyStep WithInMemoryMetastore();
        ICryptoPolicyStep WithMetastore(IMetastore<JObject> metastore);
    }

    public interface ICryptoPolicyStep
    {
        IKeyManagementServiceStep WithNeverExpiredCryptoPolicy();
        IKeyManagementServiceStep WithCryptoPolicy(CryptoPolicy cryptoPolicy);
    }

    public interface IKeyManagementServiceStep
    {
        IBuildStep WithStaticKeyManagementService(string staticMasterKey);
        IBuildStep WithKeyManagementService(IKeyManagementService kms);
    }

    public interface IBuildStep
    {
        IBuildStep WithMetrics(object? metrics);
        IBuildStep WithLogger(object? logger);
        SessionFactory Build();
    }

    // --- Builder implementation ---

    private class FactoryBuilder : IMetastoreStep, ICryptoPolicyStep, IKeyManagementServiceStep, IBuildStep
    {
        private readonly string _productId;
        private readonly string _serviceId;
        private object? _metastore;
        private CryptoPolicy? _cryptoPolicy;
        private IKeyManagementService? _kms;

        internal FactoryBuilder(string productId, string serviceId)
        {
            _productId = productId;
            _serviceId = serviceId;
        }

        public ICryptoPolicyStep WithInMemoryMetastore()
        {
            _metastore = new InMemoryMetastoreImpl<JObject>();
            return this;
        }

        public ICryptoPolicyStep WithMetastore(IMetastore<JObject> metastore)
        {
            if (metastore is InMemoryMetastoreImpl<JObject> or AdoMetastoreImpl or DynamoDbMetastoreImpl)
                _metastore = metastore;
            else
                throw new NotSupportedException(
                    "Custom IMetastore implementations are not supported by the FFI binding. " +
                    "Use InMemoryMetastoreImpl, AdoMetastoreImpl, or DynamoDbMetastoreImpl.");
            return this;
        }

        public IKeyManagementServiceStep WithNeverExpiredCryptoPolicy()
        {
            _cryptoPolicy = new NeverExpiredCryptoPolicy();
            return this;
        }

        public IKeyManagementServiceStep WithCryptoPolicy(CryptoPolicy cryptoPolicy)
        {
            _cryptoPolicy = cryptoPolicy;
            return this;
        }

        public IBuildStep WithStaticKeyManagementService(string staticMasterKey)
        {
            _kms = new StaticKeyManagementServiceImpl(staticMasterKey);
            return this;
        }

        public IBuildStep WithKeyManagementService(IKeyManagementService kms)
        {
            _kms = kms;
            return this;
        }

        public IBuildStep WithMetrics(object? metrics) => this; // accepted, handled by native layer
        public IBuildStep WithLogger(object? logger) => this; // accepted, handled by native layer

        public SessionFactory Build()
        {
            var cb = AsherahConfig.CreateBuilder()
                .WithProductId(_productId)
                .WithServiceName(_serviceId);

            // Apply metastore config
            switch (_metastore)
            {
                case InMemoryMetastoreImpl<JObject> mem: mem.ApplyConfig(cb); break;
                case AdoMetastoreImpl ado: ado.ApplyConfig(cb); break;
                case DynamoDbMetastoreImpl dynamo: dynamo.ApplyConfig(cb); break;
            }

            // Apply crypto policy
            _cryptoPolicy?.ApplyConfig(cb);

            // Apply KMS
            _kms?.ApplyConfig(cb);

            var config = cb.Build();
            var nativeFactory = Asherah.FactoryFromConfig(config);
            return new SessionFactory(nativeFactory);
        }
    }
}
