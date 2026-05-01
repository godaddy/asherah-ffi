using GoDaddy.Asherah.AppEncryption.Crypto;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.Encryption;
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

    /// <summary>Returns a JSON-object session with binary UTF-8 encoded data row records.</summary>
    public Session<JObject, byte[]> GetSessionJson(string partitionId)
        => new SessionJsonImpl<byte[]>(_nativeFactory.GetSession(partitionId), false);

    /// <summary>Returns a byte-payload session with binary data row records (JSON ciphertext envelope).</summary>
    public Session<byte[], byte[]> GetSessionBytes(string partitionId)
        => new SessionBytesImpl<byte[]>(_nativeFactory.GetSession(partitionId), false);

    /// <summary>Returns a JSON-object session whose data row records are <see cref="JObject"/>.</summary>
    public Session<JObject, JObject> GetSessionJsonAsJson(string partitionId)
        => new SessionJsonImpl<JObject>(_nativeFactory.GetSession(partitionId), true);

    /// <summary>Returns a byte-payload session whose data row records are <see cref="JObject"/>.</summary>
    public Session<byte[], JObject> GetSessionBytesAsJson(string partitionId)
        => new SessionBytesImpl<JObject>(_nativeFactory.GetSession(partitionId), true);

    /// <summary>Releases the underlying native factory.</summary>
    public void Dispose() => _nativeFactory.Dispose();

    /// <summary>Begins building a <see cref="SessionFactory"/> for the given product and service identifiers.</summary>
    public static IMetastoreStep NewBuilder(string productId, string serviceId)
        => new FactoryBuilder(productId, serviceId);

    // --- Builder step interfaces ---

    /// <summary>Builder step: choose metastore configuration.</summary>
    public interface IMetastoreStep
    {
        /// <summary>Uses the in-process in-memory metastore (testing / dev).</summary>
        ICryptoPolicyStep WithInMemoryMetastore();
        /// <summary>Uses a supported metastore adapter (in-memory, ADO, or DynamoDB).</summary>
        ICryptoPolicyStep WithMetastore(IMetastore<JObject> metastore);
    }

    /// <summary>Builder step: choose crypto policy.</summary>
    public interface ICryptoPolicyStep
    {
        /// <summary>Uses keys that never expire per <see cref="NeverExpiredCryptoPolicy"/>.</summary>
        IKeyManagementServiceStep WithNeverExpiredCryptoPolicy();
        /// <summary>Uses the supplied <paramref name="cryptoPolicy"/>.</summary>
        IKeyManagementServiceStep WithCryptoPolicy(CryptoPolicy cryptoPolicy);
    }

    /// <summary>Builder step: choose key management (KMS).</summary>
    public interface IKeyManagementServiceStep
    {
        /// <summary>Static master key (testing only; sets environment for native static KMS).</summary>
        IBuildStep WithStaticKeyManagementService(string staticMasterKey);
        /// <summary>Uses a supported KMS implementation (static or AWS).</summary>
        IBuildStep WithKeyManagementService(IKeyManagementService kms);
    }

    /// <summary>Final builder step: optional hooks and <see cref="Build"/>.</summary>
    public interface IBuildStep
    {
        /// <summary>Reserved for API parity; metrics are handled by the native layer when configured.</summary>
        IBuildStep WithMetrics(object? metrics);
        /// <summary>Reserved for API parity; logging is handled by the native layer when configured.</summary>
        IBuildStep WithLogger(object? logger);
        /// <summary>Builds the configured factory.</summary>
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
            var nativeFactory = AsherahFactory.FromConfig(config);
            return new SessionFactory(nativeFactory);
        }
    }
}
