using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using App.Metrics;
using GoDaddy.Asherah.AppEncryption.Envelope;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.AppEncryption.Util;
using GoDaddy.Asherah.Crypto;
using GoDaddy.Asherah.Crypto.Keys;
using GoDaddy.Asherah.Internal;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption;

public class SessionFactory : IDisposable
{
    private const int CompactionPercentage = 50;
    private readonly MemoryCache _sessionCache;
    internal MemoryCache SessionCache => _sessionCache;

    private readonly ILogger? _logger;
    private readonly string _productId;
    private readonly string _serviceId;
    private readonly IMetastore<JObject> _metastore;
    private readonly SecureCryptoKeyDictionary<DateTimeOffset> _systemKeyCache;
    private readonly CryptoPolicy _cryptoPolicy;
    private readonly IKeyManagementService _keyManagementService;
    private readonly IAsherahCore _core;
    private readonly ConcurrentDictionary<string, object> _locks = new();

    public SessionFactory(
        string productId,
        string serviceId,
        IMetastore<JObject> metastore,
        SecureCryptoKeyDictionary<DateTimeOffset> systemKeyCache,
        CryptoPolicy cryptoPolicy,
        IKeyManagementService keyManagementService)
        : this(productId, serviceId, metastore, systemKeyCache, cryptoPolicy, keyManagementService, null)
    {
    }

    public SessionFactory(
        string productId,
        string serviceId,
        IMetastore<JObject> metastore,
        SecureCryptoKeyDictionary<DateTimeOffset> systemKeyCache,
        CryptoPolicy cryptoPolicy,
        IKeyManagementService keyManagementService,
        ILogger? logger)
    {
        _productId = productId;
        _serviceId = serviceId;
        _metastore = metastore;
        _systemKeyCache = systemKeyCache;
        _cryptoPolicy = cryptoPolicy;
        _keyManagementService = keyManagementService;
        _logger = logger;
        _sessionCache = new MemoryCache(new MemoryCacheOptions());

        var config = ConfigBuilder.BuildConfig(serviceId, productId, metastore, cryptoPolicy, keyManagementService);
        _core = CoreFactory.Create(config);
    }

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
        IBuildStep WithKeyManagementService(IKeyManagementService keyManagementService);
    }

    public interface IBuildStep
    {
        IBuildStep WithMetrics(IMetrics metrics);
        IBuildStep WithLogger(ILogger logger);
        SessionFactory Build();
    }

    public static IMetastoreStep NewBuilder(string productId, string serviceId) => new Builder(productId, serviceId);

    public void Dispose()
    {
        try
        {
            _systemKeyCache.Dispose();
        }
        catch (Exception e)
        {
            _logger?.LogError(e, "unexpected exception during skCache close");
        }

        try
        {
            lock (_sessionCache)
            {
                foreach (KeyValuePair<string, object> sessionCacheKey in _locks)
                {
                    CachedSession? cachedSession = _sessionCache.Get<CachedSession>(sessionCacheKey.Key);
                    cachedSession?.GetEnvelopeEncryptionJsonImpl().Dispose();
                    _sessionCache.Remove(sessionCacheKey.Key);
                }
            }
        }
        catch (Exception e)
        {
            _logger?.LogError(e, "unexpected exception during dispose");
        }
        finally
        {
            _sessionCache.Dispose();
            _core.Dispose();
        }
    }

    public Session<JObject, byte[]> GetSessionJson(string partitionId)
    {
        IEnvelopeEncryption<byte[]> envelopeEncryption = GetEnvelopeEncryptionBytes(partitionId);
        return new SessionJsonImpl<byte[]>(envelopeEncryption, _logger);
    }

    public Session<byte[], byte[]> GetSessionBytes(string partitionId)
    {
        IEnvelopeEncryption<byte[]> envelopeEncryption = GetEnvelopeEncryptionBytes(partitionId);
        return new SessionBytesImpl<byte[]>(envelopeEncryption, _logger);
    }

    public Session<JObject, JObject> GetSessionJsonAsJson(string partitionId)
    {
        IEnvelopeEncryption<JObject> envelopeEncryption = GetEnvelopeEncryptionJson(partitionId);
        return new SessionJsonImpl<JObject>(envelopeEncryption, _logger);
    }

    public Session<byte[], JObject> GetSessionBytesAsJson(string partitionId)
    {
        IEnvelopeEncryption<JObject> envelopeEncryption = GetEnvelopeEncryptionJson(partitionId);
        return new SessionBytesImpl<JObject>(envelopeEncryption, _logger);
    }

    internal IEnvelopeEncryption<byte[]> GetEnvelopeEncryptionBytes(string partitionId) =>
        new EnvelopeEncryptionBytesImpl(GetEnvelopeEncryptionJson(partitionId), _logger);

    internal Partition GetPartition(string partitionId)
    {
        string regionSuffix = _metastore.GetKeySuffix();
        if (!string.IsNullOrEmpty(regionSuffix))
        {
            return new SuffixedPartition(partitionId, _serviceId, _productId, regionSuffix);
        }

        return new DefaultPartition(partitionId, _serviceId, _productId);
    }

    private IEnvelopeEncryption<JObject> GetEnvelopeEncryptionJson(string partitionId)
    {
        Func<EnvelopeEncryptionJsonImpl> createSessionFunc = () =>
            new EnvelopeEncryptionJsonImpl(_core, partitionId, _logger);

        if (_cryptoPolicy.CanCacheSessions())
        {
            return AcquireShared(createSessionFunc, partitionId);
        }

        return createSessionFunc();
    }

    private CachedSession AcquireShared(Func<EnvelopeEncryptionJsonImpl> createSessionFunc, string partitionId)
    {
        object lockObj = _locks.GetOrAdd(partitionId, _ => new object());
        CachedSession cachedItem;
        lock (lockObj)
        {
            if (!_sessionCache.TryGetValue(partitionId, out cachedItem!))
            {
                if (_sessionCache.Count >= _cryptoPolicy.GetSessionCacheMaxSize())
                {
                    _sessionCache.Compact(CompactionPercentage);
                }

                cachedItem = new CachedSession(createSessionFunc(), partitionId, this);
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    .SetPriority(CacheItemPriority.NeverRemove);
                _sessionCache.Set(partitionId, cachedItem, cacheEntryOptions);
            }

            cachedItem.IncrementUsageTracker();
        }

        return cachedItem;
    }

    private void ReleaseShared(string partitionId)
    {
        try
        {
            CachedSession? cacheItem = _sessionCache.Get<CachedSession>(partitionId);
            if (cacheItem == null)
            {
                return;
            }

            cacheItem.DecrementUsageTracker();
            if (!cacheItem.IsUsed())
            {
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    .SetPriority(CacheItemPriority.Low)
                    .SetSlidingExpiration(TimeSpan.FromMilliseconds(_cryptoPolicy.GetSessionCacheExpireMillis()))
                    .RegisterPostEvictionCallback((_, value, _, _) =>
                    {
                        ((CachedSession)value!).GetEnvelopeEncryptionJsonImpl().Dispose();
                    });
                _sessionCache.Set(partitionId, cacheItem, cacheEntryOptions);
            }
        }
        catch (Exception e)
        {
            _logger?.LogError(e, "Unexpected exception during dispose");
        }
    }

    private class CachedSession : IEnvelopeEncryption<JObject>
    {
        private readonly EnvelopeEncryptionJsonImpl _envelopeEncryptionJsonImpl;
        private int _usageCount;
        private readonly string _key;
        private readonly SessionFactory _sessionFactory;

        public CachedSession(EnvelopeEncryptionJsonImpl envelopeEncryptionJsonImpl, string key, SessionFactory sessionFactory)
        {
            _envelopeEncryptionJsonImpl = envelopeEncryptionJsonImpl;
            _key = key;
            _sessionFactory = sessionFactory;
        }

        public void Dispose() => _sessionFactory.ReleaseShared(_key);

        public byte[] DecryptDataRowRecord(JObject dataRowRecord) =>
            _envelopeEncryptionJsonImpl.DecryptDataRowRecord(dataRowRecord);

        public JObject EncryptPayload(byte[] payload) =>
            _envelopeEncryptionJsonImpl.EncryptPayload(payload);

        public System.Threading.Tasks.Task<byte[]> DecryptDataRowRecordAsync(JObject dataRowRecord) =>
            _envelopeEncryptionJsonImpl.DecryptDataRowRecordAsync(dataRowRecord);

        public System.Threading.Tasks.Task<JObject> EncryptPayloadAsync(byte[] payload) =>
            _envelopeEncryptionJsonImpl.EncryptPayloadAsync(payload);

        internal void IncrementUsageTracker() => Interlocked.Increment(ref _usageCount);
        internal void DecrementUsageTracker() => Interlocked.Decrement(ref _usageCount);
        internal bool IsUsed() => _usageCount > 0;

        internal EnvelopeEncryptionJsonImpl GetEnvelopeEncryptionJsonImpl() => _envelopeEncryptionJsonImpl;
    }

    private class Builder : IMetastoreStep, ICryptoPolicyStep, IKeyManagementServiceStep, IBuildStep
    {
        private readonly string _productId;
        private readonly string _serviceId;
        private IMetastore<JObject>? _metastore;
        private CryptoPolicy? _cryptoPolicy;
        private IKeyManagementService? _kms;
        private IMetrics? _metrics;
        private ILogger? _logger;

        internal Builder(string productId, string serviceId)
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
            _metastore = metastore;
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

        public IBuildStep WithKeyManagementService(IKeyManagementService keyManagementService)
        {
            _kms = keyManagementService;
            return this;
        }

        public IBuildStep WithMetrics(IMetrics metrics)
        {
            _metrics = metrics;
            return this;
        }

        public IBuildStep WithLogger(ILogger logger)
        {
            _logger = logger;
            return this;
        }

        public SessionFactory Build()
        {
            if (_metastore == null)
            {
                throw new InvalidOperationException("Metastore is required");
            }
            if (_cryptoPolicy == null)
            {
                throw new InvalidOperationException("CryptoPolicy is required");
            }
            if (_kms == null)
            {
                throw new InvalidOperationException("KeyManagementService is required");
            }

            if (_metrics == null)
            {
                _metrics = new MetricsBuilder().Configuration.Configure(options => options.Enabled = false).Build();
            }
            MetricsUtil.SetMetricsInstance(_metrics);

            var systemKeyCache = new SecureCryptoKeyDictionary<DateTimeOffset>(_cryptoPolicy.GetRevokeCheckPeriodMillis());
            return new SessionFactory(
                _productId,
                _serviceId,
                _metastore,
                systemKeyCache,
                _cryptoPolicy,
                _kms,
                _logger);
        }
    }
}
