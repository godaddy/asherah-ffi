using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace GoDaddy.Asherah.Crypto.Keys;

#pragma warning disable CS8714
public class SecureCryptoKeyDictionary<TKey> : IDisposable
{
    private readonly ConcurrentDictionary<TKey, SharedCryptoKeyEntry> _sharedCryptoKeyDictionary =
        new ConcurrentDictionary<TKey, SharedCryptoKeyEntry>();

    private readonly long _revokeCheckPeriodMillis;
    private volatile int _isClosed = 0;

    public SecureCryptoKeyDictionary(long revokeCheckPeriodMillis)
    {
        _revokeCheckPeriodMillis = revokeCheckPeriodMillis;
    }

    public virtual CryptoKey? Get(TKey key)
    {
        if (!Convert.ToBoolean(_isClosed))
        {
            if (_sharedCryptoKeyDictionary.TryGetValue(key, out SharedCryptoKeyEntry? entry))
            {
                if (entry.SharedCryptoKey.IsRevoked()
                    || (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - Interlocked.Read(ref entry.CachedTimeMillis)) <
                    _revokeCheckPeriodMillis)
                {
                    return entry.SharedCryptoKey;
                }
            }

            return null;
        }

        throw new InvalidOperationException("Attempted to get CryptoKey after close");
    }

    public virtual CryptoKey? GetLast()
    {
        if (!Convert.ToBoolean(_isClosed))
        {
            if (!_sharedCryptoKeyDictionary.IsEmpty)
            {
                IOrderedEnumerable<KeyValuePair<TKey, SharedCryptoKeyEntry>> sorted =
                    _sharedCryptoKeyDictionary.OrderBy(x => x.Key);
                KeyValuePair<TKey, SharedCryptoKeyEntry> lastEntry = sorted.Last();

                if (lastEntry.Value.SharedCryptoKey.IsRevoked()
                    || (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - Interlocked.Read(ref lastEntry.Value.CachedTimeMillis)) <
                    _revokeCheckPeriodMillis)
                {
                    return lastEntry.Value.SharedCryptoKey;
                }
            }

            return null;
        }

        throw new InvalidOperationException("Attempted to get CryptoKey after close");
    }

    public virtual CryptoKey PutAndGetUsable(TKey key, CryptoKey cryptoKey)
    {
        if (!Convert.ToBoolean(_isClosed))
        {
            bool addedToCache = _sharedCryptoKeyDictionary.TryAdd(
                key,
                new SharedCryptoKeyEntry(new SharedCryptoKey(cryptoKey), DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()));

            _sharedCryptoKeyDictionary.TryGetValue(key, out SharedCryptoKeyEntry? cacheValue);
            if (addedToCache)
            {
                return cacheValue!.SharedCryptoKey;
            }

            if (cryptoKey.IsRevoked())
            {
                cacheValue!.SharedCryptoKey.MarkRevoked();
            }
            else
            {
                Interlocked.Exchange(ref cacheValue!.CachedTimeMillis, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            }

            return cryptoKey;
        }

        throw new InvalidOperationException("Attempted to get CryptoKey after close");
    }

    public virtual void Dispose()
    {
        if (!Convert.ToBoolean(Interlocked.CompareExchange(ref _isClosed, 1, 0)))
        {
            foreach (SharedCryptoKeyEntry sharedCryptoKeyEntry in _sharedCryptoKeyDictionary.Values)
            {
                sharedCryptoKeyEntry.SharedCryptoKey.SharedKey.Dispose();
            }

            _sharedCryptoKeyDictionary.Clear();
        }
    }

    private class SharedCryptoKeyEntry
    {
        internal long CachedTimeMillis;

        public SharedCryptoKeyEntry(SharedCryptoKey sharedCryptoKey, long cachedTimeMillis)
        {
            SharedCryptoKey = sharedCryptoKey;
            CachedTimeMillis = cachedTimeMillis;
        }

        internal SharedCryptoKey SharedCryptoKey { get; }
    }
}
#pragma warning restore CS8714
