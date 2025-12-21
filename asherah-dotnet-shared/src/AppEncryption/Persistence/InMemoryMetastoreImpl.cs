using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using LanguageExt;

namespace GoDaddy.Asherah.AppEncryption.Persistence;

public class InMemoryMetastoreImpl<T> : IMetastore<T>, IDisposable
{
    private readonly ConcurrentDictionary<(string, long), T> _values = new();

    public Option<T> Load(string keyId, DateTimeOffset created)
    {
        var key = (keyId, created.ToUnixTimeSeconds());
        return _values.TryGetValue(key, out var value) ? Option<T>.Some(value) : Option<T>.None;
    }

    public Option<T> LoadLatest(string keyId)
    {
        long best = long.MinValue;
        T? value = default;
        foreach (KeyValuePair<(string, long), T> pair in _values)
        {
            if (pair.Key.Item1 == keyId && pair.Key.Item2 > best)
            {
                best = pair.Key.Item2;
                value = pair.Value;
            }
        }
        return best == long.MinValue ? Option<T>.None : Option<T>.Some(value!);
    }

    public bool Store(string keyId, DateTimeOffset created, T value)
    {
        var key = (keyId, created.ToUnixTimeSeconds());
        return _values.TryAdd(key, value);
    }

    public string GetKeySuffix() => string.Empty;

    public void Dispose()
    {
        _values.Clear();
    }
}
