using System;
using LanguageExt;

namespace GoDaddy.Asherah.AppEncryption.Persistence;

public abstract class Persistence<T>
{
    public abstract Option<T> Load(string key);
    public abstract void Store(string key, T value);

    public virtual string Store(T value)
    {
        string persistenceKey = GenerateKey(value);
        Store(persistenceKey, value);
        return persistenceKey;
    }

    public virtual string GenerateKey(T value) => Guid.NewGuid().ToString();
}
