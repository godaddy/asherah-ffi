using System;
using LanguageExt;

namespace GoDaddy.Asherah.AppEncryption.Persistence;

public class AdhocPersistence<T> : Persistence<T>
{
    private readonly Func<string, Option<T>> _persistenceLoad;
    private readonly Action<string, T> _persistenceStore;

    public AdhocPersistence(Func<string, Option<T>> load, Action<string, T> store)
    {
        _persistenceLoad = load;
        _persistenceStore = store;
    }

    public override Option<T> Load(string key)
    {
        return _persistenceLoad(key);
    }

    public override void Store(string key, T value)
    {
        _persistenceStore(key, value);
    }
}
