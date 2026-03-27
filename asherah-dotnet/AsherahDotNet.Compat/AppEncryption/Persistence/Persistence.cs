using LanguageExt;

namespace GoDaddy.Asherah.AppEncryption.Persistence;

/// <summary>
/// Abstract persistence layer for storing and loading encrypted data row records.
/// Compatible with the canonical godaddy/asherah Persistence class.
/// </summary>
public abstract class Persistence<T>
{
    public abstract Option<T> Load(string key);
    public abstract void Store(string key, T value);

    public virtual string Store(T value)
    {
        var key = GenerateKey(value);
        Store(key, value);
        return key;
    }

    public virtual string GenerateKey(T value) => Guid.NewGuid().ToString();
}

/// <summary>
/// Convenience persistence implementation using delegates.
/// Compatible with the canonical godaddy/asherah AdhocPersistence.
/// </summary>
public class AdhocPersistence<T> : Persistence<T>
{
    private readonly Func<string, Option<T>> _load;
    private readonly Action<string, T> _store;

    public AdhocPersistence(Func<string, Option<T>> load, Action<string, T> store)
    {
        _load = load ?? throw new ArgumentNullException(nameof(load));
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public override Option<T> Load(string key) => _load(key);
    public override void Store(string key, T value) => _store(key, value);
}
