using LanguageExt;

namespace GoDaddy.Asherah.AppEncryption.Persistence;

/// <summary>
/// Abstract persistence layer for storing and loading encrypted data row records.
/// Compatible with the canonical godaddy/asherah Persistence class.
/// </summary>
public abstract class Persistence<T>
{
    /// <summary>Loads an encrypted value by key, if present.</summary>
    public abstract Option<T> Load(string key);

    /// <summary>Stores an encrypted value under <paramref name="key"/>.</summary>
    public abstract void Store(string key, T value);

    /// <summary>Generates a key, stores <paramref name="value"/>, and returns the key.</summary>
    public virtual string Store(T value)
    {
        var key = GenerateKey(value);
        Store(key, value);
        return key;
    }

    /// <summary>Generates a new random persistence key for <paramref name="value"/>.</summary>
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

    /// <summary>Delegates load/store to the supplied functions.</summary>
    public AdhocPersistence(Func<string, Option<T>> load, Action<string, T> store)
    {
        _load = load ?? throw new ArgumentNullException(nameof(load));
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <inheritdoc />
    public override Option<T> Load(string key) => _load(key);

    /// <inheritdoc />
    public override void Store(string key, T value) => _store(key, value);
}
