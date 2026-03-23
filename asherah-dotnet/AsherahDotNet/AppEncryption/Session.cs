using System.Text;
using GoDaddy.Asherah.AppEncryption.Persistence;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption;

/// <summary>
/// Abstract session for encrypting and decrypting data for a specific partition.
/// Compatible with the canonical godaddy/asherah Session class.
/// </summary>
/// <typeparam name="TP">The payload type (JObject or byte[])</typeparam>
/// <typeparam name="TD">The data row record type (byte[] or JObject)</typeparam>
public abstract class Session<TP, TD> : IDisposable
{
    public abstract void Dispose();
    public abstract TP Decrypt(TD dataRowRecord);
    public abstract TD Encrypt(TP payload);

    public virtual Task<TP> DecryptAsync(TD dataRowRecord)
        => Task.Run(() => Decrypt(dataRowRecord));

    public virtual Task<TD> EncryptAsync(TP payload)
        => Task.Run(() => Encrypt(payload));

    public virtual Option<TP> Load(string persistenceKey, Persistence<TD> dataPersistence)
    {
        var drr = dataPersistence.Load(persistenceKey);
        return drr.HasValue ? Option<TP>.Some(Decrypt(drr.Value)) : Option<TP>.Empty;
    }

    public virtual string Store(TP payload, Persistence<TD> dataPersistence)
    {
        var drr = Encrypt(payload);
        var key = dataPersistence.GenerateKey(drr);
        dataPersistence.Store(key, drr);
        return key;
    }

    public virtual void Store(string key, TP payload, Persistence<TD> dataPersistence)
    {
        var drr = Encrypt(payload);
        dataPersistence.Store(key, drr);
    }
}

/// <summary>Simple optional value type matching the canonical SDK's Option.</summary>
public readonly struct Option<T>
{
    public static readonly Option<T> Empty = new();

    private readonly T? _value;
    public bool HasValue { get; }
    public T Value => HasValue ? _value! : throw new InvalidOperationException("No value");

    private Option(T value) { _value = value; HasValue = true; }

    public static Option<T> Some(T value) => new(value);
    public Option<TU> Map<TU>(Func<T, TU> mapper) =>
        HasValue ? Option<TU>.Some(mapper(_value!)) : Option<TU>.Empty;
}
