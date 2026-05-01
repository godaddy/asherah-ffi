using System.Text;
using GoDaddy.Asherah.AppEncryption.Persistence;
using LanguageExt;
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
    /// <summary>Releases native session resources.</summary>
    public abstract void Dispose();

    /// <summary>Decrypts an encrypted data row record to a payload.</summary>
    /// <param name="dataRowRecord">Serialized envelope (bytes or JSON, depending on session flavor).</param>
    public abstract TP Decrypt(TD dataRowRecord);

    /// <summary>Encrypts <paramref name="payload"/> into a data row record.</summary>
    public abstract TD Encrypt(TP payload);

    /// <summary>Asynchronously decrypts; default implementation offloads <see cref="Decrypt"/>.</summary>
    public virtual Task<TP> DecryptAsync(TD dataRowRecord)
        => Task.Run(() => Decrypt(dataRowRecord));

    /// <summary>Asynchronously encrypts; default implementation offloads <see cref="Encrypt"/>.</summary>
    public virtual Task<TD> EncryptAsync(TP payload)
        => Task.Run(() => Encrypt(payload));

    /// <summary>Loads ciphertext from persistence and decrypts when present.</summary>
    /// <returns><see cref="Option{T}.Some"/> when a stored record exists.</returns>
    public virtual Option<TP> Load(string persistenceKey, Persistence<TD> dataPersistence)
    {
        var drr = dataPersistence.Load(persistenceKey);
        return drr.Map(d => Decrypt(d));
    }

    /// <summary>Encrypts and stores under a newly generated persistence key.</summary>
    /// <returns>The generated key.</returns>
    public virtual string Store(TP payload, Persistence<TD> dataPersistence)
    {
        var drr = Encrypt(payload);
        var key = dataPersistence.GenerateKey(drr);
        dataPersistence.Store(key, drr);
        return key;
    }

    /// <summary>Encrypts and stores under the given persistence key.</summary>
    public virtual void Store(string key, TP payload, Persistence<TD> dataPersistence)
    {
        var drr = Encrypt(payload);
        dataPersistence.Store(key, drr);
    }
}
