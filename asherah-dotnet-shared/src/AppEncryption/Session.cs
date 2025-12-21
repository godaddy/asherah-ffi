using System;
using System.Threading.Tasks;
using GoDaddy.Asherah.AppEncryption.Persistence;
using LanguageExt;

namespace GoDaddy.Asherah.AppEncryption;

public abstract class Session<TP, TD> : IDisposable
{
    public abstract void Dispose();
    public abstract TP Decrypt(TD dataRowRecord);
    public abstract TD Encrypt(TP payLoad);
    public abstract Task<TP> DecryptAsync(TD dataRowRecord);
    public abstract Task<TD> EncryptAsync(TP payLoad);

    public virtual Option<TP> Load(string persistenceKey, Persistence<TD> dataPersistence)
    {
        return dataPersistence.Load(persistenceKey).Map(Decrypt);
    }

    public virtual string Store(TP payload, Persistence<TD> dataPersistence)
    {
        TD dataRowRecord = Encrypt(payload);
        return dataPersistence.Store(dataRowRecord);
    }

    public virtual void Store(string key, TP payload, Persistence<TD> dataPersistence)
    {
        TD dataRowRecord = Encrypt(payload);
        dataPersistence.Store(key, dataRowRecord);
    }
}
