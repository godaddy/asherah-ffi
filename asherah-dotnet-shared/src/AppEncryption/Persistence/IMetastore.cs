using System;
using LanguageExt;

namespace GoDaddy.Asherah.AppEncryption.Persistence;

public interface IMetastore<T>
{
    Option<T> Load(string keyId, DateTimeOffset created);
    Option<T> LoadLatest(string keyId);
    bool Store(string keyId, DateTimeOffset created, T value);
    string GetKeySuffix();
}
