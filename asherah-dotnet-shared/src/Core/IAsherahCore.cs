using System;

namespace GoDaddy.Asherah.Internal;

internal interface IAsherahCore : IDisposable
{
    byte[] EncryptToJson(string partitionId, byte[] plaintext);
    byte[] DecryptFromJson(string partitionId, byte[] json);
}
