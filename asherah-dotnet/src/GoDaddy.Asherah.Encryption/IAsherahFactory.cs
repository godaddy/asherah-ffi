using System;

namespace GoDaddy.Asherah.Encryption;

public interface IAsherahFactory : IDisposable
{
    IAsherahSession GetSession(string partitionId);
}
