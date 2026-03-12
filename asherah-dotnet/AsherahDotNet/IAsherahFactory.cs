using System;

namespace GoDaddy.Asherah;

public interface IAsherahFactory : IDisposable
{
    IAsherahSession GetSession(string partitionId);
}
