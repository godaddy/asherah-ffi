using System;
using GoDaddy.Asherah.AppEncryption;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.Crypto;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AsherahDotNet.SharedTests;

public class SessionFactoryBuilderTests
{
    [Fact]
    public void Build_SucceedsWithRequiredComponents()
    {
        var builder = SessionFactory.NewBuilder("prod", "svc")
            .WithMetastore(new InMemoryMetastoreImpl<JObject>())
            .WithCryptoPolicy(new NeverExpiredCryptoPolicy())
            .WithKeyManagementService(new StaticKeyManagementServiceImpl(new string('a', 32)));

        using SessionFactory factory = builder.Build();
        Assert.NotNull(factory);
    }
}
