using System;
using System.Text;
using GoDaddy.Asherah.AppEncryption;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AsherahDotNet.SharedTests;

public class JsonShapeTests
{
    static JsonShapeTests()
    {
        TestHelpers.EnsureNativeLibraryConfigured();
    }

    [Fact]
    public void Encrypt_EmitsDataRowRecordJsonShape()
    {
        using SessionFactory factory = TestHelpers.CreateSessionFactory();
        using Session<byte[], JObject> session = factory.GetSessionBytesAsJson("partition-json-shape");

        byte[] payload = Encoding.UTF8.GetBytes("shape");
        JObject drr = session.Encrypt(payload);

        Assert.NotNull(drr["Data"]);
        Assert.NotNull(drr["Key"]);
        string dataBase64 = drr.Value<string>("Data")!;
        _ = Convert.FromBase64String(dataBase64);

        JObject key = drr.Value<JObject>("Key")!;
        Assert.NotNull(key["Created"]);
        Assert.NotNull(key["Key"]);
    }
}
