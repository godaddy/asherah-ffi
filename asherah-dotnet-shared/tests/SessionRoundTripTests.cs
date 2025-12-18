using System.Text;
using GoDaddy.Asherah.AppEncryption;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AsherahDotNet.SharedTests;

public class SessionRoundTripTests
{
    static SessionRoundTripTests()
    {
        TestHelpers.EnsureNativeLibraryConfigured();
    }

    [Fact]
    public void BytesSession_RoundTrip()
    {
        using SessionFactory factory = TestHelpers.CreateSessionFactory();
        using Session<byte[], byte[]> session = factory.GetSessionBytes("partition-bytes");

        byte[] payload = Encoding.UTF8.GetBytes("hello");
        byte[] drr = session.Encrypt(payload);
        byte[] decrypted = session.Decrypt(drr);

        Assert.Equal(payload, decrypted);
    }

    [Fact]
    public void JsonSession_RoundTrip()
    {
        using SessionFactory factory = TestHelpers.CreateSessionFactory();
        using Session<JObject, byte[]> session = factory.GetSessionJson("partition-json");

        JObject payload = new JObject { ["foo"] = "bar" };
        byte[] drr = session.Encrypt(payload);
        JObject decrypted = session.Decrypt(drr);

        Assert.Equal("bar", decrypted.Value<string>("foo"));
    }
}
