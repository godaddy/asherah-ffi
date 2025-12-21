using System;
using GoDaddy.Asherah.AppEncryption.Util;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AsherahDotNet.SharedTests;

public class JsonHelperTests
{
    [Fact]
    public void Json_PutAndGet_RoundTrip()
    {
        var json = new Json();
        json.Put("str", "value");
        json.Put("bool", true);
        json.Put("bytes", new byte[] { 1, 2, 3 });
        var now = DateTimeOffset.UtcNow;
        json.Put("created", now);
        json.Put("obj", new JObject { ["nested"] = "x" });

        Assert.Equal("value", json.GetString("str"));
        Assert.True(json.GetOptionalBoolean("bool").IfNone(false));
        Assert.Equal(new byte[] { 1, 2, 3 }, json.GetBytes("bytes"));
        Assert.Equal(now.ToUnixTimeSeconds(), json.GetDateTimeOffset("created").ToUnixTimeSeconds());
        Assert.Equal("x", json.GetJson("obj").GetString("nested"));
    }
}
