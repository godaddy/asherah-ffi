using System;
using System.Text;
using GoDaddy.Asherah.AppEncryption;
using Xunit;

namespace AsherahDotNet.SharedTests;

public class SqlServerIntegrationTests
{
    static SqlServerIntegrationTests()
    {
        TestHelpers.EnsureNativeLibraryConfigured();
    }

    [Fact]
    public void SqlServerMetastore_RoundTrip()
    {
        string? conn = Environment.GetEnvironmentVariable("MSSQL_URL");
        if (string.IsNullOrWhiteSpace(conn))
        {
            return;
        }

        using SessionFactory factory = TestHelpers.CreateSessionFactory();
        using Session<byte[], byte[]> session = factory.GetSessionBytes("partition-sqlserver");

        byte[] payload = Encoding.UTF8.GetBytes("sqlserver roundtrip");
        byte[] drr = session.Encrypt(payload);
        byte[] decrypted = session.Decrypt(drr);

        Assert.Equal(payload, decrypted);
    }
}
