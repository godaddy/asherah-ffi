using System;
using System.Collections.Generic;
using Amazon.Runtime;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.Crypto;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.Internal;

internal static class ConfigBuilder
{
    internal static ConfigOptions BuildConfig(
        string serviceId,
        string productId,
        IMetastore<JObject> metastore,
        CryptoPolicy cryptoPolicy,
        IKeyManagementService keyManagementService)
    {
        var config = new ConfigOptions
        {
            ServiceName = serviceId,
            ProductId = productId,
        };

        ApplyCryptoPolicy(config, cryptoPolicy);
        ApplyMetastore(config, metastore);
        ApplyKms(config, keyManagementService);

        return config;
    }

    private static void ApplyCryptoPolicy(ConfigOptions config, CryptoPolicy cryptoPolicy)
    {
        if (cryptoPolicy is BasicExpiringCryptoPolicy basic)
        {
            config.ExpireAfter = MillisToSeconds(basic.KeyExpirationMillis);
            config.CheckInterval = MillisToSeconds(basic.RevokeCheckMillis);
        }
        else if (cryptoPolicy is NeverExpiredCryptoPolicy)
        {
            config.ExpireAfter = null;
            config.CheckInterval = null;
        }
        else
        {
            config.CheckInterval = MillisToSeconds(cryptoPolicy.GetRevokeCheckPeriodMillis());
        }

        config.EnableSessionCaching = cryptoPolicy.CanCacheSessions();
        if (cryptoPolicy.CanCacheSessions())
        {
            config.SessionCacheMaxSize = ClampToInt(cryptoPolicy.GetSessionCacheMaxSize());
            config.SessionCacheDuration = MillisToSeconds(cryptoPolicy.GetSessionCacheExpireMillis());
        }
    }

    private static void ApplyMetastore(ConfigOptions config, IMetastore<JObject> metastore)
    {
        switch (metastore)
        {
            case InMemoryMetastoreImpl<JObject>:
                config.Metastore = "memory";
                return;
            case AdoMetastoreImpl ado:
                config.Metastore = "rdbms";
                config.ConnectionString = ado.ConnectionString;
                return;
            case DynamoDbMetastoreImpl dynamo:
                if (dynamo.DbClient != null)
                {
                    throw new NotSupportedException(
                        "DynamoDbMetastoreImpl.WithDynamoDbClient is not supported by native core");
                }
                ApplyAwsCredentials(dynamo.Credentials);
                config.Metastore = "dynamodb";
                config.DynamoDbTableName = dynamo.TableName;
                config.DynamoDbEndpoint = dynamo.Endpoint;
                config.DynamoDbRegion = dynamo.Region ?? dynamo.PreferredRegion;
                config.EnableRegionSuffix = dynamo.HasKeySuffix;
                return;
            default:
                throw new NotSupportedException($"Metastore type {metastore.GetType().Name} is not supported by native core");
        }
    }

    private static void ApplyKms(ConfigOptions config, IKeyManagementService keyManagementService)
    {
        switch (keyManagementService)
        {
            case StaticKeyManagementServiceImpl staticKms:
                config.Kms = "static";
                config.StaticMasterKeyHex = ConvertStaticKeyToHex(staticKms.StaticMasterKey);
                return;
            case AwsKeyManagementServiceImpl aws:
                ApplyAwsCredentials(aws.Credentials);
                config.Kms = "aws";
                config.RegionMap = new Dictionary<string, string>(aws.RegionMap);
                config.PreferredRegion = aws.PreferredRegion;
                return;
            default:
                throw new NotSupportedException(
                    $"KeyManagementService type {keyManagementService.GetType().Name} is not supported by native core");
        }
    }

    private static string ConvertStaticKeyToHex(string value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(value);
        if (bytes.Length != 32)
        {
            throw new InvalidOperationException("Static master key must be 32 bytes when UTF-8 encoded");
        }

        return BytesToHex(bytes);
    }

    private static string BytesToHex(byte[] bytes)
    {
        var result = new char[bytes.Length * 2];
        int idx = 0;
        foreach (byte b in bytes)
        {
            result[idx++] = GetHexValue(b / 16);
            result[idx++] = GetHexValue(b % 16);
        }
        return new string(result);
    }

    private static char GetHexValue(int value)
    {
        return (char)(value < 10 ? value + 48 : value - 10 + 97);
    }

    private static void ApplyAwsCredentials(AWSCredentials? credentials)
    {
        if (credentials == null)
        {
            return;
        }

        ImmutableCredentials imm = credentials.GetCredentials();
        if (!string.IsNullOrEmpty(imm.AccessKey))
        {
            Environment.SetEnvironmentVariable("AWS_ACCESS_KEY_ID", imm.AccessKey);
        }
        if (!string.IsNullOrEmpty(imm.SecretKey))
        {
            Environment.SetEnvironmentVariable("AWS_SECRET_ACCESS_KEY", imm.SecretKey);
        }
        if (string.IsNullOrEmpty(imm.Token))
        {
            Environment.SetEnvironmentVariable("AWS_SESSION_TOKEN", null);
        }
        else
        {
            Environment.SetEnvironmentVariable("AWS_SESSION_TOKEN", imm.Token);
        }
    }

    private static long MillisToSeconds(long millis)
    {
        if (millis <= 0)
        {
            return 0;
        }
        return millis / 1000;
    }

    private static int? ClampToInt(long value)
    {
        if (value <= 0)
        {
            return null;
        }
        return value > int.MaxValue ? int.MaxValue : (int)value;
    }
}
