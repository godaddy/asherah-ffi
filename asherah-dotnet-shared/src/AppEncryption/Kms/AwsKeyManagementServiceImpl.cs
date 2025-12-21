using System;
using System.Collections.Generic;
using Amazon.Runtime;
using GoDaddy.Asherah.Crypto.Keys;
using Microsoft.Extensions.Logging;

namespace GoDaddy.Asherah.AppEncryption.Kms;

public class AwsKeyManagementServiceImpl : KeyManagementService
{
    internal AwsKeyManagementServiceImpl(Builder builder)
    {
        RegionMap = builder.RegionMap;
        PreferredRegion = builder.PreferredRegion;
        Credentials = builder.Credentials;
        Logger = builder.Logger;
    }

    internal Dictionary<string, string> RegionMap { get; }
    internal string PreferredRegion { get; }
    internal AWSCredentials? Credentials { get; }
    internal ILogger? Logger { get; }

    public static Builder NewBuilder(Dictionary<string, string> regionToArnDictionary, string region) =>
        new(regionToArnDictionary, region);

    public override byte[] EncryptKey(CryptoKey key) =>
        throw new NotSupportedException("AwsKeyManagementServiceImpl is configuration-only when using native core");

    public override CryptoKey DecryptKey(byte[] keyCipherText, DateTimeOffset keyCreated, bool revoked) =>
        throw new NotSupportedException("AwsKeyManagementServiceImpl is configuration-only when using native core");

    public interface IBuildStep
    {
        IBuildStep WithCredentials(AWSCredentials credentials);
        IBuildStep WithLogger(ILogger logger);
        AwsKeyManagementServiceImpl Build();
    }

    public class Builder : IBuildStep
    {
        internal Dictionary<string, string> RegionMap { get; }
        internal string PreferredRegion { get; }
        internal AWSCredentials? Credentials { get; private set; }
        internal ILogger? Logger { get; private set; }

        public Builder(Dictionary<string, string> regionToArnDictionary, string region)
        {
            RegionMap = new Dictionary<string, string>(regionToArnDictionary);
            PreferredRegion = region;
        }

        public IBuildStep WithCredentials(AWSCredentials credentials)
        {
            Credentials = credentials;
            return this;
        }

        public IBuildStep WithLogger(ILogger logger)
        {
            Logger = logger;
            return this;
        }

        public AwsKeyManagementServiceImpl Build() => new(this);
    }
}
