using Amazon;
using Amazon.KeyManagementService;
using Amazon.Runtime;

namespace GoDaddy.Asherah.AppEncryption.Kms;

public class AwsKmsClientFactory
{
    internal virtual IAmazonKeyManagementService CreateAwsKmsClient(string region, AWSCredentials credentials)
    {
        return new AmazonKeyManagementServiceClient(credentials, RegionEndpoint.GetBySystemName(region));
    }
}
