using GoDaddy.Asherah.AppEncryption;
using Xunit;

namespace AsherahDotNet.SharedTests;

public class PartitionTests
{
    [Fact]
    public void DefaultPartition_KeyIds()
    {
        var partition = new DefaultPartition("part", "svc", "prod");
        Assert.Equal("_SK_svc_prod", partition.SystemKeyId);
        Assert.Equal("_IK_part_svc_prod", partition.IntermediateKeyId);
        Assert.True(partition.IsValidIntermediateKeyId("_IK_part_svc_prod"));
        Assert.False(partition.IsValidIntermediateKeyId("_IK_other_svc_prod"));
    }

    [Fact]
    public void SuffixedPartition_KeyIds()
    {
        var partition = new SuffixedPartition("part", "svc", "prod", "us-west-2");
        Assert.Equal("_SK_svc_prod_us-west-2", partition.SystemKeyId);
        Assert.Equal("_IK_part_svc_prod_us-west-2", partition.IntermediateKeyId);
        Assert.True(partition.IsValidIntermediateKeyId("_IK_part_svc_prod_us-west-2"));
        Assert.True(partition.IsValidIntermediateKeyId("_IK_part_svc_prod_us-west-2_extra"));
        Assert.False(partition.IsValidIntermediateKeyId("_IK_other_svc_prod_us-west-2"));
    }
}
