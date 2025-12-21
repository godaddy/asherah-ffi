using System;

namespace GoDaddy.Asherah.AppEncryption;

public class SuffixedPartition : Partition
{
    private readonly string _regionSuffix;

    public SuffixedPartition(string partitionId, string serviceId, string productId, string regionSuffix)
        : base(partitionId, serviceId, productId)
    {
        _regionSuffix = regionSuffix;
    }

    public override string SystemKeyId => base.SystemKeyId + "_" + _regionSuffix;

    public override string IntermediateKeyId => base.IntermediateKeyId + "_" + _regionSuffix;

    public override string ToString()
    {
        return GetType().Name + "[partitionId=" + PartitionId +
               ", serviceId=" + ServiceId + ", productId=" + ProductId + ", regionSuffix=" + _regionSuffix + "]";
    }

    public override bool IsValidIntermediateKeyId(string keyId)
    {
        return keyId.Equals(IntermediateKeyId, StringComparison.Ordinal)
            || keyId.StartsWith(base.IntermediateKeyId, StringComparison.Ordinal);
    }
}
