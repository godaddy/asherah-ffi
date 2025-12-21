using System;
using System.Text;
using System.Threading.Tasks;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.Crypto;
using GoDaddy.Asherah.Crypto.Envelope;
using GoDaddy.Asherah.Crypto.Keys;
using GoDaddy.Asherah.Internal;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption.Envelope;

public sealed class EnvelopeEncryptionJsonImpl : IEnvelopeEncryption<JObject>
{
    private readonly ILogger? _logger;
    private readonly IAsherahCore _core;
    private readonly string _partitionId;
    private readonly bool _ownsCore;

    public EnvelopeEncryptionJsonImpl(
        Partition partition,
        IMetastore<JObject> metastore,
        SecureCryptoKeyDictionary<DateTimeOffset> systemKeyCache,
        SecureCryptoKeyDictionary<DateTimeOffset> intermediateKeyCache,
        AeadEnvelopeCrypto aeadEnvelopeCrypto,
        CryptoPolicy cryptoPolicy,
        IKeyManagementService keyManagementService,
        ILogger logger)
        : this(partition, metastore, cryptoPolicy, keyManagementService, logger)
    {
    }

    public EnvelopeEncryptionJsonImpl(
        Partition partition,
        IMetastore<JObject> metastore,
        SecureCryptoKeyDictionary<DateTimeOffset> systemKeyCache,
        SecureCryptoKeyDictionary<DateTimeOffset> intermediateKeyCache,
        AeadEnvelopeCrypto aeadEnvelopeCrypto,
        CryptoPolicy cryptoPolicy,
        IKeyManagementService keyManagementService)
        : this(partition, metastore, cryptoPolicy, keyManagementService, null)
    {
    }

    internal EnvelopeEncryptionJsonImpl(IAsherahCore core, string partitionId, ILogger? logger = null)
    {
        _core = core;
        _partitionId = partitionId;
        _logger = logger;
        _ownsCore = false;
    }

    internal EnvelopeEncryptionJsonImpl()
    {
        _core = null!;
        _partitionId = string.Empty;
        _ownsCore = false;
    }

    private EnvelopeEncryptionJsonImpl(
        Partition partition,
        IMetastore<JObject> metastore,
        CryptoPolicy cryptoPolicy,
        IKeyManagementService keyManagementService,
        ILogger? logger)
    {
        _partitionId = partition.PartitionId;
        _logger = logger;
        var config = ConfigBuilder.BuildConfig(partition.ServiceId, partition.ProductId, metastore, cryptoPolicy, keyManagementService);
        _core = CoreFactory.Create(config);
        _ownsCore = true;
    }

    public byte[] DecryptDataRowRecord(JObject dataRowRecord)
    {
        var jsonBytes = Encoding.UTF8.GetBytes(dataRowRecord.ToString());
        return _core.DecryptFromJson(_partitionId, jsonBytes);
    }

    public JObject EncryptPayload(byte[] payload)
    {
        var jsonBytes = _core.EncryptToJson(_partitionId, payload);
        return JObject.Parse(Encoding.UTF8.GetString(jsonBytes));
    }

    public Task<byte[]> DecryptDataRowRecordAsync(JObject dataRowRecord) =>
        Task.FromResult(DecryptDataRowRecord(dataRowRecord));

    public Task<JObject> EncryptPayloadAsync(byte[] payload) =>
        Task.FromResult(EncryptPayload(payload));

    public void Dispose()
    {
        if (!_ownsCore)
        {
            return;
        }

        try
        {
            _core.Dispose();
        }
        catch (Exception e)
        {
            _logger?.LogError(e, "Unexpected exception during dispose");
        }
    }
}
