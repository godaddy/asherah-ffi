using System;
using System.Threading.Tasks;
using GoDaddy.Asherah.AppEncryption.Util;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption.Envelope;

public sealed class EnvelopeEncryptionBytesImpl : IEnvelopeEncryption<byte[]>
{
    private readonly ILogger? _logger;
    private readonly IEnvelopeEncryption<JObject> _jsonEnvelope;

    public EnvelopeEncryptionBytesImpl(IEnvelopeEncryption<JObject> envelopeEncryptionJson, ILogger? logger)
    {
        _jsonEnvelope = envelopeEncryptionJson;
        _logger = logger;
    }

    public EnvelopeEncryptionBytesImpl(IEnvelopeEncryption<JObject> envelopeEncryptionJson)
        : this(envelopeEncryptionJson, null)
    {
    }

    public void Dispose()
    {
        try
        {
            _jsonEnvelope.Dispose();
        }
        catch (Exception e)
        {
            _logger?.LogError(e, "Unexpected exception during dispose");
        }
    }

    public byte[] DecryptDataRowRecord(byte[] dataRowRecord)
    {
        Json dataRowRecordJson = new Json(dataRowRecord);
        return _jsonEnvelope.DecryptDataRowRecord(dataRowRecordJson.ToJObject());
    }

    public byte[] EncryptPayload(byte[] payload)
    {
        Json drrJson = new Json(_jsonEnvelope.EncryptPayload(payload));
        return drrJson.ToUtf8();
    }

    public Task<byte[]> DecryptDataRowRecordAsync(byte[] dataRowRecord) =>
        Task.FromResult(DecryptDataRowRecord(dataRowRecord));

    public Task<byte[]> EncryptPayloadAsync(byte[] payload) =>
        Task.FromResult(EncryptPayload(payload));
}
