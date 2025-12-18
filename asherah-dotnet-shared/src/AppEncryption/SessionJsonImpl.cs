using System;
using System.Threading.Tasks;
using GoDaddy.Asherah.AppEncryption.Envelope;
using GoDaddy.Asherah.AppEncryption.Util;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption;

public class SessionJsonImpl<TD> : Session<JObject, TD>
{
    private readonly ILogger? _logger;
    private readonly IEnvelopeEncryption<TD> _envelopeEncryption;

    public SessionJsonImpl(IEnvelopeEncryption<TD> envelopeEncryption, ILogger? logger)
    {
        _envelopeEncryption = envelopeEncryption;
        _logger = logger;
    }

    public SessionJsonImpl(IEnvelopeEncryption<TD> envelopeEncryption)
        : this(envelopeEncryption, null)
    {
    }

    public override JObject Decrypt(TD dataRowRecord)
    {
        byte[] jsonAsUtf8Bytes = _envelopeEncryption.DecryptDataRowRecord(dataRowRecord);
        return new Json(jsonAsUtf8Bytes).ToJObject();
    }

    public override TD Encrypt(JObject payload)
    {
        byte[] jsonAsUtf8Bytes = new Json(payload).ToUtf8();
        return _envelopeEncryption.EncryptPayload(jsonAsUtf8Bytes);
    }

    public override Task<JObject> DecryptAsync(TD dataRowRecord) => Task.FromResult(Decrypt(dataRowRecord));

    public override Task<TD> EncryptAsync(JObject payload) => Task.FromResult(Encrypt(payload));

    public override void Dispose()
    {
        try
        {
            _envelopeEncryption.Dispose();
        }
        catch (Exception e)
        {
            _logger?.LogError(e, "unexpected exception during close");
        }
    }
}
