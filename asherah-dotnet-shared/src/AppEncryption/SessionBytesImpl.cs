using System;
using System.Threading.Tasks;
using GoDaddy.Asherah.AppEncryption.Envelope;
using Microsoft.Extensions.Logging;

namespace GoDaddy.Asherah.AppEncryption;

public class SessionBytesImpl<TD> : Session<byte[], TD>
{
    private readonly ILogger? _logger;
    private readonly IEnvelopeEncryption<TD> _envelopeEncryption;

    public SessionBytesImpl(IEnvelopeEncryption<TD> envelopeEncryption, ILogger? logger)
    {
        _envelopeEncryption = envelopeEncryption;
        _logger = logger;
    }

    public SessionBytesImpl(IEnvelopeEncryption<TD> envelopeEncryption)
        : this(envelopeEncryption, null)
    {
    }

    public override byte[] Decrypt(TD dataRowRecord) => _envelopeEncryption.DecryptDataRowRecord(dataRowRecord);

    public override TD Encrypt(byte[] payload) => _envelopeEncryption.EncryptPayload(payload);

    public override Task<byte[]> DecryptAsync(TD dataRowRecord) => Task.FromResult(Decrypt(dataRowRecord));

    public override Task<TD> EncryptAsync(byte[] payload) => Task.FromResult(Encrypt(payload));

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
