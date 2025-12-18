using System;
using System.Threading.Tasks;

namespace GoDaddy.Asherah.AppEncryption.Envelope;

public interface IEnvelopeEncryption<TD> : IDisposable
{
    byte[] DecryptDataRowRecord(TD dataRowRecord);
    TD EncryptPayload(byte[] payload);
    Task<byte[]> DecryptDataRowRecordAsync(TD dataRowRecord);
    Task<TD> EncryptPayloadAsync(byte[] payload);
}
