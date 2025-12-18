namespace GoDaddy.Asherah.Crypto.Envelope;

public class EnvelopeEncryptResult<T> where T : class
{
    public byte[] CipherText { get; set; } = Array.Empty<byte>();
    public byte[] EncryptedKey { get; set; } = Array.Empty<byte>();
    public T? UserState { get; set; }
}

public class EnvelopeEncryptResult : EnvelopeEncryptResult<object>
{
}
