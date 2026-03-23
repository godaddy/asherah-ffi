using System.Text;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption;

internal class SessionBytesImpl<TD> : Session<byte[], TD>
{
    private readonly AsherahSession _inner;
    private readonly bool _drrIsJson;

    internal SessionBytesImpl(AsherahSession inner, bool drrIsJson)
    {
        _inner = inner;
        _drrIsJson = drrIsJson;
    }

    public override TD Encrypt(byte[] payload)
    {
        var drrJson = Encoding.UTF8.GetString(_inner.EncryptBytes(payload));
        if (_drrIsJson)
            return (TD)(object)JObject.Parse(drrJson);
        return (TD)(object)Encoding.UTF8.GetBytes(drrJson);
    }

    public override byte[] Decrypt(TD dataRowRecord)
    {
        string drrJson;
        if (dataRowRecord is JObject jobj)
            drrJson = jobj.ToString(Newtonsoft.Json.Formatting.None);
        else
            drrJson = Encoding.UTF8.GetString((byte[])(object)dataRowRecord!);

        return _inner.DecryptBytes(Encoding.UTF8.GetBytes(drrJson));
    }

    public override void Dispose() => _inner.Dispose();
}
