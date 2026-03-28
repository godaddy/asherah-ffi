using System.Text;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption;

internal class SessionJsonImpl<TD> : Session<JObject, TD>
{
    private readonly AsherahSession _inner;
    private readonly bool _drrIsJson;

    internal SessionJsonImpl(AsherahSession inner, bool drrIsJson)
    {
        _inner = inner;
        _drrIsJson = drrIsJson;
    }

    public override TD Encrypt(JObject payload)
    {
        var data = Encoding.UTF8.GetBytes(payload.ToString(Newtonsoft.Json.Formatting.None));
        var drrJson = Encoding.UTF8.GetString(_inner.EncryptBytes(data));
        if (_drrIsJson)
            return (TD)(object)JObject.Parse(drrJson);
        return (TD)(object)Encoding.UTF8.GetBytes(drrJson);
    }

    public override JObject Decrypt(TD dataRowRecord)
    {
        var drrJson = dataRowRecord is JObject jobj
            ? jobj.ToString(Newtonsoft.Json.Formatting.None)
            : Encoding.UTF8.GetString((byte[])(object)dataRowRecord!);
        var plaintext = _inner.DecryptBytes(Encoding.UTF8.GetBytes(drrJson));
        return JObject.Parse(Encoding.UTF8.GetString(plaintext));
    }

    public override void Dispose() => _inner.Dispose();
}
