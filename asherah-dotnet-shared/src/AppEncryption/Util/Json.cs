using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using LanguageExt;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption.Util;

public class Json
{
    private readonly JObject _document;

    public Json()
    {
        _document = new JObject();
    }

    public Json(JObject jObject)
    {
        _document = jObject ?? throw new ArgumentException("jObject is null");
    }

    public Json(byte[] utf8Json)
    {
        _document = ConvertUtf8ToJson(utf8Json);
    }

    public Json GetJson(string key)
    {
        return new Json(_document.GetValue(key)!.ToObject<JObject>()!);
    }

    public Option<Json> GetOptionalJson(string key)
    {
        return _document.TryGetValue(key, out JToken? result)
            ? new Json(result!.ToObject<JObject>()!)
            : Option<Json>.None;
    }

    public string GetString(string key)
    {
        return _document.GetValue(key)!.ToObject<string>()!;
    }

    public byte[] GetBytes(string key)
    {
        return Convert.FromBase64String(_document.GetValue(key)!.ToObject<string>()!);
    }

    public DateTimeOffset GetDateTimeOffset(string key)
    {
        long unixTime = _document.GetValue(key)!.ToObject<long>();
        return DateTimeOffset.FromUnixTimeSeconds(unixTime);
    }

    public Option<bool> GetOptionalBoolean(string key)
    {
        return _document.TryGetValue(key, out JToken? result)
            ? result!.ToObject<Option<bool>>()
            : Option<bool>.None;
    }

    public JArray GetJsonArray(string key)
    {
        return _document.GetValue(key)!.ToObject<JArray>()!;
    }

    public void Put(string key, DateTimeOffset dateTimeOffset)
    {
        _document.Add(key, dateTimeOffset.ToUnixTimeSeconds());
    }

    public void Put(string key, string text)
    {
        _document.Add(key, text);
    }

    public void Put(string key, byte[] bytes)
    {
        _document.Add(key, Convert.ToBase64String(bytes));
    }

    public void Put(string key, JObject jObject)
    {
        _document.Add(key, jObject);
    }

    public void Put(string key, Json json)
    {
        _document.Add(key, json.ToJObject());
    }

    public void Put(string key, bool value)
    {
        _document.Add(key, value);
    }

    public void Put(string key, List<JObject> jsonList)
    {
        _document.Add(key, JToken.FromObject(jsonList));
    }

    public string ToJsonString()
    {
        return _document.ToString(Formatting.None);
    }

    public byte[] ToUtf8()
    {
        return ConvertJsonToUtf8(_document);
    }

    public JObject ToJObject()
    {
        return _document;
    }

    private static byte[] ConvertJsonToUtf8(JObject jObject)
    {
        using var stream = new MemoryStream();
        using var writer = new StreamWriter(stream, new UTF8Encoding(false), 1024, true);
        using var jsonWriter = new JsonTextWriter(writer);
        var serializer = new JsonSerializer();
        serializer.Serialize(jsonWriter, jObject);
        jsonWriter.Flush();
        return stream.ToArray();
    }

    private static JObject ConvertUtf8ToJson(byte[] utf8Json)
    {
        using var stream = new MemoryStream(utf8Json);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        using var jsonReader = new JsonTextReader(reader);
        return JObject.Load(jsonReader);
    }
}
