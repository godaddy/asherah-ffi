// Probe canonical GoDaddy.Asherah.AppEncryption to discover its actual
// behavior on null/empty inputs. Prints one line per probe in the form
// "<name>: <result>" so the Python interop test can assert on exact strings.
using System;
using System.Text;
using GoDaddy.Asherah.AppEncryption;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.Crypto;

var policy = BasicExpiringCryptoPolicy.NewBuilder()
    .WithKeyExpirationDays(90)
    .WithRevokeCheckMinutes(60)
    .Build();

// canonical StaticKeyManagementServiceImpl expects a 32-byte UTF-8 string (AES-256 key bytes)
var kms = new StaticKeyManagementServiceImpl("01234567890123456789012345678901");

using var factory = SessionFactory
    .NewBuilder("product", "service")
    .WithInMemoryMetastore()
    .WithCryptoPolicy(policy)
    .WithKeyManagementService(kms)
    .Build();

// Warm-up: do a non-empty encrypt first so the IK exists in the metastore.
// Otherwise every subsequent probe trips IK-creation paths and the error
// message is about "Unable to store IK" rather than the input validation
// we're actually probing.
using (var warm = factory.GetSessionBytes("p1"))
{
    warm.Encrypt(Encoding.UTF8.GetBytes("warmup"));
}

// 1) GetSession with null partition id — and try to actually use it
Probe("GetSessionBytes_null_partition", () =>
{
    using var s = factory.GetSessionBytes(null!);
    return "accepted";
});

Probe("Encrypt_with_null_partition_session", () =>
{
    using var s = factory.GetSessionBytes(null!);
    var ct = s.Encrypt(Encoding.UTF8.GetBytes("payload"));
    // Parse the DRR JSON to see what KeyId was stored
    var json = Encoding.UTF8.GetString(ct);
    return $"accepted: drr={FirstLine(json)}";
});

// 2) GetSession with empty partition id — and try to actually use it
Probe("GetSessionBytes_empty_partition", () =>
{
    using var s = factory.GetSessionBytes("");
    return "accepted";
});

Probe("Encrypt_with_empty_partition_session", () =>
{
    using var s = factory.GetSessionBytes("");
    var ct = s.Encrypt(Encoding.UTF8.GetBytes("payload"));
    var json = Encoding.UTF8.GetString(ct);
    return $"accepted: drr={FirstLine(json)}";
});

// 3) Encrypt with null byte[]
Probe("Encrypt_null_bytes", () =>
{
    using var s = factory.GetSessionBytes("p1");
    var ct = s.Encrypt(null!);
    return $"accepted: ct_len={(ct == null ? -1 : ct.Length)}";
});

// 4) Encrypt with empty byte[]
Probe("Encrypt_empty_bytes", () =>
{
    using var s = factory.GetSessionBytes("p1");
    var ct = s.Encrypt(Array.Empty<byte>());
    return $"accepted: ct_len={ct.Length}";
});

// 5) Encrypt empty then Decrypt — round-trip
Probe("Roundtrip_empty_bytes", () =>
{
    using var s = factory.GetSessionBytes("p1");
    var ct = s.Encrypt(Array.Empty<byte>());
    var pt = s.Decrypt(ct);
    return $"recovered_len={pt.Length} null={pt == null}";
});

// 6) Decrypt with null
Probe("Decrypt_null", () =>
{
    using var s = factory.GetSessionBytes("p1");
    var pt = s.Decrypt(null!);
    return $"accepted: pt_len={(pt == null ? -1 : pt.Length)}";
});

// 7) Decrypt with empty byte[]
Probe("Decrypt_empty_bytes", () =>
{
    using var s = factory.GetSessionBytes("p1");
    var pt = s.Decrypt(Array.Empty<byte>());
    return $"accepted: pt_len={pt.Length}";
});

static void Probe(string name, Func<string> fn)
{
    try
    {
        var result = fn();
        Console.WriteLine($"{name}: {result}");
    }
    catch (Exception ex)
    {
        var inner = ex.InnerException;
        var innerStr = inner == null ? "" : $" inner={inner.GetType().Name}: {FirstLine(inner.Message)}";
        Console.WriteLine($"{name}: ERROR: {ex.GetType().Name}: {FirstLine(ex.Message)}{innerStr}");
    }
}

static string FirstLine(string s)
{
    var i = s.IndexOf('\n');
    return i < 0 ? s : s.Substring(0, i);
}
