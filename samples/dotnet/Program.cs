using System.Text;
using GoDaddy.Asherah;

// Testing only — production must use AWS KMS.
Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX",
    "2222222222222222222222222222222222222222222222222222222222222222");

var config = AsherahConfig.CreateBuilder()
    .WithServiceName("sample-service")
    .WithProductId("sample-product")
    .WithMetastore("memory")         // testing only — use "mysql", "postgres", or "dynamodb"
    .WithKms("static")               // testing only — use "aws" with RegionMap
    .WithEnableSessionCaching(true)
    .Build();

// --- 1. Static API (simplest, manages sessions internally) ---

Asherah.Setup(config);
try
{
    // String encrypt/decrypt
    var cipher = Asherah.EncryptString("partition-1", "Hello from .NET!");
    Console.WriteLine($"Static string:  {Asherah.DecryptString("partition-1", cipher)}");

    // Byte encrypt/decrypt
    var cipherBytes = Asherah.Encrypt("partition-1", Encoding.UTF8.GetBytes("byte payload"));
    Console.WriteLine($"Static bytes:   {Encoding.UTF8.GetString(Asherah.Decrypt("partition-1", cipherBytes))}");
}
finally
{
    Asherah.Shutdown();
}

// --- 2. Factory/Session API (recommended — explicit session lifecycle) ---

using (var factory = Asherah.FactoryFromConfig(config))
{
    using (var session = factory.GetSession("partition-2"))
    {
        var encrypted = session.EncryptString("Factory/Session example");
        Console.WriteLine($"Session string: {session.DecryptString(encrypted)}");

        var encBytes = session.EncryptBytes(Encoding.UTF8.GetBytes("session bytes"));
        Console.WriteLine($"Session bytes:  {Encoding.UTF8.GetString(session.DecryptBytes(encBytes))}");
    }
}

// --- 3. Async API (true async via Rust tokio — does not block .NET thread pool) ---

await RunAsyncExample();

static async Task RunAsyncExample()
{
    var cfg = AsherahConfig.CreateBuilder()
        .WithServiceName("sample-service")
        .WithProductId("sample-product")
        .WithMetastore("memory")
        .WithKms("static")
        .WithEnableSessionCaching(true)
        .Build();

    // Static async
    Asherah.Setup(cfg);
    try
    {
        var cipher = await Asherah.EncryptStringAsync("partition-3", "async static");
        Console.WriteLine($"Async static:   {await Asherah.DecryptStringAsync("partition-3", cipher)}");
    }
    finally
    {
        Asherah.Shutdown();
    }

    // Session async
    using var factory = Asherah.FactoryFromConfig(cfg);
    using var session = factory.GetSession("partition-4");
    var enc = await session.EncryptBytesAsync(Encoding.UTF8.GetBytes("async session"));
    Console.WriteLine($"Async session:  {Encoding.UTF8.GetString(await session.DecryptBytesAsync(enc))}");
}

// --- 4. Production config (uncomment and fill in real values) ---
//
// var prodConfig = AsherahConfig.CreateBuilder()
//     .WithServiceName("my-service")
//     .WithProductId("my-product")
//     .WithMetastore("mysql")
//     .WithConnectionString("server=db.example.com;database=asherah;user=app;password=secret")
//     .WithKms("aws")
//     .WithRegionMap(new Dictionary<string, string>
//     {
//         ["us-west-2"] = "arn:aws:kms:us-west-2:111122223333:key/example-key-id",
//     })
//     .WithPreferredRegion("us-west-2")
//     .WithEnableSessionCaching(true)
//     .WithSessionCacheMaxSize(1000)
//     .WithSessionCacheDuration(120)
//     .Build();
