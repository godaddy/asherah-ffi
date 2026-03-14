using GoDaddy.Asherah;

// A static master key for local development only.
// In production, use KMS: "aws" with a proper region map.
Environment.SetEnvironmentVariable("STATIC_MASTER_KEY_HEX",
    "2222222222222222222222222222222222222222222222222222222222222222");

var config = AsherahConfig.CreateBuilder()
    .WithServiceName("sample-service")
    .WithProductId("sample-product")
    .WithMetastore("memory")
    .WithKms("static")
    .WithEnableSessionCaching(true)
    .Build();

Asherah.Setup(config);
try
{
    // Encrypt
    var ciphertext = Asherah.EncryptString("sample-partition", "Hello from .NET!");
    Console.WriteLine($"Encrypted: {ciphertext[..Math.Min(80, ciphertext.Length)]}...");

    // Decrypt
    var recovered = Asherah.DecryptString("sample-partition", ciphertext);
    Console.WriteLine($"Decrypted: {recovered}");
}
finally
{
    Asherah.Shutdown();
}
