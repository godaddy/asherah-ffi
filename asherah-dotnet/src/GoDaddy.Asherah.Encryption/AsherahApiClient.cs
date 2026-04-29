using System.Threading.Tasks;

namespace GoDaddy.Asherah.Encryption;

/// <summary>
/// Default implementation of <see cref="IAsherahApi"/>. Forwards every
/// call to the corresponding <see cref="AsherahApi"/> static method. Use
/// when you want a DI-friendly handle for the single-shot API
/// (constructor injection, mock-able in tests).
/// </summary>
public sealed class AsherahApiClient : IAsherahApi
{
    public void Setup(AsherahConfig config) => AsherahApi.Setup(config);
    public Task SetupAsync(AsherahConfig config) => AsherahApi.SetupAsync(config);
    public void Shutdown() => AsherahApi.Shutdown();
    public Task ShutdownAsync() => AsherahApi.ShutdownAsync();
    public bool GetSetupStatus() => AsherahApi.GetSetupStatus();

    public byte[] Encrypt(string partitionId, byte[] plaintext) =>
        AsherahApi.Encrypt(partitionId, plaintext);

    public string EncryptString(string partitionId, string plaintext) =>
        AsherahApi.EncryptString(partitionId, plaintext);

    public Task<byte[]> EncryptAsync(string partitionId, byte[] plaintext) =>
        AsherahApi.EncryptAsync(partitionId, plaintext);

    public Task<string> EncryptStringAsync(string partitionId, string plaintext) =>
        AsherahApi.EncryptStringAsync(partitionId, plaintext);

    public byte[] Decrypt(string partitionId, byte[] dataRowRecordJson) =>
        AsherahApi.Decrypt(partitionId, dataRowRecordJson);

    public byte[] DecryptJson(string partitionId, string dataRowRecordJson) =>
        AsherahApi.DecryptJson(partitionId, dataRowRecordJson);

    public string DecryptString(string partitionId, string dataRowRecordJson) =>
        AsherahApi.DecryptString(partitionId, dataRowRecordJson);

    public Task<byte[]> DecryptAsync(string partitionId, byte[] dataRowRecordJson) =>
        AsherahApi.DecryptAsync(partitionId, dataRowRecordJson);

    public Task<string> DecryptStringAsync(string partitionId, string dataRowRecordJson) =>
        AsherahApi.DecryptStringAsync(partitionId, dataRowRecordJson);

    public void SetLogHook(System.Action<LogEvent>? callback) =>
        AsherahHooks.SetLogHook(callback);

    public void SetMetricsHook(System.Action<MetricsEvent>? callback) =>
        AsherahHooks.SetMetricsHook(callback);
}
