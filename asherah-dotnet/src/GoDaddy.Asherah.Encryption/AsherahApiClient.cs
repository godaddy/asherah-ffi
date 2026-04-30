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
    /// <inheritdoc />
    public void Setup(AsherahConfig config) => AsherahApi.Setup(config);

    /// <inheritdoc />
    public Task SetupAsync(AsherahConfig config) => AsherahApi.SetupAsync(config);

    /// <inheritdoc />
    public void Shutdown() => AsherahApi.Shutdown();

    /// <inheritdoc />
    public Task ShutdownAsync() => AsherahApi.ShutdownAsync();

    /// <inheritdoc />
    public bool GetSetupStatus() => AsherahApi.GetSetupStatus();

    /// <inheritdoc />
    public byte[] Encrypt(string partitionId, byte[] plaintext) =>
        AsherahApi.Encrypt(partitionId, plaintext);

    /// <inheritdoc />
    public string EncryptString(string partitionId, string plaintext) =>
        AsherahApi.EncryptString(partitionId, plaintext);

    /// <inheritdoc />
    public Task<byte[]> EncryptAsync(string partitionId, byte[] plaintext) =>
        AsherahApi.EncryptAsync(partitionId, plaintext);

    /// <inheritdoc />
    public Task<string> EncryptStringAsync(string partitionId, string plaintext) =>
        AsherahApi.EncryptStringAsync(partitionId, plaintext);

    /// <inheritdoc />
    public byte[] Decrypt(string partitionId, byte[] dataRowRecordJson) =>
        AsherahApi.Decrypt(partitionId, dataRowRecordJson);

    /// <inheritdoc />
    public byte[] DecryptJson(string partitionId, string dataRowRecordJson) =>
        AsherahApi.DecryptJson(partitionId, dataRowRecordJson);

    /// <inheritdoc />
    public string DecryptString(string partitionId, string dataRowRecordJson) =>
        AsherahApi.DecryptString(partitionId, dataRowRecordJson);

    /// <inheritdoc />
    public Task<byte[]> DecryptAsync(string partitionId, byte[] dataRowRecordJson) =>
        AsherahApi.DecryptAsync(partitionId, dataRowRecordJson);

    /// <inheritdoc />
    public Task<string> DecryptStringAsync(string partitionId, string dataRowRecordJson) =>
        AsherahApi.DecryptStringAsync(partitionId, dataRowRecordJson);

    /// <inheritdoc />
    public void SetLogHook(System.Action<LogEvent>? callback) =>
        AsherahHooks.SetLogHook(callback);

    /// <inheritdoc />
    public void SetMetricsHook(System.Action<MetricsEvent>? callback) =>
        AsherahHooks.SetMetricsHook(callback);
}
