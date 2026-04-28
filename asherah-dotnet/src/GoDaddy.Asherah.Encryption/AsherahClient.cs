using System.Threading.Tasks;

namespace GoDaddy.Asherah;

public sealed class AsherahClient : IAsherah
{
    public void Setup(AsherahConfig config) => Asherah.Setup(config);
    public Task SetupAsync(AsherahConfig config) => Asherah.SetupAsync(config);
    public void Shutdown() => Asherah.Shutdown();
    public Task ShutdownAsync() => Asherah.ShutdownAsync();
    public bool GetSetupStatus() => Asherah.GetSetupStatus();

    public byte[] Encrypt(string partitionId, byte[] plaintext) =>
        Asherah.Encrypt(partitionId, plaintext);

    public string EncryptString(string partitionId, string plaintext) =>
        Asherah.EncryptString(partitionId, plaintext);

    public Task<byte[]> EncryptAsync(string partitionId, byte[] plaintext) =>
        Asherah.EncryptAsync(partitionId, plaintext);

    public Task<string> EncryptStringAsync(string partitionId, string plaintext) =>
        Asherah.EncryptStringAsync(partitionId, plaintext);

    public byte[] Decrypt(string partitionId, byte[] dataRowRecordJson) =>
        Asherah.Decrypt(partitionId, dataRowRecordJson);

    public byte[] DecryptJson(string partitionId, string dataRowRecordJson) =>
        Asherah.DecryptJson(partitionId, dataRowRecordJson);

    public string DecryptString(string partitionId, string dataRowRecordJson) =>
        Asherah.DecryptString(partitionId, dataRowRecordJson);

    public Task<byte[]> DecryptAsync(string partitionId, byte[] dataRowRecordJson) =>
        Asherah.DecryptAsync(partitionId, dataRowRecordJson);

    public Task<string> DecryptStringAsync(string partitionId, string dataRowRecordJson) =>
        Asherah.DecryptStringAsync(partitionId, dataRowRecordJson);

    public void SetLogHook(System.Action<LogEvent>? callback) =>
        Asherah.SetLogHook(callback);
    public void SetMetricsHook(System.Action<MetricsEvent>? callback) =>
        Asherah.SetMetricsHook(callback);
}
