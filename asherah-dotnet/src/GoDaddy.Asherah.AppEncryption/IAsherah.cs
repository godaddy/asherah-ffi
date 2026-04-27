using System;
using System.Threading.Tasks;

namespace GoDaddy.Asherah;

public interface IAsherah
{
    void Setup(AsherahConfig config);
    Task SetupAsync(AsherahConfig config);
    void Shutdown();
    Task ShutdownAsync();
    bool GetSetupStatus();

    byte[] Encrypt(string partitionId, byte[] plaintext);
    string EncryptString(string partitionId, string plaintext);
    Task<byte[]> EncryptAsync(string partitionId, byte[] plaintext);
    Task<string> EncryptStringAsync(string partitionId, string plaintext);

    byte[] Decrypt(string partitionId, byte[] dataRowRecordJson);
    byte[] DecryptJson(string partitionId, string dataRowRecordJson);
    string DecryptString(string partitionId, string dataRowRecordJson);
    Task<byte[]> DecryptAsync(string partitionId, byte[] dataRowRecordJson);
    Task<string> DecryptStringAsync(string partitionId, string dataRowRecordJson);

    /// <summary>
    /// Register or unregister a structured-event log callback that fires for
    /// every log event from the Rust core. Pass <c>null</c> to deregister.
    /// </summary>
    void SetLogHook(Action<LogEvent>? callback);

    /// <summary>
    /// Register or unregister a metrics callback that fires for every
    /// encrypt/decrypt/store/load timing event and key cache
    /// hit/miss/stale event. Pass <c>null</c> to deregister.
    /// </summary>
    void SetMetricsHook(Action<MetricsEvent>? callback);
}
