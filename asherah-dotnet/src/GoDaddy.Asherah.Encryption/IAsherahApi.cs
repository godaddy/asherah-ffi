using System;
using System.Threading.Tasks;

namespace GoDaddy.Asherah.Encryption;

/// <summary>
/// DI-friendly interface mirror of <see cref="AsherahApi"/>. Inject
/// <see cref="IAsherahApi"/> in services that want the single-shot
/// API but need testability or DI lifetime control. The default
/// implementation is <see cref="AsherahApiClient"/>, which forwards every
/// call to the corresponding <see cref="AsherahApi"/> static method.
/// </summary>
public interface IAsherahApi
{
    /// <inheritdoc cref="AsherahApi.Setup(AsherahConfig)"/>
    void Setup(AsherahConfig config);

    /// <inheritdoc cref="AsherahApi.SetupAsync(AsherahConfig)"/>
    Task SetupAsync(AsherahConfig config);

    /// <inheritdoc cref="AsherahApi.Shutdown"/>
    void Shutdown();

    /// <inheritdoc cref="AsherahApi.ShutdownAsync"/>
    Task ShutdownAsync();

    /// <inheritdoc cref="AsherahApi.GetSetupStatus"/>
    bool GetSetupStatus();

    /// <inheritdoc cref="AsherahApi.Encrypt(string, byte[])"/>
    byte[] Encrypt(string partitionId, byte[] plaintext);

    /// <inheritdoc cref="AsherahApi.EncryptString(string, string)"/>
    string EncryptString(string partitionId, string plaintext);

    /// <inheritdoc cref="AsherahApi.EncryptAsync(string, byte[])"/>
    Task<byte[]> EncryptAsync(string partitionId, byte[] plaintext);

    /// <inheritdoc cref="AsherahApi.EncryptStringAsync(string, string)"/>
    Task<string> EncryptStringAsync(string partitionId, string plaintext);

    /// <inheritdoc cref="AsherahApi.Decrypt(string, byte[])"/>
    byte[] Decrypt(string partitionId, byte[] dataRowRecordJson);

    /// <inheritdoc cref="AsherahApi.DecryptJson(string, string)"/>
    byte[] DecryptJson(string partitionId, string dataRowRecordJson);

    /// <inheritdoc cref="AsherahApi.DecryptString(string, string)"/>
    string DecryptString(string partitionId, string dataRowRecordJson);

    /// <inheritdoc cref="AsherahApi.DecryptAsync(string, byte[])"/>
    Task<byte[]> DecryptAsync(string partitionId, byte[] dataRowRecordJson);

    /// <inheritdoc cref="AsherahApi.DecryptStringAsync(string, string)"/>
    Task<string> DecryptStringAsync(string partitionId, string dataRowRecordJson);

    /// <inheritdoc cref="AsherahHooks.SetLogHook(Action{LogEvent})"/>
    void SetLogHook(Action<LogEvent>? callback);

    /// <inheritdoc cref="AsherahHooks.SetMetricsHook(Action{MetricsEvent})"/>
    void SetMetricsHook(Action<MetricsEvent>? callback);
}
