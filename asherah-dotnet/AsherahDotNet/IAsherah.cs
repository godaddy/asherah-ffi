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
}
