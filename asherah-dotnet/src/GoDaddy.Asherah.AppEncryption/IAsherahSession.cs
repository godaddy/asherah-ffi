using System;
using System.Threading.Tasks;

namespace GoDaddy.Asherah;

public interface IAsherahSession : IDisposable
{
    byte[] EncryptBytes(byte[] plaintext);
    string EncryptString(string plaintext);
    byte[] DecryptBytes(byte[] ciphertextJson);
    string DecryptString(string ciphertextJson);
    Task<byte[]> EncryptBytesAsync(byte[] plaintext);
    Task<string> EncryptStringAsync(string plaintext);
    Task<byte[]> DecryptBytesAsync(byte[] ciphertextJson);
    Task<string> DecryptStringAsync(string ciphertextJson);
}
