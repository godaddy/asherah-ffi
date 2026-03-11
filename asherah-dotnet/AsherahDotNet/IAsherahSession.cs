using System;

namespace GoDaddy.Asherah;

public interface IAsherahSession : IDisposable
{
    byte[] EncryptBytes(byte[] plaintext);
    string EncryptString(string plaintext);
    byte[] DecryptBytes(byte[] ciphertextJson);
    string DecryptString(string ciphertextJson);
}
