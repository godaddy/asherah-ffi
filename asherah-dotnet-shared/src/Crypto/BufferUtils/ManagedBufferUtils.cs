using System.Runtime.CompilerServices;

namespace GoDaddy.Asherah.Crypto.BufferUtils;

public static class ManagedBufferUtils
{
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static void WipeByteArray(byte[] sensitiveData)
    {
        if (sensitiveData.Length == 0)
        {
            return;
        }
        System.Array.Clear(sensitiveData, 0, sensitiveData.Length);
    }
}
