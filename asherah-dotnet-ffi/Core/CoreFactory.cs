using GoDaddy.Asherah.Internal;

namespace GoDaddy.Asherah.Internal;

internal static class CoreFactory
{
    internal static IAsherahCore Create(ConfigOptions config)
    {
        return new FfiCore(config);
    }
}
