namespace GoDaddy.Asherah.Internal;

internal static class CoreFactory
{
    internal static IAsherahCore Create(ConfigOptions config)
    {
#if ASHERAH_FFI
        return new FfiCore(config);
#elif ASHERAH_COBHAN
        return new CobhanCore(config);
#else
        throw new System.NotSupportedException("No native core selected");
#endif
    }
}
