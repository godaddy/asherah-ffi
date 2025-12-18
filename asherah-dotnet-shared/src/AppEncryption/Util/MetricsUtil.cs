using System;
using App.Metrics;

namespace GoDaddy.Asherah.AppEncryption.Util;

public static class MetricsUtil
{
    public const string AelMetricsPrefix = "ael";

    private static volatile IMetrics? metricsInstance;

    public static IMetrics MetricsInstance
    {
        get
        {
            if (metricsInstance == null)
            {
                throw new ArgumentNullException(nameof(metricsInstance), "metricsInstance not initialized");
            }

            return metricsInstance;
        }
    }

    public static void SetMetricsInstance(IMetrics metricsInstance)
    {
        MetricsUtil.metricsInstance = metricsInstance;
    }
}
