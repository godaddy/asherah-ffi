using System;

namespace GoDaddy.Asherah.Crypto.ExtensionMethods;

public static class DateTimeOffsetExtensions
{
    public static DateTimeOffset Truncate(this DateTimeOffset dateTimeOffset, TimeSpan timeSpan)
    {
        if (timeSpan == TimeSpan.Zero)
        {
            return dateTimeOffset;
        }

        if (dateTimeOffset == DateTimeOffset.MinValue || dateTimeOffset == DateTimeOffset.MaxValue)
        {
            return dateTimeOffset;
        }

        return dateTimeOffset.AddTicks(-(dateTimeOffset.Ticks % timeSpan.Ticks));
    }
}
