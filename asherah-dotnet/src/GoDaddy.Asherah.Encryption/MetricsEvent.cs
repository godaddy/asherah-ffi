namespace GoDaddy.Asherah.Encryption;

/// <summary>
/// Type of metrics event delivered to a callback registered with
/// <see cref="Asherah.SetMetricsHook"/>. Timing events
/// (<see cref="Encrypt"/>, <see cref="Decrypt"/>, <see cref="Store"/>,
/// <see cref="Load"/>) carry <see cref="MetricsEvent.DurationNs"/>; cache
/// events (<see cref="CacheHit"/>, <see cref="CacheMiss"/>,
/// <see cref="CacheStale"/>) carry <see cref="MetricsEvent.Name"/>.
/// </summary>
public enum MetricsEventType
{
    /// <summary>An encrypt operation completed; <see cref="MetricsEvent.DurationNs"/> is the elapsed time.</summary>
    Encrypt = 0,
    /// <summary>A decrypt operation completed; <see cref="MetricsEvent.DurationNs"/> is the elapsed time.</summary>
    Decrypt = 1,
    /// <summary>A metastore store operation completed; <see cref="MetricsEvent.DurationNs"/> is the elapsed time.</summary>
    Store = 2,
    /// <summary>A metastore load operation completed; <see cref="MetricsEvent.DurationNs"/> is the elapsed time.</summary>
    Load = 3,
    /// <summary>A key cache hit; <see cref="MetricsEvent.Name"/> identifies the cache.</summary>
    CacheHit = 4,
    /// <summary>A key cache miss; <see cref="MetricsEvent.Name"/> identifies the cache.</summary>
    CacheMiss = 5,
    /// <summary>A key cache stale entry was evicted; <see cref="MetricsEvent.Name"/> identifies the cache.</summary>
    CacheStale = 6,
}

/// <summary>
/// A metrics event delivered to a callback registered with
/// <see cref="Asherah.SetMetricsHook"/>.
/// </summary>
/// <param name="Type">The event type.</param>
/// <param name="DurationNs">Elapsed time in nanoseconds for timing events.
/// Zero for cache events.</param>
/// <param name="Name">Cache name for cache events. Null for timing events.</param>
public sealed record MetricsEvent(MetricsEventType Type, ulong DurationNs, string? Name);
