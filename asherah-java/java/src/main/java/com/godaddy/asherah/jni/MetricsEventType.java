package com.godaddy.asherah.jni;

/**
 * Type of metrics event delivered to a registered {@link AsherahMetricsHook}.
 *
 * <p>{@code ENCRYPT}, {@code DECRYPT}, {@code STORE}, and {@code LOAD} carry a
 * non-zero duration in nanoseconds. Cache events ({@code CACHE_HIT},
 * {@code CACHE_MISS}, {@code CACHE_STALE}) carry the cache name in
 * {@link MetricsEvent#getName()} and a duration of {@code 0}.
 */
public enum MetricsEventType {
    /** Time spent encrypting (DRR build, KMS, AEAD). */
    ENCRYPT,
    /** Time spent decrypting (KMS unwrap, AEAD). */
    DECRYPT,
    /** Time spent storing an envelope key in the metastore. */
    STORE,
    /** Time spent loading an envelope key from the metastore. */
    LOAD,
    /** A cache lookup served a fresh entry. */
    CACHE_HIT,
    /** A cache lookup missed (entry not present). */
    CACHE_MISS,
    /** A cache lookup found an expired/stale entry. */
    CACHE_STALE;

    /** Parse the lowercase string form delivered by the JNI bridge. */
    public static MetricsEventType fromString(String s) {
        if (s == null) return ENCRYPT;
        switch (s) {
            case "encrypt":     return ENCRYPT;
            case "decrypt":     return DECRYPT;
            case "store":       return STORE;
            case "load":        return LOAD;
            case "cache_hit":   return CACHE_HIT;
            case "cache_miss":  return CACHE_MISS;
            case "cache_stale": return CACHE_STALE;
            default:            return ENCRYPT;
        }
    }
}
