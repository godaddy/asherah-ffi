package com.godaddy.asherah.jni;

import java.util.Objects;

/**
 * Single metrics event delivered to a registered {@link AsherahMetricsHook}.
 *
 * <p>Constructed by the JNI bridge whenever the underlying Rust crate emits a
 * metrics observation. {@code type} is one of {@code "encrypt"}, {@code "decrypt"},
 * {@code "store"}, {@code "load"}, {@code "cache_hit"}, {@code "cache_miss"},
 * {@code "cache_stale"}.
 *
 * <p>For timing events ({@code encrypt}, {@code decrypt}, {@code store},
 * {@code load}), {@link #getDurationNs()} carries the elapsed nanoseconds and
 * {@link #getName()} is {@code null}. For cache events, {@code durationNs} is
 * {@code 0} and {@code name} carries the cache identifier.
 */
public final class MetricsEvent {
    private final String type;
    private final long durationNs;
    private final String name;

    /** Invoked from JNI; not intended for application code. */
    public MetricsEvent(String type, long durationNs, String name) {
        this.type = Objects.requireNonNullElse(type, "encrypt");
        this.durationNs = durationNs;
        this.name = name;
    }

    /** Lowercase string form of the event type. */
    public String getType() {
        return type;
    }

    /** Typed event type enum, parsed from {@link #getType()}. */
    public MetricsEventType getTypeEnum() {
        return MetricsEventType.fromString(type);
    }

    /** Elapsed time in nanoseconds for timing events; {@code 0} for cache events. */
    public long getDurationNs() {
        return durationNs;
    }

    /** Cache name for cache events; {@code null} for timing events. */
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return "MetricsEvent{type=" + type + ", durationNs=" + durationNs + ", name=" + name + "}";
    }
}
