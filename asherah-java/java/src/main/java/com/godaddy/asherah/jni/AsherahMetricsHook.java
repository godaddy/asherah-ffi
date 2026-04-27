package com.godaddy.asherah.jni;

/**
 * Functional interface for receiving metrics events from the underlying Asherah
 * native library. Register an instance via
 * {@link Asherah#setMetricsHook(AsherahMetricsHook)}; clear it with
 * {@link Asherah#clearMetricsHook()}.
 *
 * <p>Installing a hook implicitly enables the global metrics gate; clearing it
 * disables the gate. Per-factory metrics are always enabled by the JNI bridge
 * so an installed hook always fires.
 *
 * <p>The callback may fire from any thread (tokio worker threads, DB driver
 * threads). Implementations must be thread-safe and should never block.
 *
 * <p>Exceptions thrown from {@link #onMetric(MetricsEvent)} are caught and
 * silently swallowed by the JNI bridge so they cannot propagate across the FFI
 * boundary and crash the JVM.
 */
@FunctionalInterface
public interface AsherahMetricsHook {
    /** Invoked once per metrics event. {@code event} is never {@code null}. */
    void onMetric(MetricsEvent event);
}
