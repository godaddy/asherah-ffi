package com.godaddy.asherah.jni;

/**
 * Functional interface for receiving log events from the underlying Asherah
 * native library. Register an instance via
 * {@link Asherah#setLogHook(AsherahLogHook)}; clear it with
 * {@link Asherah#clearLogHook()}.
 *
 * <p>The callback may fire from any thread (tokio worker threads, DB driver
 * threads). Implementations must be thread-safe and should never block — if you
 * forward events to a logging framework, make sure the appender is non-blocking.
 *
 * <p>Exceptions thrown from {@link #onLog(LogEvent)} are caught and silently
 * swallowed by the JNI bridge so they cannot propagate across the FFI boundary
 * and crash the JVM.
 */
@FunctionalInterface
public interface AsherahLogHook {
    /** Invoked once per log record. {@code event} is never {@code null}. */
    void onLog(LogEvent event);
}
