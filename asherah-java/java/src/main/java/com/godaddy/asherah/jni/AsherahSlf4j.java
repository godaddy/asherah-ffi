package com.godaddy.asherah.jni;

import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;

/**
 * SLF4J helpers for Asherah log forwarding.
 *
 * <p>The common case — forwarding all Asherah records to a single
 * {@link Logger} — is wired directly:
 *
 * <pre>
 *   Asherah.setLogHook(LoggerFactory.getLogger("asherah"));
 * </pre>
 *
 * <p>For per-target dispatch (each Rust source target like
 * {@code asherah::session}, {@code asherah::builders} routed to its own
 * {@code Logger} so host-side filter rules can match by category), use
 * {@link #logHook(ILoggerFactory)}:
 *
 * <pre>
 *   Asherah.setLogHook(AsherahSlf4j.logHook(LoggerFactory.getILoggerFactory()));
 * </pre>
 */
public final class AsherahSlf4j {
    private AsherahSlf4j() {}

    /**
     * Build an {@link AsherahLogHook} that resolves a target-specific
     * {@link Logger} from the supplied factory and forwards each record to
     * it. Loggers are cached per target.
     */
    public static AsherahLogHook logHook(final ILoggerFactory factory) {
        Objects.requireNonNull(factory, "factory");
        final ConcurrentHashMap<String, Logger> cache = new ConcurrentHashMap<>();
        return event -> {
            Logger logger = cache.computeIfAbsent(event.getTarget(), factory::getLogger);
            Asherah.adaptLogger(logger).onLog(event);
        };
    }
}
