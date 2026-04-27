package com.godaddy.asherah.jni;

import java.util.Objects;
import org.slf4j.event.Level;

/**
 * Single log event delivered to a registered {@link AsherahLogHook}.
 *
 * <p>Constructed by the JNI bridge on every log record emitted by the underlying
 * Rust crates. Severity is exposed as the industry-standard SLF4J
 * {@link org.slf4j.event.Level} so consumers can pass the level straight into
 * any SLF4J-compatible logger without translation.
 */
public final class LogEvent {
    private final Level level;
    private final String target;
    private final String message;

    /** Invoked from JNI; not intended for application code. */
    public LogEvent(String level, String target, String message) {
        this.level = parseLevel(level);
        this.target = Objects.requireNonNullElse(target, "");
        this.message = Objects.requireNonNullElse(message, "");
    }

    /** Severity as the SLF4J {@link Level} (TRACE/DEBUG/INFO/WARN/ERROR). */
    public Level getLevel() {
        return level;
    }

    /** Logging target/module path (e.g. {@code "asherah::session"}). */
    public String getTarget() {
        return target;
    }

    /** Formatted log message. */
    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return "LogEvent{level=" + level + ", target=" + target + ", message=" + message + "}";
    }

    private static Level parseLevel(String s) {
        if (s == null) return Level.ERROR;
        switch (s) {
            case "trace": return Level.TRACE;
            case "debug": return Level.DEBUG;
            case "info":  return Level.INFO;
            case "warn":  return Level.WARN;
            case "error": return Level.ERROR;
            default:      return Level.ERROR;
        }
    }
}
