package com.godaddy.asherah.jni;

import java.util.Objects;

/**
 * Single log event delivered to a registered {@link AsherahLogHook}.
 *
 * <p>Constructed by the JNI bridge on every log record emitted by the underlying
 * Rust crates. The {@code level} is one of {@code "trace"}, {@code "debug"},
 * {@code "info"}, {@code "warn"}, {@code "error"} — use {@link LogLevel#fromString(String)}
 * to convert to the typed enum.
 */
public final class LogEvent {
    private final String level;
    private final String target;
    private final String message;

    /** Invoked from JNI; not intended for application code. */
    public LogEvent(String level, String target, String message) {
        this.level = Objects.requireNonNullElse(level, "error");
        this.target = Objects.requireNonNullElse(target, "");
        this.message = Objects.requireNonNullElse(message, "");
    }

    /** Lowercase string form of the level (matches {@link LogLevel#fromString(String)}). */
    public String getLevel() {
        return level;
    }

    /** Typed level enum, parsed from {@link #getLevel()}. */
    public LogLevel getLevelEnum() {
        return LogLevel.fromString(level);
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
}
