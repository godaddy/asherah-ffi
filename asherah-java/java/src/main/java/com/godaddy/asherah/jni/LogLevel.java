package com.godaddy.asherah.jni;

/**
 * Severity level of a log event delivered to a registered log hook.
 * Mirrors the Rust {@code log::Level}.
 */
public enum LogLevel {
    /** Verbose tracing output, typically off in production. */
    TRACE,
    /** Debug-level diagnostic output. */
    DEBUG,
    /** Informational events. */
    INFO,
    /** Recoverable issues that may require attention. */
    WARN,
    /** Errors that may indicate misconfiguration or operational failure. */
    ERROR;

    /** Parse the lowercase string representation (the form delivered by the JNI bridge). */
    public static LogLevel fromString(String s) {
        if (s == null) return ERROR;
        switch (s) {
            case "trace": return TRACE;
            case "debug": return DEBUG;
            case "info":  return INFO;
            case "warn":  return WARN;
            case "error": return ERROR;
            default:      return ERROR;
        }
    }
}
