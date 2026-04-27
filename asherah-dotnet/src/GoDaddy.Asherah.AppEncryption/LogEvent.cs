namespace GoDaddy.Asherah;

/// <summary>
/// Severity level of a log event delivered to a registered log hook.
/// Mirrors the Rust <c>log::Level</c>.
/// </summary>
public enum LogLevel
{
    /// <summary>Verbose tracing output, typically off in production.</summary>
    Trace = 0,
    /// <summary>Debug-level diagnostic output.</summary>
    Debug = 1,
    /// <summary>Informational events.</summary>
    Info = 2,
    /// <summary>Recoverable issues that may require attention.</summary>
    Warn = 3,
    /// <summary>Errors that may indicate misconfiguration or operational failure.</summary>
    Error = 4,
}

/// <summary>
/// A structured log event delivered to a callback registered with
/// <see cref="Asherah.SetLogHook"/>.
/// </summary>
/// <param name="Level">Severity level.</param>
/// <param name="Target">Source module / target string (typically the Rust
/// module path that emitted the log). Useful for filtering.</param>
/// <param name="Message">Formatted log message.</param>
public sealed record LogEvent(LogLevel Level, string Target, string Message);
