using Microsoft.Extensions.Logging;

namespace GoDaddy.Asherah.Encryption;

/// <summary>
/// A structured log event delivered to a callback registered with
/// <see cref="Asherah.SetLogHook(System.Action{LogEvent}?)"/>.
/// </summary>
/// <param name="Level">
/// Severity, mapped 1:1 from the underlying Rust <c>log::Level</c> onto the
/// industry-standard <see cref="LogLevel"/> enum from
/// <c>Microsoft.Extensions.Logging</c>. Asherah only emits Trace, Debug,
/// Information, Warning, and Error — Critical and None never appear in a
/// delivered event but are valid <c>minLevel</c> filter values (Critical or
/// None at the filter means "deliver nothing").
/// </param>
/// <param name="Target">Source module / target string (typically the Rust
/// module path that emitted the log, e.g. <c>asherah::session</c>). Useful
/// for filtering and as a logger category.</param>
/// <param name="Message">Formatted log message.</param>
public sealed record LogEvent(LogLevel Level, string Target, string Message);
