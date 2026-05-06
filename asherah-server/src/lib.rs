#[cfg(not(unix))]
compile_error!("asherah-server requires Unix (Linux/macOS) for Unix domain socket support");

pub mod convert;
pub mod service;

#[allow(
    clippy::all,
    missing_debug_implementations,
    trivial_casts,
    unused_qualifications
)]
pub mod proto {
    tonic::include_proto!("asherah.apps.server");
}

/// Parse a Go-style duration string into seconds.
///
/// Supports compound forms like `"1h30m"`, `"2h45m30s"`, plus the simple
/// suffixed forms (`"90m"`, `"2h"`, `"300s"`, bare `"300"` for seconds).
/// Each component must use exactly one of `h`/`m`/`s`. The bare-integer
/// shorthand still works only for the entire input (no mixing with
/// suffixed components).
///
/// Asherah ships configuration parity with the canonical Go reference,
/// which uses Go's `time.ParseDuration` semantics — compound forms are
/// the common case in real configs (T-finding "parse_go_duration rejects
/// compound durations" in `docs/review-2026-05-05-findings.md`).
pub fn parse_go_duration(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("duration is empty".to_string());
    }
    // Bare integer: interpret as seconds.
    if s.bytes()
        .all(|b| b.is_ascii_digit() || b == b'-' || b == b'+')
    {
        return s.parse::<i64>().map_err(|e| e.to_string());
    }

    let mut total_s: i64 = 0;
    let mut digits = String::new();
    let mut saw_component = false;
    for ch in s.chars() {
        if ch.is_ascii_digit() || ch == '-' || ch == '+' {
            digits.push(ch);
            continue;
        }
        let unit_secs: i64 = match ch {
            'h' | 'H' => 3600,
            'm' | 'M' => 60,
            's' | 'S' => 1,
            other => return Err(format!("unsupported duration unit '{other}' in '{s}'")),
        };
        if digits.is_empty() {
            return Err(format!(
                "duration unit '{ch}' has no preceding number in '{s}'"
            ));
        }
        let n: i64 = digits
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let component = n
            .checked_mul(unit_secs)
            .ok_or_else(|| format!("duration component '{digits}{ch}' overflows i64"))?;
        total_s = total_s
            .checked_add(component)
            .ok_or_else(|| "duration overflow".to_string())?;
        digits.clear();
        saw_component = true;
    }
    if !digits.is_empty() {
        return Err(format!(
            "duration '{s}' ends with bare digits '{digits}' (expected unit suffix h/m/s)"
        ));
    }
    if !saw_component {
        return Err(format!("duration '{s}' has no recognized unit"));
    }
    Ok(total_s)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_go_duration_bare_seconds() {
        assert_eq!(parse_go_duration("300").unwrap(), 300);
        assert_eq!(parse_go_duration("0").unwrap(), 0);
    }

    #[test]
    fn parse_go_duration_simple_suffixes() {
        assert_eq!(parse_go_duration("90m").unwrap(), 5400);
        assert_eq!(parse_go_duration("2h").unwrap(), 7200);
        assert_eq!(parse_go_duration("45s").unwrap(), 45);
    }

    #[test]
    fn parse_go_duration_compound() {
        assert_eq!(parse_go_duration("1h30m").unwrap(), 5400);
        assert_eq!(parse_go_duration("2h45m30s").unwrap(), 9930);
        assert_eq!(parse_go_duration("0h0m0s").unwrap(), 0);
    }

    #[test]
    fn parse_go_duration_rejects_unknown_units() {
        assert!(parse_go_duration("5d").is_err());
        assert!(parse_go_duration("100ms").is_err());
        assert!(parse_go_duration("").is_err());
        assert!(parse_go_duration("abc").is_err());
        assert!(parse_go_duration("1h30").is_err()); // trailing bare digits
    }
}
