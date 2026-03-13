#![allow(clippy::unwrap_used)]

//! Unit tests for public library functions.

use asherah_server::parse_go_duration;

// ============================================================
// parse_go_duration
// ============================================================

#[test]
fn duration_minutes() {
    assert_eq!(parse_go_duration("90m").unwrap(), 5400);
    assert_eq!(parse_go_duration("10m").unwrap(), 600);
    assert_eq!(parse_go_duration("1m").unwrap(), 60);
    assert_eq!(parse_go_duration("0m").unwrap(), 0);
}

#[test]
fn duration_hours() {
    assert_eq!(parse_go_duration("2h").unwrap(), 7200);
    assert_eq!(parse_go_duration("1h").unwrap(), 3600);
    assert_eq!(parse_go_duration("24h").unwrap(), 86400);
    assert_eq!(parse_go_duration("0h").unwrap(), 0);
}

#[test]
fn duration_seconds() {
    assert_eq!(parse_go_duration("300s").unwrap(), 300);
    assert_eq!(parse_go_duration("1s").unwrap(), 1);
    assert_eq!(parse_go_duration("0s").unwrap(), 0);
    assert_eq!(parse_go_duration("86400s").unwrap(), 86400);
}

#[test]
fn duration_bare_number_as_seconds() {
    assert_eq!(parse_go_duration("300").unwrap(), 300);
    assert_eq!(parse_go_duration("0").unwrap(), 0);
    assert_eq!(parse_go_duration("1").unwrap(), 1);
    assert_eq!(parse_go_duration("86400").unwrap(), 86400);
}

#[test]
fn duration_whitespace_trimmed() {
    assert_eq!(parse_go_duration(" 90m ").unwrap(), 5400);
    assert_eq!(parse_go_duration("  2h  ").unwrap(), 7200);
    assert_eq!(parse_go_duration("\t300s\n").unwrap(), 300);
    assert_eq!(parse_go_duration("  42  ").unwrap(), 42);
}

#[test]
fn duration_negative() {
    // Negative durations are valid i64 parses — we don't block them
    assert_eq!(parse_go_duration("-1m").unwrap(), -60);
    assert_eq!(parse_go_duration("-2h").unwrap(), -7200);
    assert_eq!(parse_go_duration("-300s").unwrap(), -300);
    assert_eq!(parse_go_duration("-10").unwrap(), -10);
}

#[test]
fn duration_invalid_empty() {
    assert!(parse_go_duration("").is_err());
    assert!(parse_go_duration("   ").is_err());
}

#[test]
fn duration_invalid_no_number() {
    assert!(parse_go_duration("m").is_err());
    assert!(parse_go_duration("h").is_err());
    assert!(parse_go_duration("s").is_err());
}

#[test]
fn duration_invalid_non_numeric() {
    assert!(parse_go_duration("abc").is_err());
    assert!(parse_go_duration("12.5m").is_err());
    assert!(parse_go_duration("1.5h").is_err());
    assert!(parse_go_duration("hello").is_err());
}

#[test]
fn duration_invalid_mixed() {
    // We don't support compound durations like Go's "1h30m"
    assert!(parse_go_duration("1h30m").is_err());
    assert!(parse_go_duration("1m30s").is_err());
}

#[test]
fn duration_large_values() {
    assert_eq!(parse_go_duration("999999h").unwrap(), 999999 * 3600);
    assert_eq!(parse_go_duration("99999999").unwrap(), 99999999);
}
