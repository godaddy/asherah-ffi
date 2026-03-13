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
/// Supports: "90m" (minutes), "2h" (hours), "300s" (seconds), "300" (bare seconds).
pub fn parse_go_duration(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if let Some(rest) = s.strip_suffix('h') {
        rest.parse::<i64>()
            .map(|n| n * 3600)
            .map_err(|e| e.to_string())
    } else if let Some(rest) = s.strip_suffix('m') {
        rest.parse::<i64>()
            .map(|n| n * 60)
            .map_err(|e| e.to_string())
    } else if let Some(rest) = s.strip_suffix('s') {
        rest.parse::<i64>().map_err(|e| e.to_string())
    } else {
        s.parse::<i64>().map_err(|e| e.to_string())
    }
}
