use anyhow::{Context, Result};
use asherah_server::{parse_go_duration, proto};
use clap::Parser;
use std::time::Duration;
use tonic::transport::Server;

#[derive(Parser, Debug)]
#[command(
    name = "asherah-server",
    about = "gRPC sidecar server for Asherah envelope encryption"
)]
struct Cli {
    /// The unix domain socket the server will listen on
    #[arg(
        short = 's',
        long,
        default_value = "/tmp/appencryption.sock",
        env = "ASHERAH_SOCKET_FILE"
    )]
    socket_file: String,

    /// File mode (octal) applied to the listening Unix socket after bind. The
    /// default `0660` restricts access to the owner and group; set explicitly
    /// to a wider mode (e.g. `0666`) only when you understand the local
    /// trust model. Any local UID with read/write on this socket can ask the
    /// sidecar to encrypt or decrypt arbitrary records.
    #[arg(
        long,
        default_value = "0660",
        value_parser = parse_octal_mode,
        env = "ASHERAH_SOCKET_MODE"
    )]
    socket_mode: u32,

    /// The name of this service
    #[arg(long, env = "ASHERAH_SERVICE_NAME")]
    service: String,

    /// The name of the product that owns this service
    #[arg(long, env = "ASHERAH_PRODUCT_NAME")]
    product: String,

    /// Determines the type of metastore to use for persisting keys
    #[arg(long, value_parser = ["rdbms", "dynamodb", "memory"], env = "ASHERAH_METASTORE_MODE")]
    metastore: String,

    /// The database connection string (required if --metastore=rdbms)
    #[arg(long, env = "ASHERAH_CONNECTION_STRING")]
    conn: Option<String>,

    /// Configures the master key management service
    #[arg(
        long,
        value_parser = ["aws", "static", "test-debug-static"],
        default_value = "aws",
        env = "ASHERAH_KMS_MODE"
    )]
    kms: String,

    /// A comma separated list of key-value pairs in the form of REGION1=ARN1[,REGION2=ARN2] (required if --kms=aws)
    #[arg(long, env = "ASHERAH_REGION_MAP")]
    region_map: Option<String>,

    /// The preferred AWS region (required if --kms=aws)
    #[arg(long, env = "ASHERAH_PREFERRED_REGION")]
    preferred_region: Option<String>,

    /// AWS shared-credentials profile name for KMS, DynamoDB, and Secrets Manager
    /// clients. When unset, the standard AWS credential chain (including
    /// AWS_PROFILE) is used.
    #[arg(long, env = "ASHERAH_AWS_PROFILE_NAME")]
    aws_profile_name: Option<String>,

    /// The amount of time a key is considered valid
    #[arg(long, value_parser = parse_go_duration, env = "ASHERAH_EXPIRE_AFTER")]
    expire_after: Option<i64>,

    /// The amount of time before cached keys are considered stale
    #[arg(long, value_parser = parse_go_duration, env = "ASHERAH_CHECK_INTERVAL")]
    check_interval: Option<i64>,

    /// Enable shared session caching (default: true)
    #[arg(long, default_value = "true", env = "ASHERAH_ENABLE_SESSION_CACHING")]
    enable_session_caching: bool,

    /// Define the maximum number of sessions to cache
    #[arg(long, default_value = "1000", env = "ASHERAH_SESSION_CACHE_MAX_SIZE")]
    session_cache_max_size: u32,

    /// The amount of time a session will remain cached
    #[arg(long, value_parser = parse_go_duration, default_value = "2h", env = "ASHERAH_SESSION_CACHE_DURATION")]
    session_cache_duration: i64,

    /// An optional endpoint URL (hostname only or fully qualified URI) (only supported by --metastore=dynamodb)
    #[arg(long, env = "ASHERAH_DYNAMODB_ENDPOINT")]
    dynamodb_endpoint: Option<String>,

    /// The AWS region for DynamoDB requests (defaults to globally configured region) (only supported by --metastore=dynamodb)
    #[arg(long, env = "ASHERAH_DYNAMODB_REGION")]
    dynamodb_region: Option<String>,

    /// The table name for DynamoDB (only supported by --metastore=dynamodb)
    #[arg(long, env = "ASHERAH_DYNAMODB_TABLE_NAME")]
    dynamodb_table_name: Option<String>,

    /// Required for Aurora sessions using write forwarding
    #[arg(long, value_parser = ["eventual", "global", "session"], env = "ASHERAH_REPLICA_READ_CONSISTENCY")]
    replica_read_consistency: Option<String>,

    /// Configure the metastore to use regional suffixes (only supported by --metastore=dynamodb)
    #[arg(long, env = "ASHERAH_ENABLE_REGION_SUFFIX")]
    enable_region_suffix: bool,

    /// Enable verbose logging output
    #[arg(short = 'v', long, env = "ASHERAH_VERBOSE")]
    verbose: bool,

    /// Maximum time (seconds) to wait for in-flight gRPC sessions to drain
    /// after a shutdown signal. After the timeout the server future is
    /// dropped and any still-running session tasks are abandoned. Accepts
    /// Go-style suffixes via `parse_go_duration` (e.g. `30s`, `2m`). The
    /// default preserves the previously-hard-coded value; raise it for
    /// long-lived streaming sessions.
    #[arg(
        long,
        value_parser = parse_go_duration,
        default_value = "5s",
        env = "ASHERAH_SHUTDOWN_DRAIN_TIMEOUT"
    )]
    shutdown_drain_timeout: i64,
}

/// Parse an octal file mode (e.g. `0660`, `660`, `0o660`) into a `u32` mode
/// suitable for `Permissions::from_mode`. Accepts an optional `0o` or `0`
/// prefix; rejects modes outside `0o000..=0o777`.
fn parse_octal_mode(s: &str) -> Result<u32, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("socket mode must not be empty".to_string());
    }
    let body = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
        .or_else(|| trimmed.strip_prefix('0'))
        .unwrap_or(trimmed);
    let body = if body.is_empty() { "0" } else { body };
    let mode = u32::from_str_radix(body, 8)
        .map_err(|_| format!("invalid octal socket mode '{trimmed}'"))?;
    if mode > 0o777 {
        return Err(format!(
            "socket mode {trimmed} (parsed as {mode:o}) exceeds 0o777"
        ));
    }
    Ok(mode)
}

/// Parse region map from Go-style `REGION1=ARN1[,REGION2=ARN2]` or JSON format.
fn parse_region_map(s: &str) -> Option<std::collections::HashMap<String, String>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(map) = serde_json::from_str(trimmed) {
        return Some(map);
    }
    let mut map = std::collections::HashMap::new();
    for pair in trimmed.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if k.is_empty() {
                log::warn!("region-map: ignoring entry with empty key: '{pair}'");
            } else if v.is_empty() {
                log::warn!("region-map: ignoring entry with empty value: '{pair}'");
            } else {
                map.insert(k.to_string(), v.to_string());
            }
        } else {
            log::warn!("region-map: ignoring malformed entry (missing '='): '{pair}'");
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

fn cli_to_config(cli: &Cli) -> asherah_config::ConfigOptions {
    let region_map = cli.region_map.as_deref().and_then(parse_region_map);

    asherah_config::ConfigOptions {
        service_name: Some(cli.service.clone()),
        product_id: Some(cli.product.clone()),
        metastore: Some(cli.metastore.clone()),
        connection_string: cli.conn.clone(),
        kms: Some(cli.kms.clone()),
        region_map,
        preferred_region: cli.preferred_region.clone(),
        aws_profile_name: cli.aws_profile_name.clone(),
        expire_after: cli.expire_after,
        check_interval: cli.check_interval,
        enable_session_caching: Some(cli.enable_session_caching),
        session_cache_max_size: Some(cli.session_cache_max_size),
        session_cache_duration: Some(cli.session_cache_duration),
        dynamo_db_endpoint: cli.dynamodb_endpoint.clone(),
        dynamo_db_region: cli.dynamodb_region.clone(),
        dynamo_db_table_name: cli.dynamodb_table_name.clone(),
        replica_read_consistency: cli.replica_read_consistency.clone(),
        enable_region_suffix: Some(cli.enable_region_suffix),
        verbose: Some(cli.verbose),
        ..Default::default()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if cli.verbose { "debug" } else { "info" }),
    )
    .init();

    // Build the factory on the blocking pool. Construction may do DNS,
    // TLS handshakes, and KMS warm-up (synchronous AWS SDK init), all of
    // which would otherwise hold the Tokio main thread (T8 in
    // docs/review-2026-05-05-findings.md).
    let config = cli_to_config(&cli);
    let (factory, _applied) =
        tokio::task::spawn_blocking(move || asherah_config::factory_from_config(&config))
            .await
            .context("factory init task panicked")?
            .context("failed to initialize Asherah")?;

    let svc = asherah_server::service::AppEncryptionService::new(factory);
    let grpc_svc = proto::app_encryption_server::AppEncryptionServer::new(svc);

    // Remove stale socket file from previous run (only if it's a socket)
    if let Ok(meta) = std::fs::symlink_metadata(&cli.socket_file) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if meta.file_type().is_socket() {
                if let Err(err) = std::fs::remove_file(&cli.socket_file) {
                    log::warn!(
                        "failed to remove stale socket file '{}': {}",
                        cli.socket_file,
                        err
                    );
                }
            } else {
                anyhow::bail!(
                    "socket path '{}' exists but is not a Unix socket",
                    cli.socket_file
                );
            }
        }
        #[cfg(not(unix))]
        drop(std::fs::remove_file(&cli.socket_file));
    }

    let listener =
        tokio::net::UnixListener::bind(&cli.socket_file).context("failed to bind Unix socket")?;

    // The socket inherits umask-dependent permissions (typically 0o666). For a
    // sidecar holding KMS access and decrypted plaintext, that lets any local
    // UID encrypt/decrypt. Tighten to the configured mode immediately after
    // bind. Permission tightening is best-effort on non-Unix targets.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(cli.socket_mode);
        std::fs::set_permissions(&cli.socket_file, perms).with_context(|| {
            format!(
                "failed to set socket mode {:o} on '{}'",
                cli.socket_mode, cli.socket_file
            )
        })?;
    }

    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);

    log::info!(
        "listening on {} (mode {:#o})",
        cli.socket_file,
        cli.socket_mode
    );

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    // Spawn a task that listens for SIGTERM/SIGINT and broadcasts shutdown.
    // shutdown_signal returns a Result so signal-registration failures (a
    // seccomp-restricted host or a runtime that already owns the signal
    // disposition) surface to the operator instead of aborting the spawned
    // task and silently losing shutdown handling.
    tokio::spawn(async move {
        match shutdown_signal().await {
            Ok(()) => {}
            Err(e) => {
                log::error!("shutdown signal handler failed to register: {e:#}");
            }
        }
        let _ = shutdown_tx.send(true);
    });

    let mut drain_rx = shutdown_rx.clone();
    let server = Server::builder()
        .add_service(grpc_svc)
        .serve_with_incoming_shutdown(incoming, async move {
            // changed() returns Err(RecvError) only when shutdown_tx is
            // dropped without sending — i.e. the spawned signal task
            // panicked or exited unexpectedly. Treat that as an
            // immediate-shutdown signal but log it so operators can tell
            // it apart from a SIGTERM-driven shutdown. T-finding
            // "drop(shutdown_rx.changed().await) discards the Result"
            // in `docs/review-2026-05-05-findings.md`.
            if let Err(e) = shutdown_rx.changed().await {
                log::warn!(
                    "shutdown signal channel closed unexpectedly ({e}); \
                     server will drain immediately"
                );
            }
        });

    // Race graceful shutdown against a configurable hard drain timeout.
    // When the timeout wins the server future is dropped — any in-flight
    // session tasks are abandoned. The default is 30s (raised from the
    // hard-coded 5s); operators can tune via --shutdown-drain-timeout or
    // ASHERAH_SHUTDOWN_DRAIN_TIMEOUT.
    let drain_timeout = if cli.shutdown_drain_timeout > 0 {
        Duration::from_secs(cli.shutdown_drain_timeout as u64)
    } else {
        Duration::from_secs(30)
    };
    tokio::select! {
        result = server => {
            result.context("server error")?;
        }
        _ = async {
            // Same Err(RecvError) handling as the shutdown future above —
            // log unexpected channel closure so it doesn't look like a
            // normal SIGTERM-driven drain.
            if let Err(e) = drain_rx.changed().await {
                log::warn!(
                    "shutdown signal channel closed unexpectedly ({e}); \
                     starting drain timer immediately"
                );
            }
            log::info!(
                "received shutdown signal, draining connections (timeout {drain_timeout:?})..."
            );
            tokio::time::sleep(drain_timeout).await;
        } => {
            log::warn!(
                "graceful drain timed out after {drain_timeout:?}, forcing shutdown"
            );
        }
    }

    log::info!("shutting down");
    // Only remove if it's still a socket (could have been replaced during runtime)
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if std::fs::symlink_metadata(&cli.socket_file)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
        {
            if let Err(err) = std::fs::remove_file(&cli.socket_file) {
                log::warn!(
                    "failed to remove socket file '{}' during shutdown: {}",
                    cli.socket_file,
                    err
                );
            }
        }
    }
    #[cfg(not(unix))]
    drop(std::fs::remove_file(&cli.socket_file));

    Ok(())
}

async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate())?;
    let ctrl_c = tokio::signal::ctrl_c();

    tokio::select! {
        result = ctrl_c => result?,
        _ = sigterm.recv() => {}
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_octal_mode_accepts_canonical_forms() {
        assert_eq!(parse_octal_mode("0660").unwrap(), 0o660);
        assert_eq!(parse_octal_mode("660").unwrap(), 0o660);
        assert_eq!(parse_octal_mode("0o660").unwrap(), 0o660);
        assert_eq!(parse_octal_mode("0O660").unwrap(), 0o660);
        assert_eq!(parse_octal_mode(" 0600 ").unwrap(), 0o600);
        assert_eq!(parse_octal_mode("0").unwrap(), 0);
        assert_eq!(parse_octal_mode("777").unwrap(), 0o777);
    }

    #[test]
    fn parse_octal_mode_rejects_non_octal_digits() {
        assert!(parse_octal_mode("0689").is_err());
        assert!(parse_octal_mode("0xff").is_err());
        assert!(parse_octal_mode("abc").is_err());
    }

    #[test]
    fn parse_octal_mode_rejects_empty() {
        assert!(parse_octal_mode("").is_err());
        assert!(parse_octal_mode("   ").is_err());
    }

    #[test]
    fn parse_octal_mode_rejects_overlarge_values() {
        assert!(parse_octal_mode("01000").is_err());
        assert!(parse_octal_mode("7777").is_err());
    }
}
