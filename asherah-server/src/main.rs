use anyhow::{Context, Result};
use asherah_server::{parse_go_duration, proto};
use clap::{Parser, ValueEnum};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tonic::transport::Server;

/// Metastore backend selector. Mirrors the values the Go reference
/// server accepts and keeps them in lockstep so the CLI rejects
/// typos at parse time rather than failing later inside
/// `factory_from_config`. T-finding "value_parser with string array;
/// use typed enum" in `docs/review-2026-05-05-findings.md`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "kebab-case")]
enum MetastoreMode {
    Rdbms,
    Dynamodb,
    Memory,
}

impl MetastoreMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Rdbms => "rdbms",
            Self::Dynamodb => "dynamodb",
            Self::Memory => "memory",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "kebab-case")]
enum KmsMode {
    Aws,
    Static,
    TestDebugStatic,
}

impl KmsMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Static => "static",
            Self::TestDebugStatic => "test-debug-static",
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "kebab-case")]
enum ReplicaReadConsistency {
    Eventual,
    Global,
    Session,
}

impl ReplicaReadConsistency {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eventual => "eventual",
            Self::Global => "global",
            Self::Session => "session",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "asherah-server",
    about = "gRPC sidecar server for Asherah envelope encryption"
)]
struct Cli {
    /// The unix domain socket the server will listen on. Plain filesystem
    /// path, matching the Go reference server's `--socket-file` flag.
    #[arg(short = 's', long = "socket-file", env = "ASHERAH_SOCKET_FILE")]
    socket_file: Option<String>,

    /// Alias for `--socket-file` (env `ASHERAH_SOCKET`). Accepts the same
    /// plain filesystem path; for caller convenience a leading `unix://`
    /// URI prefix is stripped (gRPC dial URIs and bind paths are commonly
    /// confused). When both `ASHERAH_SOCKET_FILE` and `ASHERAH_SOCKET` are
    /// set, `ASHERAH_SOCKET_FILE` wins because it matches the canonical
    /// Go reference convention. This alias is an asherah-ffi extension —
    /// the Go reference server does not read either env var, only the
    /// `--socket-file` flag.
    #[arg(long = "socket", env = "ASHERAH_SOCKET")]
    socket: Option<String>,

    /// File mode (octal) applied to the listening Unix socket after bind.
    /// When unset, the socket inherits the process umask (typically
    /// `0o666`), matching the Go reference server which does not call
    /// `chmod` on its socket. Operators on multi-tenant hosts who want
    /// the socket restricted should set this explicitly (e.g. `0660`)
    /// — any local UID with read/write on this socket can ask the
    /// sidecar to encrypt or decrypt arbitrary records.
    ///
    /// Drop-in compatibility: the previous default of `0660` was a
    /// security hardening from the 2026-05-05 review that broke
    /// deployments where the sidecar runs under a different UID than
    /// the client (e.g. asherah-server under one supervisord-owned
    /// uid, Apache PHP under `APACHE_RUN_USER`). The Go reference
    /// did not tighten, so the hardening was a unilateral divergence.
    #[arg(
        long,
        value_parser = parse_octal_mode,
        env = "ASHERAH_SOCKET_MODE"
    )]
    socket_mode: Option<u32>,

    /// The name of this service
    #[arg(long, env = "ASHERAH_SERVICE_NAME")]
    service: String,

    /// The name of the product that owns this service
    #[arg(long, env = "ASHERAH_PRODUCT_NAME")]
    product: String,

    /// Determines the type of metastore to use for persisting keys
    #[arg(long, value_enum, env = "ASHERAH_METASTORE_MODE")]
    metastore: MetastoreMode,

    /// The database connection string (required if --metastore=rdbms)
    #[arg(long, env = "ASHERAH_CONNECTION_STRING")]
    conn: Option<String>,

    /// Configures the master key management service
    #[arg(
        long,
        value_enum,
        default_value_t = KmsMode::Aws,
        env = "ASHERAH_KMS_MODE"
    )]
    kms: KmsMode,

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
    #[arg(long, value_enum, env = "ASHERAH_REPLICA_READ_CONSISTENCY")]
    replica_read_consistency: Option<ReplicaReadConsistency>,

    /// Configure the metastore to use regional suffixes (only supported by --metastore=dynamodb)
    #[arg(long, env = "ASHERAH_ENABLE_REGION_SUFFIX")]
    enable_region_suffix: bool,

    /// Enable verbose logging output. When set, forces the log filter to
    /// `info,asherah=debug,asherah_server=debug` regardless of `RUST_LOG`,
    /// matching the Go reference server's posture that `ASHERAH_VERBOSE`
    /// is the primary logging knob (the Go server has no `RUST_LOG`
    /// equivalent). When unset, `RUST_LOG` is honored if present and the
    /// default filter is `info`.
    ///
    /// **Blessed incompatibility with the Go reference:** the Go server
    /// emits `handling encrypt|decrypt|get-session for <partition>` and
    /// `closing session for <partition>` at info level *unconditionally*.
    /// We deliberately downgrade those to debug — they appear only under
    /// `--verbose` / `ASHERAH_VERBOSE=true`. The partition ID is a
    /// caller-supplied tenant identifier and operators running this
    /// sidecar at info should not inadvertently log per-request tenant
    /// activity. T-finding "verbose mode emits per-request partition ID
    /// logs; tenant identifier exposure" in
    /// `docs/review-2026-05-05-findings.md`.
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

/// Default socket path, matching the Go reference server's
/// `--socket-file` default. Used when neither `ASHERAH_SOCKET_FILE` nor
/// `ASHERAH_SOCKET` is provided.
const DEFAULT_SOCKET_PATH: &str = "/tmp/appencryption.sock";

/// Resolve the listening socket path from the two compat env vars.
/// `ASHERAH_SOCKET_FILE` wins over `ASHERAH_SOCKET` (the Go-reference name
/// takes precedence over the asherah-ffi alias). A leading `unix://`
/// prefix is stripped from either value — gRPC clients dial unix domain
/// sockets via `unix://<path>` URIs and consumers commonly export the
/// same value as a server bind variable. The Go reference server treats
/// such a value as a literal filename and silently binds the wrong path,
/// so we normalize instead.
fn resolve_socket_path(socket_file: Option<&str>, socket: Option<&str>) -> String {
    fn non_empty(opt: Option<&str>) -> Option<&str> {
        opt.map(str::trim).filter(|s| !s.is_empty())
    }
    // An explicit-but-blank `ASHERAH_SOCKET_FILE=""` must not mask a real
    // `ASHERAH_SOCKET` value — `clap` exposes it as `Some("")`, so we
    // filter empties at each level before falling through.
    let raw = non_empty(socket_file)
        .or_else(|| non_empty(socket))
        .unwrap_or(DEFAULT_SOCKET_PATH);
    raw.strip_prefix("unix://").unwrap_or(raw).to_string()
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
        metastore: Some(cli.metastore.as_str().to_string()),
        connection_string: cli.conn.clone(),
        kms: Some(cli.kms.as_str().to_string()),
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
        replica_read_consistency: cli.replica_read_consistency.map(|m| m.as_str().to_string()),
        enable_region_suffix: Some(cli.enable_region_suffix),
        verbose: Some(cli.verbose),
        ..Default::default()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    asherah::process_hardening::ensure_process_hardened()
        .context("failed to initialize process hardening")?;

    let cli = Cli::parse();

    // Drop-in compatibility with the Go reference: ASHERAH_VERBOSE is the
    // primary logging knob and the Go server has no RUST_LOG analog. When
    // verbose is set we override RUST_LOG entirely so a consumer-supplied
    // restrictive RUST_LOG can't silence the asherah-crate debug stream
    // they explicitly asked for. When unset we keep RUST_LOG honored (a
    // power-user knob beyond Go parity) with `info` as the default.
    if cli.verbose {
        env_logger::Builder::new()
            .parse_filters("info,asherah=debug,asherah_server=debug")
            .init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    let socket_path = resolve_socket_path(cli.socket_file.as_deref(), cli.socket.as_deref());

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

    // Track in-flight per-session tasks so we can `join_next()` them on
    // shutdown and force-cancel any stragglers that exceed the drain
    // deadline. Without this, the server future is dropped at the
    // timeout and abandons in-flight `s.close()` calls — leaking
    // memguard-locked pages and skipping IK-cache cleanup.
    let session_tasks: Arc<Mutex<JoinSet<()>>> = Arc::new(Mutex::new(JoinSet::new()));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let svc = asherah_server::service::AppEncryptionService::with_lifecycle(
        factory,
        shutdown_rx.clone(),
        session_tasks.clone(),
    );
    let grpc_svc = proto::app_encryption_server::AppEncryptionServer::new(svc);

    // Remove stale socket file from previous run (only if it's a socket)
    if let Ok(meta) = std::fs::symlink_metadata(&socket_path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if meta.file_type().is_socket() {
                if let Err(err) = std::fs::remove_file(&socket_path) {
                    log::warn!("failed to remove stale socket file '{socket_path}': {err}");
                }
            } else {
                anyhow::bail!("socket path '{socket_path}' exists but is not a Unix socket");
            }
        }
        #[cfg(not(unix))]
        drop(std::fs::remove_file(&socket_path));
    }

    let listener =
        tokio::net::UnixListener::bind(&socket_path).context("failed to bind Unix socket")?;

    // Only tighten permissions when the operator explicitly opts in via
    // `--socket-mode` / `ASHERAH_SOCKET_MODE`. The Go reference server
    // does not chmod its socket (it inherits umask-default permissions,
    // typically 0o666); tightening unconditionally broke drop-in
    // deployments where the sidecar runs under a different UID than the
    // gRPC client (e.g. supervisord-managed asherah-server vs Apache PHP
    // under APACHE_RUN_USER). Operators on multi-tenant hosts who want
    // the socket restricted should set the mode explicitly.
    #[cfg(unix)]
    if let Some(mode) = cli.socket_mode {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(&socket_path, perms)
            .with_context(|| format!("failed to set socket mode {mode:o} on '{socket_path}'"))?;
    }

    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);

    match cli.socket_mode {
        Some(mode) => log::info!("listening on {socket_path} (mode {mode:#o})"),
        None => log::info!("listening on {socket_path} (mode inherited from umask)"),
    }

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

    let mut server_shutdown_rx = shutdown_rx.clone();
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
            if let Err(e) = server_shutdown_rx.changed().await {
                log::warn!(
                    "shutdown signal channel closed unexpectedly ({e}); \
                     server will drain immediately"
                );
            }
        });

    // Race graceful shutdown against a configurable hard drain timeout.
    // The drain phase observes the session JoinSet directly: when the
    // shutdown signal fires, every in-flight per-session task drops out
    // of its `inbound.message()` loop (drops the response sender so
    // tonic can return promptly) and then runs `s.close()` on the
    // blocking pool. After the server future resolves we `join_next()`
    // the set until it's empty (clean drain) or the deadline passes
    // (force-cancel via `set.shutdown()`), ensuring `close()` actually
    // runs before the runtime tears down — the previous design dropped
    // the server future on timeout and abandoned in-flight `close()`s.
    let drain_timeout = if cli.shutdown_drain_timeout > 0 {
        Duration::from_secs(cli.shutdown_drain_timeout as u64)
    } else {
        Duration::from_secs(30)
    };

    tokio::pin!(server);
    let mut shutdown_observer = shutdown_rx.clone();
    let shutdown_received = tokio::select! {
        biased;
        res = &mut server => {
            // Server exited on its own (bind error, shutdown future
            // already completed, etc.) — fall through to drain.
            if let Err(e) = res {
                log::warn!("server exited with error: {e:#}");
            }
            false
        }
        res = shutdown_observer.changed() => {
            if let Err(e) = res {
                log::warn!(
                    "shutdown signal channel closed unexpectedly ({e}); \
                     draining immediately"
                );
            }
            true
        }
    };

    let drain_deadline = tokio::time::Instant::now() + drain_timeout;

    if shutdown_received {
        log::info!("received shutdown signal, draining (timeout {drain_timeout:?})...");
        // Give tonic up to `drain_timeout` to finish its in-flight
        // streams and return. If it doesn't, we drop the server future
        // (cancelling any blocked HTTP/2 work) and proceed to force the
        // session JoinSet down.
        match tokio::time::timeout_at(drain_deadline, &mut server).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => log::warn!("server exited with error during drain: {e:#}"),
            Err(_) => log::warn!(
                "server didn't finish draining within {drain_timeout:?}; \
                 cancelling and force-shutting session tasks"
            ),
        }
    }

    {
        let mut set = session_tasks.lock().await;
        while !set.is_empty() {
            match tokio::time::timeout_at(drain_deadline, set.join_next()).await {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(join_err))) => {
                    if !join_err.is_cancelled() {
                        log::debug!("session task ended: {join_err}");
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    let remaining = set.len();
                    log::warn!(
                        "graceful drain timed out after {drain_timeout:?} with \
                         {remaining} session task(s) in flight; force-cancelling"
                    );
                    set.shutdown().await;
                    break;
                }
            }
        }
    }
    drop(shutdown_rx);

    log::info!("shutting down");
    // Only remove if it's still a socket (could have been replaced during runtime)
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if std::fs::symlink_metadata(&socket_path)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
        {
            if let Err(err) = std::fs::remove_file(&socket_path) {
                log::warn!("failed to remove socket file '{socket_path}' during shutdown: {err}");
            }
        }
    }
    #[cfg(not(unix))]
    drop(std::fs::remove_file(&socket_path));

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

    #[test]
    fn resolve_socket_path_defaults_when_unset() {
        assert_eq!(resolve_socket_path(None, None), DEFAULT_SOCKET_PATH);
    }

    #[test]
    fn resolve_socket_path_prefers_socket_file_over_socket() {
        assert_eq!(
            resolve_socket_path(Some("/a/canonical.sock"), Some("/b/alias.sock")),
            "/a/canonical.sock"
        );
    }

    #[test]
    fn resolve_socket_path_falls_back_to_socket_alias() {
        assert_eq!(
            resolve_socket_path(None, Some("/b/alias.sock")),
            "/b/alias.sock"
        );
    }

    #[test]
    fn resolve_socket_path_strips_unix_uri_prefix() {
        assert_eq!(
            resolve_socket_path(None, Some("unix:///sock/asherah.sock")),
            "/sock/asherah.sock"
        );
        assert_eq!(
            resolve_socket_path(Some("unix:///tmp/foo.sock"), None),
            "/tmp/foo.sock"
        );
    }

    #[test]
    fn resolve_socket_path_treats_empty_as_unset() {
        assert_eq!(resolve_socket_path(Some(""), None), DEFAULT_SOCKET_PATH);
        assert_eq!(resolve_socket_path(Some("   "), None), DEFAULT_SOCKET_PATH);
        assert_eq!(
            resolve_socket_path(Some(""), Some("/b/alias.sock")),
            "/b/alias.sock"
        );
    }
}
