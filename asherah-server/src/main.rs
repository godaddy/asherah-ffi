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
    #[arg(long, value_parser = ["aws", "static"], default_value = "aws", env = "ASHERAH_KMS_MODE")]
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
            if v.is_empty() {
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

    let config = cli_to_config(&cli);
    let (factory, _applied) =
        asherah_config::factory_from_config(&config).context("failed to initialize Asherah")?;

    let svc = asherah_server::service::AppEncryptionService::new(factory);
    let grpc_svc = proto::app_encryption_server::AppEncryptionServer::new(svc);

    // Remove stale socket file from previous run (only if it's a socket)
    if let Ok(meta) = std::fs::symlink_metadata(&cli.socket_file) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if meta.file_type().is_socket() {
                drop(std::fs::remove_file(&cli.socket_file));
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
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);

    log::info!("listening on {}", cli.socket_file);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

    // Spawn a task that listens for SIGTERM/SIGINT and broadcasts shutdown
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let mut drain_rx = shutdown_rx.clone();
    let server = Server::builder()
        .add_service(grpc_svc)
        .serve_with_incoming_shutdown(incoming, async move {
            drop(shutdown_rx.changed().await);
        });

    // Race graceful shutdown against a hard drain timeout
    tokio::select! {
        result = server => {
            result.context("server error")?;
        }
        _ = async {
            drop(drain_rx.changed().await);
            log::info!("received shutdown signal, draining connections...");
            tokio::time::sleep(Duration::from_secs(5)).await;
        } => {
            log::warn!("graceful drain timed out after 5s, forcing shutdown");
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
            drop(std::fs::remove_file(&cli.socket_file));
        }
    }
    #[cfg(not(unix))]
    drop(std::fs::remove_file(&cli.socket_file));

    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let ctrl_c = tokio::signal::ctrl_c();

    tokio::select! {
        _ = ctrl_c => {}
        _ = sigterm.recv() => {}
    }
}
