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
    /// Unix domain socket path
    #[arg(
        short = 's',
        long,
        default_value = "/tmp/appencryption.sock",
        env = "ASHERAH_SOCKET_FILE"
    )]
    socket_file: String,

    /// Service name
    #[arg(long, env = "ASHERAH_SERVICE_NAME")]
    service: String,

    /// Product ID
    #[arg(long, env = "ASHERAH_PRODUCT_NAME")]
    product: String,

    /// Metastore type: memory, rdbms, dynamodb
    #[arg(long, default_value = "memory", env = "ASHERAH_METASTORE_MODE")]
    metastore: String,

    /// Database connection string (required for rdbms metastore)
    #[arg(long, env = "ASHERAH_CONNECTION_STRING")]
    conn: Option<String>,

    /// KMS type: static, aws
    #[arg(long, default_value = "static", env = "ASHERAH_KMS_MODE")]
    kms: String,

    /// AWS region-to-ARN mapping as JSON (required for aws KMS)
    #[arg(long, env = "ASHERAH_REGION_MAP")]
    region_map: Option<String>,

    /// Preferred AWS region (required for aws KMS)
    #[arg(long, env = "ASHERAH_PREFERRED_REGION")]
    preferred_region: Option<String>,

    /// Key expiration duration (e.g., 90m, 2h, 5400s, or 5400)
    #[arg(long, value_parser = parse_go_duration, env = "ASHERAH_EXPIRE_AFTER")]
    expire_after: Option<i64>,

    /// Key revocation check interval (e.g., 10m, 1h, 600s, or 600)
    #[arg(long, value_parser = parse_go_duration, env = "ASHERAH_CHECK_INTERVAL")]
    check_interval: Option<i64>,

    /// Enable session caching
    #[arg(long, env = "ASHERAH_ENABLE_SESSION_CACHING")]
    session_cache: Option<bool>,

    /// Maximum sessions in cache
    #[arg(long, env = "ASHERAH_SESSION_CACHE_MAX_SIZE")]
    session_cache_max_size: Option<u32>,

    /// Session cache TTL (e.g., 2h, 120m, 7200s, or 7200)
    #[arg(long, value_parser = parse_go_duration, env = "ASHERAH_SESSION_CACHE_DURATION")]
    session_cache_duration: Option<i64>,

    /// Custom DynamoDB endpoint
    #[arg(long, env = "ASHERAH_DYNAMODB_ENDPOINT")]
    dynamodb_endpoint: Option<String>,

    /// DynamoDB region
    #[arg(long, env = "ASHERAH_DYNAMODB_REGION")]
    dynamodb_region: Option<String>,

    /// DynamoDB table name
    #[arg(long, env = "ASHERAH_DYNAMODB_TABLE_NAME")]
    dynamodb_table_name: Option<String>,

    /// Replica read consistency (aurora, eventual, global, session)
    #[arg(long, env = "ASHERAH_REPLICA_READ_CONSISTENCY")]
    replica_read_consistency: Option<String>,

    /// Enable region suffix on system keys
    #[arg(long, env = "ASHERAH_ENABLE_REGION_SUFFIX")]
    enable_region_suffix: Option<bool>,

    /// Enable debug logging
    #[arg(long)]
    verbose: bool,
}

fn cli_to_config(cli: &Cli) -> asherah_config::ConfigOptions {
    let region_map = cli
        .region_map
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok());

    asherah_config::ConfigOptions {
        service_name: Some(cli.service.clone()),
        product_id: Some(cli.product.clone()),
        metastore: Some(cli.metastore.clone()),
        connection_string: cli.conn.clone(),
        kms: Some(cli.kms.clone()),
        region_map,
        preferred_region: cli.preferred_region.clone(),
        expire_after: cli.expire_after,
        check_interval: cli.check_interval,
        enable_session_caching: cli.session_cache,
        session_cache_max_size: cli.session_cache_max_size,
        session_cache_duration: cli.session_cache_duration,
        dynamo_db_endpoint: cli.dynamodb_endpoint.clone(),
        dynamo_db_region: cli.dynamodb_region.clone(),
        dynamo_db_table_name: cli.dynamodb_table_name.clone(),
        replica_read_consistency: cli.replica_read_consistency.clone(),
        enable_region_suffix: cli.enable_region_suffix,
        verbose: Some(cli.verbose),
        ..Default::default()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Check ASHERAH_VERBOSE env var in addition to --verbose flag
    let verbose = cli.verbose
        || std::env::var("ASHERAH_VERBOSE")
            .is_ok_and(|v| matches!(v.as_str(), "1" | "true" | "yes"));

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(if verbose {
        "debug"
    } else {
        "info"
    }))
    .init();

    let config = cli_to_config(&cli);
    let (factory, _applied) =
        asherah_config::factory_from_config(&config).context("failed to initialize Asherah")?;

    let svc = asherah_server::service::AppEncryptionService::new(factory);
    let grpc_svc = proto::app_encryption_server::AppEncryptionServer::new(svc);

    // Remove stale socket file from previous run
    drop(std::fs::remove_file(&cli.socket_file));

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
