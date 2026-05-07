#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used)]

//! End-to-end tests that spawn the actual asherah-server binary.

use asherah_server::proto::app_encryption_client::AppEncryptionClient;
use asherah_server::proto::session_request::Request;
use asherah_server::proto::session_response::Response;
use asherah_server::proto::{Decrypt, Encrypt, GetSession, SessionRequest};
use serial_test::serial;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::net::UnixStream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

static E2E_COUNTER: AtomicU32 = AtomicU32::new(0);

fn e2e_socket_path() -> PathBuf {
    let n = E2E_COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!("/tmp/asherah-e2e-{}-{n}.sock", std::process::id()))
}

fn server_bin() -> String {
    // CARGO_BIN_EXE_<name> is set by cargo for integration tests
    env!("CARGO_BIN_EXE_asherah-server").to_string()
}

fn spawn_server(sock: &Path) -> std::process::Child {
    Command::new(server_bin())
        .args([
            "--service",
            "e2e-service",
            "--product",
            "e2e-product",
            "--kms",
            "test-debug-static",
            "--metastore",
            "memory",
            "-s",
            sock.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start server binary")
}

fn spawn_server_with_env(sock: &Path) -> std::process::Child {
    Command::new(server_bin())
        .env("ASHERAH_SERVICE_NAME", "env-service")
        .env("ASHERAH_PRODUCT_NAME", "env-product")
        .env("ASHERAH_KMS_MODE", "test-debug-static")
        .env("ASHERAH_METASTORE_MODE", "memory")
        .env("ASHERAH_SOCKET_FILE", sock.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start server binary")
}

async fn wait_for_server(sock: &Path, timeout_ms: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    while tokio::time::Instant::now() < deadline {
        if sock.exists() {
            // Verify the server is actually accepting connections, not just
            // that the file exists (which could be a stale socket).
            if UnixStream::connect(sock).await.is_ok() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "server not ready on {} within {}ms",
        sock.display(),
        timeout_ms
    );
}

fn send_signal(child: &std::process::Child, sig: &str) {
    Command::new("kill")
        .args([sig, &child.id().to_string()])
        .status()
        .expect("failed to send signal");
}

fn send_sigterm(child: &std::process::Child) {
    send_signal(child, "-TERM");
}

/// Send SIGTERM and wait up to `timeout` for exit. If the server doesn't exit,
/// send SIGKILL. Returns the exit status.
fn stop_server(child: &mut std::process::Child, timeout: Duration) -> std::process::ExitStatus {
    send_sigterm(child);
    let start = std::time::Instant::now();
    loop {
        match child.try_wait().expect("try_wait failed") {
            Some(status) => return status,
            None if start.elapsed() >= timeout => {
                send_signal(child, "-KILL");
                return child.wait().expect("wait after SIGKILL failed");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

async fn e2e_connect(sock: PathBuf) -> AppEncryptionClient<tonic::transport::Channel> {
    let channel = tokio::time::timeout(Duration::from_secs(5), async {
        Endpoint::try_from("http://[::]:50051")
            .expect("endpoint")
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = sock.clone();
                async move {
                    let stream = UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                }
            }))
            .await
            .expect("connect failed")
    })
    .await
    .expect("tonic connect timed out after 5s");

    AppEncryptionClient::new(channel)
}

fn make_request(r: Request) -> SessionRequest {
    SessionRequest { request: Some(r) }
}

#[tokio::test]
#[serial]
async fn test_binary_roundtrip() {
    let sock = e2e_socket_path();
    let mut child = spawn_server(&sock);

    wait_for_server(&sock, 5000).await;

    let mut client = e2e_connect(sock.clone()).await;
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let stream = ReceiverStream::new(rx);
    let response = client.session(stream).await.unwrap();
    let mut resp = response.into_inner();

    // GetSession
    tx.send(make_request(Request::GetSession(GetSession {
        partition_id: "e2e-partition".to_string(),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    assert!(msg.response.is_none());

    // Encrypt
    tx.send(make_request(Request::Encrypt(Encrypt {
        data: b"e2e test data".to_vec(),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    let drr = match msg.response {
        Some(Response::EncryptResponse(r)) => r.data_row_record.unwrap(),
        other => panic!("expected EncryptResponse, got {other:?}"),
    };

    // Decrypt
    tx.send(make_request(Request::Decrypt(Decrypt {
        data_row_record: Some(drr),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    match msg.response {
        Some(Response::DecryptResponse(r)) => {
            assert_eq!(r.data, b"e2e test data");
        }
        other => panic!("expected DecryptResponse, got {other:?}"),
    }

    drop(tx);
    drop(resp);
    drop(client);

    let status = stop_server(&mut child, Duration::from_secs(10));
    assert!(
        status.success(),
        "server should exit cleanly on SIGTERM (got {status})"
    );

    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_binary_sigterm_shutdown() {
    let sock = e2e_socket_path();
    let mut child = spawn_server(&sock);

    wait_for_server(&sock, 5000).await;
    assert!(sock.exists(), "socket should exist while running");

    let status = stop_server(&mut child, Duration::from_secs(5));
    assert!(status.success(), "server should exit 0 on SIGTERM");

    // Socket should be cleaned up after shutdown
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !sock.exists(),
        "socket should be removed after graceful shutdown"
    );
}

#[tokio::test]
#[serial]
async fn test_binary_stale_socket_cleanup() {
    let sock = e2e_socket_path();

    // Create a stale socket file
    std::os::unix::net::UnixListener::bind(&sock).expect("create stale socket");
    assert!(sock.exists());

    // Server should remove it and bind successfully
    let mut child = spawn_server(&sock);
    wait_for_server(&sock, 5000).await;

    // Verify the server is actually running by connecting
    let mut client = e2e_connect(sock.clone()).await;
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let stream = ReceiverStream::new(rx);
    let response = client.session(stream).await.unwrap();
    let mut resp = response.into_inner();

    tx.send(make_request(Request::GetSession(GetSession {
        partition_id: "stale-test".to_string(),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    assert!(msg.response.is_none());

    drop(tx);
    drop(resp);
    drop(client);

    stop_server(&mut child, Duration::from_secs(10));
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_binary_missing_required_args() {
    // No --service or --product
    let output = Command::new(server_bin())
        .args(["--metastore", "memory"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run server");

    assert!(
        !output.status.success(),
        "should fail without required args"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--service") || stderr.contains("required"),
        "error should mention missing --service: {stderr}"
    );
}

#[tokio::test]
#[serial]
async fn test_binary_env_var_config() {
    let sock = e2e_socket_path();
    let mut child = spawn_server_with_env(&sock);

    wait_for_server(&sock, 5000).await;

    // Verify server works when configured entirely through env vars
    let mut client = e2e_connect(sock.clone()).await;
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let stream = ReceiverStream::new(rx);
    let response = client.session(stream).await.unwrap();
    let mut resp = response.into_inner();

    tx.send(make_request(Request::GetSession(GetSession {
        partition_id: "env-partition".to_string(),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    assert!(msg.response.is_none());

    let plaintext = b"env var configured server works";
    tx.send(make_request(Request::Encrypt(Encrypt {
        data: plaintext.to_vec(),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    let drr = match msg.response {
        Some(Response::EncryptResponse(r)) => r.data_row_record.unwrap(),
        other => panic!("expected EncryptResponse, got {other:?}"),
    };

    tx.send(make_request(Request::Decrypt(Decrypt {
        data_row_record: Some(drr),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    match msg.response {
        Some(Response::DecryptResponse(r)) => {
            assert_eq!(r.data, plaintext);
        }
        other => panic!("expected DecryptResponse, got {other:?}"),
    }

    drop(tx);
    drop(resp);
    drop(client);

    stop_server(&mut child, Duration::from_secs(10));
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_binary_multiple_clients() {
    let sock = e2e_socket_path();
    let mut child = spawn_server(&sock);

    wait_for_server(&sock, 5000).await;

    // Spawn 5 concurrent clients against the real binary
    let mut handles = Vec::new();
    for i in 0_u32..5 {
        let sock = sock.clone();
        handles.push(tokio::spawn(async move {
            let mut client = e2e_connect(sock).await;
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            let stream = ReceiverStream::new(rx);
            let response = client.session(stream).await.unwrap();
            let mut resp = response.into_inner();

            tx.send(make_request(Request::GetSession(GetSession {
                partition_id: format!("e2e-client-{i}"),
            })))
            .await
            .unwrap();
            resp.next().await.unwrap().unwrap();

            let plaintext = format!("client {i} data").into_bytes();
            tx.send(make_request(Request::Encrypt(Encrypt {
                data: plaintext.clone(),
            })))
            .await
            .unwrap();
            let msg = resp.next().await.unwrap().unwrap();
            let drr = match msg.response {
                Some(Response::EncryptResponse(r)) => r.data_row_record.unwrap(),
                other => panic!("expected EncryptResponse, got {other:?}"),
            };

            tx.send(make_request(Request::Decrypt(Decrypt {
                data_row_record: Some(drr),
            })))
            .await
            .unwrap();
            let msg = resp.next().await.unwrap().unwrap();
            match msg.response {
                Some(Response::DecryptResponse(r)) => {
                    assert_eq!(r.data, plaintext);
                }
                other => panic!("expected DecryptResponse, got {other:?}"),
            }

            drop(tx);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    stop_server(&mut child, Duration::from_secs(10));
    drop(std::fs::remove_file(&sock));
}

// --- helpers for socket-alias and log-emission tests ----------------------

fn e2e_stderr_path() -> PathBuf {
    let n = E2E_COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        "/tmp/asherah-e2e-{}-{n}.stderr.log",
        std::process::id()
    ))
}

/// Spawn the server with a controlled environment and stderr captured to a
/// file. Uses `env_clear` so the parent test process's `RUST_LOG` (which
/// `cargo test` may have set) cannot leak in and contaminate log-emission
/// assertions. A minimal allowlist (`PATH`, `HOME`, `USER`, `TMPDIR`) is
/// preserved so the dynamic linker, AWS profile lookup, etc. still work on
/// macOS and Linux. `extra_env` is layered on top — caller controls the
/// asherah/RUST_LOG knobs under test.
fn spawn_server_with_extra_env(
    extra_env: &[(&str, &str)],
    stderr_log: &Path,
) -> std::process::Child {
    let stderr_file = std::fs::File::create(stderr_log).expect("create stderr log file");
    let mut cmd = Command::new(server_bin());
    cmd.env_clear();
    for var in ["PATH", "HOME", "USER", "TMPDIR"] {
        if let Ok(val) = std::env::var(var) {
            cmd.env(var, val);
        }
    }
    cmd.env("ASHERAH_SERVICE_NAME", "log-service")
        .env("ASHERAH_PRODUCT_NAME", "log-product")
        .env("ASHERAH_KMS_MODE", "test-debug-static")
        .env("ASHERAH_METASTORE_MODE", "memory");
    for (k, v) in extra_env {
        cmd.env(*k, *v);
    }
    cmd.stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("failed to start server binary")
}

async fn do_simple_roundtrip(sock: &Path, partition: &str, payload: &[u8]) {
    let mut client = e2e_connect(sock.to_path_buf()).await;
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let stream = ReceiverStream::new(rx);
    let response = client.session(stream).await.unwrap();
    let mut resp = response.into_inner();

    tx.send(make_request(Request::GetSession(GetSession {
        partition_id: partition.to_string(),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    assert!(msg.response.is_none(), "GetSession should return empty");

    tx.send(make_request(Request::Encrypt(Encrypt {
        data: payload.to_vec(),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    let drr = match msg.response {
        Some(Response::EncryptResponse(r)) => r.data_row_record.unwrap(),
        other => panic!("expected EncryptResponse, got {other:?}"),
    };

    tx.send(make_request(Request::Decrypt(Decrypt {
        data_row_record: Some(drr),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    match msg.response {
        Some(Response::DecryptResponse(r)) => assert_eq!(r.data, payload),
        other => panic!("expected DecryptResponse, got {other:?}"),
    }

    drop(tx);
    drop(resp);
    drop(client);
}

fn read_stderr(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

// --- ASHERAH_SOCKET / unix:// alias e2e (#3) ------------------------------

#[tokio::test]
#[serial]
async fn test_binary_socket_env_var_alias() {
    // Plain `ASHERAH_SOCKET=<path>` (no URI prefix) — the asherah-ffi alias
    // for `ASHERAH_SOCKET_FILE`. Server should bind at the given path and
    // serve traffic exactly like the canonical env var.
    let sock = e2e_socket_path();
    let stderr_log = e2e_stderr_path();
    let mut child =
        spawn_server_with_extra_env(&[("ASHERAH_SOCKET", sock.to_str().unwrap())], &stderr_log);
    wait_for_server(&sock, 5000).await;
    do_simple_roundtrip(&sock, "alias-partition", b"alias env var works").await;
    stop_server(&mut child, Duration::from_secs(10));
    drop(std::fs::remove_file(&sock));
    drop(std::fs::remove_file(&stderr_log));
}

#[tokio::test]
#[serial]
async fn test_binary_socket_unix_uri_strip() {
    // `ASHERAH_SOCKET=unix://<path>` — gRPC clients dial via the `unix://`
    // URI scheme and consumers commonly export the same value as the
    // server bind variable. The Go reference binds it as a literal
    // filename and silently fails; we strip the prefix and bind the path.
    let sock = e2e_socket_path();
    let uri = format!("unix://{}", sock.to_str().unwrap());
    let stderr_log = e2e_stderr_path();
    let mut child = spawn_server_with_extra_env(&[("ASHERAH_SOCKET", uri.as_str())], &stderr_log);
    wait_for_server(&sock, 5000).await;
    do_simple_roundtrip(&sock, "uri-partition", b"unix uri stripped").await;
    let stderr = read_stderr(&stderr_log);
    assert!(
        !stderr.contains("unix://"),
        "the listening-on log line must show the stripped path, got:\n{stderr}"
    );
    stop_server(&mut child, Duration::from_secs(10));
    drop(std::fs::remove_file(&sock));
    drop(std::fs::remove_file(&stderr_log));
}

#[tokio::test]
#[serial]
async fn test_binary_socket_file_wins_over_alias() {
    // When both env vars are set, ASHERAH_SOCKET_FILE wins because it
    // matches the canonical Go reference convention. The alias path must
    // not be bound.
    let canonical = e2e_socket_path();
    let alias = e2e_socket_path();
    let stderr_log = e2e_stderr_path();
    let mut child = spawn_server_with_extra_env(
        &[
            ("ASHERAH_SOCKET_FILE", canonical.to_str().unwrap()),
            ("ASHERAH_SOCKET", alias.to_str().unwrap()),
        ],
        &stderr_log,
    );
    wait_for_server(&canonical, 5000).await;
    assert!(
        !alias.exists(),
        "alias path '{}' must not be bound when ASHERAH_SOCKET_FILE is set",
        alias.display()
    );
    do_simple_roundtrip(&canonical, "precedence-partition", b"socket_file wins").await;
    stop_server(&mut child, Duration::from_secs(10));
    drop(std::fs::remove_file(&canonical));
    drop(std::fs::remove_file(&alias));
    drop(std::fs::remove_file(&stderr_log));
}

// --- log-emission e2e (#2) -----------------------------------------------

#[tokio::test]
#[serial]
async fn test_binary_logs_listening_line_at_default_filter() {
    // The bare-minimum signal a consumer needs to confirm the server
    // started: with no RUST_LOG and no ASHERAH_VERBOSE, the info-level
    // "listening on <path>" line must reach stderr. Regression guard for
    // the exact "no logs from the server" complaint that motivated this PR.
    let sock = e2e_socket_path();
    let stderr_log = e2e_stderr_path();
    let mut child = spawn_server_with_extra_env(
        &[("ASHERAH_SOCKET_FILE", sock.to_str().unwrap())],
        &stderr_log,
    );
    wait_for_server(&sock, 5000).await;
    stop_server(&mut child, Duration::from_secs(10));
    let stderr = read_stderr(&stderr_log);
    assert!(
        stderr.contains("listening on") && stderr.contains(sock.to_str().unwrap()),
        "expected info-level 'listening on {}' in stderr, got:\n{stderr}",
        sock.display()
    );
    drop(std::fs::remove_file(&sock));
    drop(std::fs::remove_file(&stderr_log));
}

#[tokio::test]
#[serial]
async fn test_binary_verbose_overrides_restrictive_rust_log() {
    // Exact reproduction of the consumer config that surfaced the bug:
    // `RUST_LOG=asherah_server=debug` would normally silence the
    // asherah-crate WARN lines (e.g. the static-master-key warning),
    // because env_logger directives are per-module and the asherah crate
    // is not in the directive. ASHERAH_VERBOSE=true must override
    // RUST_LOG and surface the asherah-crate stream.
    let sock = e2e_socket_path();
    let stderr_log = e2e_stderr_path();
    let mut child = spawn_server_with_extra_env(
        &[
            ("ASHERAH_SOCKET_FILE", sock.to_str().unwrap()),
            ("RUST_LOG", "asherah_server=debug"),
            ("ASHERAH_VERBOSE", "true"),
        ],
        &stderr_log,
    );
    wait_for_server(&sock, 5000).await;
    stop_server(&mut child, Duration::from_secs(10));
    let stderr = read_stderr(&stderr_log);
    assert!(
        stderr.contains("asherah::builders") && stderr.contains("static master key"),
        "ASHERAH_VERBOSE=true must override restrictive RUST_LOG and emit \
         asherah-crate WARN lines; got:\n{stderr}"
    );
    drop(std::fs::remove_file(&sock));
    drop(std::fs::remove_file(&stderr_log));
}

#[tokio::test]
#[serial]
async fn test_binary_rust_log_warn_silences_info_when_not_verbose() {
    // Pins the contract that RUST_LOG is honored exactly when verbose is
    // unset: RUST_LOG=warn must suppress the info-level startup line but
    // still let asherah-crate WARN through. Catches a regression where we
    // accidentally start forcing a debug filter unconditionally.
    let sock = e2e_socket_path();
    let stderr_log = e2e_stderr_path();
    let mut child = spawn_server_with_extra_env(
        &[
            ("ASHERAH_SOCKET_FILE", sock.to_str().unwrap()),
            ("RUST_LOG", "warn"),
        ],
        &stderr_log,
    );
    wait_for_server(&sock, 5000).await;
    stop_server(&mut child, Duration::from_secs(10));
    let stderr = read_stderr(&stderr_log);
    assert!(
        !stderr.contains("listening on"),
        "RUST_LOG=warn must suppress the info-level startup line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("static master key"),
        "asherah-crate WARN must still appear at RUST_LOG=warn, got:\n{stderr}"
    );
    drop(std::fs::remove_file(&sock));
    drop(std::fs::remove_file(&stderr_log));
}
