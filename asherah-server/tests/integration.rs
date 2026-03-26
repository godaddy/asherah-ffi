#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used)]

use asherah_server::proto;
use asherah_server::proto::app_encryption_client::AppEncryptionClient;
use asherah_server::proto::session_request::Request;
use asherah_server::proto::session_response::Response;
use asherah_server::proto::{Decrypt, Encrypt, GetSession, SessionRequest};
use serial_test::serial;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::net::UnixStream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn socket_path() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        "/tmp/asherah-server-test-{}-{n}.sock",
        std::process::id()
    ))
}

fn make_request(r: Request) -> SessionRequest {
    SessionRequest { request: Some(r) }
}

async fn start_server(sock: &std::path::Path) -> tokio::task::JoinHandle<()> {
    let config = asherah_config::ConfigOptions {
        service_name: Some("test-service".to_string()),
        product_id: Some("test-product".to_string()),
        metastore: Some("memory".to_string()),
        kms: Some("static".to_string()),
        ..Default::default()
    };

    let (factory, _applied) =
        asherah_config::factory_from_config(&config).expect("factory setup failed");

    let svc = asherah_server::service::AppEncryptionService::new(factory);
    let grpc_svc = proto::app_encryption_server::AppEncryptionServer::new(svc);

    drop(std::fs::remove_file(sock));
    let listener = tokio::net::UnixListener::bind(sock).expect("bind failed");
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);

    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(grpc_svc)
            .serve_with_incoming(incoming)
            .await
            .expect("server error");
    })
}

async fn connect(sock: PathBuf) -> AppEncryptionClient<tonic::transport::Channel> {
    let channel = Endpoint::try_from("http://[::]:50051")
        .expect("endpoint")
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = sock.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .expect("connect failed");

    AppEncryptionClient::new(channel)
}

/// Helper: open a session stream, returning sender and response stream.
async fn open_session(
    client: &mut AppEncryptionClient<tonic::transport::Channel>,
) -> (
    tokio::sync::mpsc::Sender<SessionRequest>,
    tonic::Streaming<proto::SessionResponse>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let stream = ReceiverStream::new(rx);
    let response = client.session(stream).await.expect("session RPC failed");
    (tx, response.into_inner())
}

/// Helper: send GetSession, assert empty response.
async fn do_get_session(
    tx: &tokio::sync::mpsc::Sender<SessionRequest>,
    resp: &mut tonic::Streaming<proto::SessionResponse>,
    partition: &str,
) {
    tx.send(make_request(Request::GetSession(GetSession {
        partition_id: partition.to_string(),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    assert!(
        msg.response.is_none(),
        "GetSession should return empty response"
    );
}

/// Helper: encrypt data, return the DRR.
async fn do_encrypt(
    tx: &tokio::sync::mpsc::Sender<SessionRequest>,
    resp: &mut tonic::Streaming<proto::SessionResponse>,
    data: &[u8],
) -> proto::DataRowRecord {
    tx.send(make_request(Request::Encrypt(Encrypt {
        data: data.to_vec(),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    match msg.response {
        Some(Response::EncryptResponse(r)) => r.data_row_record.expect("missing DRR"),
        other => panic!("expected EncryptResponse, got {other:?}"),
    }
}

/// Helper: decrypt a DRR, return plaintext.
async fn do_decrypt(
    tx: &tokio::sync::mpsc::Sender<SessionRequest>,
    resp: &mut tonic::Streaming<proto::SessionResponse>,
    drr: proto::DataRowRecord,
) -> Vec<u8> {
    tx.send(make_request(Request::Decrypt(Decrypt {
        data_row_record: Some(drr),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().unwrap();
    match msg.response {
        Some(Response::DecryptResponse(r)) => r.data,
        other => panic!("expected DecryptResponse, got {other:?}"),
    }
}

/// Helper: expect an error response with specific message.
async fn expect_error(resp: &mut tonic::Streaming<proto::SessionResponse>, expected_msg: &str) {
    let msg = resp.next().await.unwrap().unwrap();
    match msg.response {
        Some(Response::ErrorResponse(e)) => {
            assert_eq!(e.message, expected_msg);
        }
        other => panic!("expected ErrorResponse(\"{expected_msg}\"), got {other:?}"),
    }
}

// ============================================================
// Session state machine tests
// ============================================================

#[tokio::test]
#[serial]
async fn test_session_roundtrip() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;

    do_get_session(&tx, &mut resp, "test-partition").await;

    let plaintext = b"hello gRPC sidecar";
    let drr = do_encrypt(&tx, &mut resp, plaintext).await;
    let decrypted = do_decrypt(&tx, &mut resp, drr).await;
    assert_eq!(decrypted, plaintext);

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_encrypt_before_get_session() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;

    tx.send(make_request(Request::Encrypt(Encrypt {
        data: b"test".to_vec(),
    })))
    .await
    .unwrap();
    expect_error(&mut resp, "session not yet initialized").await;

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_decrypt_before_get_session() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;

    tx.send(make_request(Request::Decrypt(Decrypt {
        data_row_record: Some(proto::DataRowRecord {
            key: None,
            data: vec![1, 2, 3],
        }),
    })))
    .await
    .unwrap();
    expect_error(&mut resp, "session not yet initialized").await;

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_double_get_session() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;

    do_get_session(&tx, &mut resp, "p1").await;

    tx.send(make_request(Request::GetSession(GetSession {
        partition_id: "p2".to_string(),
    })))
    .await
    .unwrap();
    expect_error(&mut resp, "session has already been initialized").await;

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_empty_request() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;

    // Send a SessionRequest with no oneof variant set
    tx.send(SessionRequest { request: None }).await.unwrap();
    expect_error(&mut resp, "empty request").await;

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_decrypt_missing_data_row_record() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;

    do_get_session(&tx, &mut resp, "test").await;

    tx.send(make_request(Request::Decrypt(Decrypt {
        data_row_record: None,
    })))
    .await
    .unwrap();
    expect_error(&mut resp, "decrypt request missing data_row_record").await;

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_operations_continue_after_error() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;

    // Error: encrypt before session
    tx.send(make_request(Request::Encrypt(Encrypt {
        data: b"test".to_vec(),
    })))
    .await
    .unwrap();
    expect_error(&mut resp, "session not yet initialized").await;

    // Now properly initialize session — should still work
    do_get_session(&tx, &mut resp, "recovery-partition").await;

    let plaintext = b"after error recovery";
    let drr = do_encrypt(&tx, &mut resp, plaintext).await;
    let decrypted = do_decrypt(&tx, &mut resp, drr).await;
    assert_eq!(decrypted, plaintext);

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_multiple_operations_same_session() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;

    do_get_session(&tx, &mut resp, "multi-ops").await;

    // Encrypt and decrypt 20 different messages
    let mut drrs = Vec::new();
    for i in 0_u32..20 {
        let plaintext = format!("message number {i}");
        let drr = do_encrypt(&tx, &mut resp, plaintext.as_bytes()).await;
        drrs.push((plaintext, drr));
    }

    // Decrypt all in reverse order
    for (plaintext, drr) in drrs.into_iter().rev() {
        let decrypted = do_decrypt(&tx, &mut resp, drr).await;
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

// ============================================================
// Data integrity tests
// ============================================================

#[tokio::test]
#[serial]
async fn test_empty_payload() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;
    do_get_session(&tx, &mut resp, "empty").await;

    let drr = do_encrypt(&tx, &mut resp, b"").await;
    let decrypted = do_decrypt(&tx, &mut resp, drr).await;
    assert!(decrypted.is_empty());

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_large_payload_1mb() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;
    do_get_session(&tx, &mut resp, "large").await;

    let plaintext = vec![0xAB_u8; 1024 * 1024];
    let drr = do_encrypt(&tx, &mut resp, &plaintext).await;
    let decrypted = do_decrypt(&tx, &mut resp, drr).await;
    assert_eq!(decrypted.len(), 1024 * 1024);
    assert_eq!(decrypted, plaintext);

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_binary_payload_all_byte_values() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;
    do_get_session(&tx, &mut resp, "binary").await;

    let plaintext: Vec<u8> = (0..=255).collect();
    let drr = do_encrypt(&tx, &mut resp, &plaintext).await;
    let decrypted = do_decrypt(&tx, &mut resp, drr).await;
    assert_eq!(decrypted, plaintext);

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_unicode_payload() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;
    do_get_session(&tx, &mut resp, "unicode").await;

    let text = "你好世界 🔐 Hello мир العربية";
    let plaintext = text.as_bytes();
    let drr = do_encrypt(&tx, &mut resp, plaintext).await;
    let decrypted = do_decrypt(&tx, &mut resp, drr).await;
    assert_eq!(decrypted, plaintext);
    assert_eq!(std::str::from_utf8(&decrypted).unwrap(), text);

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_single_byte_payload() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;
    do_get_session(&tx, &mut resp, "single").await;

    let drr = do_encrypt(&tx, &mut resp, &[0x42]).await;
    let decrypted = do_decrypt(&tx, &mut resp, drr).await;
    assert_eq!(decrypted, vec![0x42]);

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

// ============================================================
// Concurrency tests
// ============================================================

#[tokio::test]
#[serial]
async fn test_concurrent_sessions() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut handles = Vec::new();

    for i in 0_u32..10 {
        let sock = sock.clone();
        handles.push(tokio::spawn(async move {
            let mut client = connect(sock).await;
            let (tx, mut resp) = open_session(&mut client).await;

            do_get_session(&tx, &mut resp, &format!("concurrent-{i}")).await;

            let plaintext = format!("data-from-session-{i}");
            let drr = do_encrypt(&tx, &mut resp, plaintext.as_bytes()).await;
            let decrypted = do_decrypt(&tx, &mut resp, drr).await;
            assert_eq!(decrypted, plaintext.as_bytes());

            drop(tx);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_rapid_connect_disconnect() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Rapidly open and close 50 sessions
    for i in 0_u32..50 {
        let mut client = connect(sock.clone()).await;
        let (tx, mut resp) = open_session(&mut client).await;
        do_get_session(&tx, &mut resp, &format!("rapid-{i}")).await;
        drop(tx);
    }

    // Server should still work after rapid cycling
    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;
    do_get_session(&tx, &mut resp, "after-rapid").await;

    let drr = do_encrypt(&tx, &mut resp, b"still alive").await;
    let decrypted = do_decrypt(&tx, &mut resp, drr).await;
    assert_eq!(decrypted, b"still alive");

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

// ============================================================
// Connection lifecycle tests
// ============================================================

#[tokio::test]
#[serial]
async fn test_client_disconnect_recovery() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Open session, do some work, then disconnect abruptly
    {
        let mut client = connect(sock.clone()).await;
        let (tx, mut resp) = open_session(&mut client).await;
        do_get_session(&tx, &mut resp, "will-disconnect").await;
        let _drr = do_encrypt(&tx, &mut resp, b"about to disconnect").await;
        // Drop everything — abrupt disconnect
    }

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Server should accept new connections fine
    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;
    do_get_session(&tx, &mut resp, "after-disconnect").await;

    let drr = do_encrypt(&tx, &mut resp, b"recovered").await;
    let decrypted = do_decrypt(&tx, &mut resp, drr).await;
    assert_eq!(decrypted, b"recovered");

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_multiple_sequential_sessions_same_client() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;

    for i in 0_u32..5 {
        let (tx, mut resp) = open_session(&mut client).await;
        do_get_session(&tx, &mut resp, &format!("seq-{i}")).await;

        let plaintext = format!("session {i} data");
        let drr = do_encrypt(&tx, &mut resp, plaintext.as_bytes()).await;
        let decrypted = do_decrypt(&tx, &mut resp, drr).await;
        assert_eq!(decrypted, plaintext.as_bytes());

        drop(tx);
    }

    drop(std::fs::remove_file(&sock));
}

// ============================================================
// DRR structure validation
// ============================================================

#[tokio::test]
#[serial]
async fn test_encrypted_drr_has_required_fields() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;
    do_get_session(&tx, &mut resp, "drr-check").await;

    let drr = do_encrypt(&tx, &mut resp, b"check structure").await;

    // DRR must have a key
    assert!(drr.key.is_some(), "encrypted DRR must have envelope key");
    let key = drr.key.unwrap();

    // Key must have created timestamp > 0
    assert!(key.created > 0, "key created timestamp must be positive");

    // Key must have non-empty encrypted key bytes
    assert!(!key.key.is_empty(), "encrypted key must be non-empty");

    // Key must have parent key meta
    assert!(
        key.parent_key_meta.is_some(),
        "key must have parent key meta"
    );
    let meta = key.parent_key_meta.unwrap();

    // Parent key meta must have non-empty key_id
    assert!(!meta.key_id.is_empty(), "parent key meta must have key_id");

    // Parent key meta must have created timestamp > 0
    assert!(meta.created > 0, "parent key meta created must be positive");

    // Data must be non-empty (encrypted ciphertext)
    assert!(!drr.data.is_empty(), "encrypted data must be non-empty");

    // Encrypted data must differ from plaintext
    assert_ne!(drr.data, b"check structure");

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_different_plaintexts_produce_different_ciphertexts() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;
    do_get_session(&tx, &mut resp, "diff").await;

    let drr1 = do_encrypt(&tx, &mut resp, b"plaintext A").await;
    let drr2 = do_encrypt(&tx, &mut resp, b"plaintext B").await;

    // Different plaintexts should produce different ciphertexts
    assert_ne!(drr1.data, drr2.data);

    // Both should decrypt correctly
    let d1 = do_decrypt(&tx, &mut resp, drr1).await;
    let d2 = do_decrypt(&tx, &mut resp, drr2).await;
    assert_eq!(d1, b"plaintext A");
    assert_eq!(d2, b"plaintext B");

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

#[tokio::test]
#[serial]
async fn test_same_plaintext_produces_different_ciphertexts() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = connect(sock.clone()).await;
    let (tx, mut resp) = open_session(&mut client).await;
    do_get_session(&tx, &mut resp, "nonce").await;

    // AES-GCM uses random nonce, so same plaintext → different ciphertext
    let drr1 = do_encrypt(&tx, &mut resp, b"same data").await;
    let drr2 = do_encrypt(&tx, &mut resp, b"same data").await;
    assert_ne!(
        drr1.data, drr2.data,
        "nonces should make ciphertexts differ"
    );

    let d1 = do_decrypt(&tx, &mut resp, drr1).await;
    let d2 = do_decrypt(&tx, &mut resp, drr2).await;
    assert_eq!(d1, b"same data");
    assert_eq!(d2, b"same data");

    drop(tx);
    drop(std::fs::remove_file(&sock));
}

// ============================================================
// Async path stress tests
// ============================================================

/// 50 concurrent sessions each doing 10 encrypt/decrypt roundtrips.
/// This exercises the async encrypt_async/decrypt_async path under
/// heavy concurrency — verifies no tokio worker starvation.
#[tokio::test]
#[serial]
async fn test_heavy_concurrent_async_roundtrips() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut handles = Vec::new();
    for i in 0_u32..50 {
        let sock = sock.clone();
        handles.push(tokio::spawn(async move {
            let mut client = connect(sock).await;
            let (tx, mut resp) = open_session(&mut client).await;
            do_get_session(&tx, &mut resp, &format!("heavy-async-{i}")).await;

            for j in 0..10 {
                let plaintext = format!("heavy-{i}-op-{j}");
                let drr = do_encrypt(&tx, &mut resp, plaintext.as_bytes()).await;
                let decrypted = do_decrypt(&tx, &mut resp, drr).await;
                assert_eq!(decrypted, plaintext.as_bytes());
            }

            drop(tx);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
    drop(std::fs::remove_file(&sock));
}

/// Multiple sessions sharing partitions with interleaved operations.
/// Verifies async encrypt/decrypt produces correct results when
/// different sessions operate on overlapping partitions concurrently.
#[tokio::test]
#[serial]
async fn test_concurrent_shared_partition_async() {
    let sock = socket_path();
    let _server = start_server(&sock).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut handles = Vec::new();
    // 20 sessions all using 4 shared partitions
    for i in 0_u32..20 {
        let sock = sock.clone();
        handles.push(tokio::spawn(async move {
            let partition = format!("shared-{}", i % 4);
            let mut client = connect(sock).await;
            let (tx, mut resp) = open_session(&mut client).await;
            do_get_session(&tx, &mut resp, &partition).await;

            let plaintext = format!("shared-data-{i}");
            let drr = do_encrypt(&tx, &mut resp, plaintext.as_bytes()).await;
            let decrypted = do_decrypt(&tx, &mut resp, drr).await;
            assert_eq!(decrypted, plaintext.as_bytes());

            drop(tx);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
    drop(std::fs::remove_file(&sock));
}
