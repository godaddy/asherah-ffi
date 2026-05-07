//! Interop test client for the asherah gRPC server.
//!
//! Connects to a single server (via `--socket <path>`) and runs a fixed
//! sequence of assertions, emitting one JSON line per check to stdout. The
//! harness invokes this binary twice (once against the Go reference server,
//! once against the Rust server) and diffs the JSON outputs to detect any
//! divergence in observable wire behavior.
//!
//! Operations covered:
//!   * Connect (asserts socket is bindable + accepts a streaming session)
//!   * GetSession with a valid partition (asserts empty success response)
//!   * GetSession-twice on same stream (asserts error response)
//!   * Encrypt-before-GetSession (asserts error response)
//!   * Encrypt round-trip (asserts a DRR with all required fields)
//!   * Decrypt round-trip of the just-encrypted DRR (asserts plaintext match)
//!   * Decrypt of an externally-supplied DRR (for cross-server interop:
//!     encrypt with server A, save DRR, decrypt with server B)
//!
//! The DRR-export path lets the harness validate cryptographic interop
//! between the two implementations using a shared metastore + same KMS key.

mod proto {
    tonic::include_proto!("asherah.apps.server");
}

use clap::{Parser, Subcommand};
use proto::app_encryption_client::AppEncryptionClient;
use proto::session_request::Request;
use proto::session_response::Response;
use proto::{Decrypt, Encrypt, GetSession, SessionRequest};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

#[derive(Parser, Debug)]
#[command(about = "Asherah gRPC interop test client")]
struct Cli {
    /// Path to the unix domain socket where the asherah-server is listening.
    #[arg(long)]
    socket: PathBuf,

    /// Partition identifier used for the GetSession call.
    #[arg(long, default_value = "interop-partition")]
    partition: String,

    /// Plaintext payload (utf-8) used for the encrypt round-trip.
    #[arg(long, default_value = "interop-test-data")]
    payload: String,

    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Run the full single-server assertion suite. Emits JSON lines to
    /// stdout, one per check, plus a final `summary` line. Exits 0 if
    /// every check passed, 1 otherwise.
    Suite,
    /// Encrypt the payload and print the resulting DRR as JSON to stdout
    /// (one line). The harness captures this for cross-server decrypt
    /// testing. No assertion sweep — minimal output.
    Encrypt,
    /// Read a DRR from stdin (the JSON line emitted by `encrypt` mode) and
    /// decrypt it against this server. Exits 0 + prints `{"plaintext_match":
    /// true|false}` based on whether the result matches `--payload`.
    Decrypt,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DrrJson {
    key_id: String,
    created: i64,
    parent_key_id: String,
    parent_key_created: i64,
    encrypted_key: Vec<u8>,
    data: Vec<u8>,
}

impl DrrJson {
    fn from_proto(d: proto::DataRowRecord) -> Self {
        let key = d.key.unwrap_or_default();
        let parent = key.parent_key_meta.unwrap_or_default();
        Self {
            key_id: parent.key_id,
            created: key.created,
            parent_key_id: String::new(),
            parent_key_created: parent.created,
            encrypted_key: key.key,
            data: d.data,
        }
    }

    fn into_proto(self) -> proto::DataRowRecord {
        proto::DataRowRecord {
            data: self.data,
            key: Some(proto::EnvelopeKeyRecord {
                created: self.created,
                key: self.encrypted_key,
                parent_key_meta: Some(proto::KeyMeta {
                    key_id: self.key_id,
                    created: self.parent_key_created,
                }),
            }),
        }
    }
}

#[derive(Serialize)]
struct CheckResult<'a> {
    check: &'a str,
    pass: bool,
    detail: String,
}

fn emit(check: &str, pass: bool, detail: String) {
    let r = CheckResult {
        check,
        pass,
        detail,
    };
    println!("{}", serde_json::to_string(&r).expect("json serialize"));
}

async fn connect(sock: PathBuf) -> AppEncryptionClient<tonic::transport::Channel> {
    let channel = tokio::time::timeout(Duration::from_secs(15), async {
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
            .expect("tonic connect failed")
    })
    .await
    .expect("connect timed out after 15s");
    AppEncryptionClient::new(channel)
}

fn req(r: Request) -> SessionRequest {
    SessionRequest { request: Some(r) }
}

async fn run_suite(cli: &Cli) -> i32 {
    let mut all_pass = true;
    let mut record_fail = |c: &str, d: String| {
        all_pass = false;
        emit(c, false, d);
    };

    // 1. Connect
    let mut client = connect(cli.socket.clone()).await;
    emit("connect", true, format!("dialed {}", cli.socket.display()));

    // 2. GetSession (success → empty response)
    {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let stream = ReceiverStream::new(rx);
        let resp = client.session(stream).await.expect("session rpc");
        let mut resp = resp.into_inner();
        tx.send(req(Request::GetSession(GetSession {
            partition_id: cli.partition.clone(),
        })))
        .await
        .unwrap();
        let msg = resp.next().await.unwrap().expect("get_session response");
        if msg.response.is_none() {
            emit("get_session_success", true, "empty response as expected".to_string());
        } else {
            record_fail(
                "get_session_success",
                format!("expected empty response, got {:?}", msg.response),
            );
        }
        drop(tx);
        drop(resp);
    }

    // 3. Double GetSession (error)
    {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let stream = ReceiverStream::new(rx);
        let resp = client.session(stream).await.expect("session rpc");
        let mut resp = resp.into_inner();
        tx.send(req(Request::GetSession(GetSession {
            partition_id: cli.partition.clone(),
        })))
        .await
        .unwrap();
        let _ = resp.next().await.unwrap().unwrap();
        tx.send(req(Request::GetSession(GetSession {
            partition_id: cli.partition.clone(),
        })))
        .await
        .unwrap();
        let msg = resp.next().await.unwrap().expect("second get_session");
        match msg.response {
            Some(Response::ErrorResponse(_)) => {
                emit("double_get_session_errors", true, "got ErrorResponse".to_string())
            }
            other => record_fail(
                "double_get_session_errors",
                format!("expected ErrorResponse, got {other:?}"),
            ),
        }
        drop(tx);
        drop(resp);
    }

    // 4. Encrypt before GetSession (error)
    {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let stream = ReceiverStream::new(rx);
        let resp = client.session(stream).await.expect("session rpc");
        let mut resp = resp.into_inner();
        tx.send(req(Request::Encrypt(Encrypt {
            data: cli.payload.as_bytes().to_vec(),
        })))
        .await
        .unwrap();
        let msg = resp.next().await.unwrap().expect("encrypt response");
        match msg.response {
            Some(Response::ErrorResponse(_)) => emit(
                "encrypt_before_session_errors",
                true,
                "got ErrorResponse".to_string(),
            ),
            other => record_fail(
                "encrypt_before_session_errors",
                format!("expected ErrorResponse, got {other:?}"),
            ),
        }
        drop(tx);
        drop(resp);
    }

    // 5. Encrypt round-trip — DRR has expected structural fields
    let drr = {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let stream = ReceiverStream::new(rx);
        let resp = client.session(stream).await.expect("session rpc");
        let mut resp = resp.into_inner();
        tx.send(req(Request::GetSession(GetSession {
            partition_id: cli.partition.clone(),
        })))
        .await
        .unwrap();
        let _ = resp.next().await.unwrap().unwrap();
        tx.send(req(Request::Encrypt(Encrypt {
            data: cli.payload.as_bytes().to_vec(),
        })))
        .await
        .unwrap();
        let msg = resp.next().await.unwrap().expect("encrypt response");
        let drr_proto = match msg.response {
            Some(Response::EncryptResponse(r)) => r.data_row_record.expect("DRR field present"),
            other => {
                record_fail("encrypt_returns_drr", format!("got {other:?}"));
                return if all_pass { 0 } else { 1 };
            }
        };
        let key = drr_proto.key.as_ref().expect("key field");
        let parent = key.parent_key_meta.as_ref().expect("parent_key_meta field");
        let mut field_pass = !drr_proto.data.is_empty()
            && !key.key.is_empty()
            && !parent.key_id.is_empty()
            && key.created > 0
            && parent.created > 0;
        if field_pass {
            emit(
                "encrypt_returns_drr",
                true,
                format!(
                    "ciphertext={}B, encrypted_key={}B, key_id={}",
                    drr_proto.data.len(),
                    key.key.len(),
                    parent.key_id
                ),
            );
        } else {
            // Use field_pass to suppress unused_mut warning if we add more.
            field_pass = false;
            record_fail(
                "encrypt_returns_drr",
                format!("DRR field shape unexpected: {drr_proto:?}, {field_pass}"),
            );
        }

        // Decrypt with same session
        tx.send(req(Request::Decrypt(Decrypt {
            data_row_record: Some(drr_proto.clone()),
        })))
        .await
        .unwrap();
        let msg = resp.next().await.unwrap().expect("decrypt response");
        match msg.response {
            Some(Response::DecryptResponse(r)) if r.data == cli.payload.as_bytes() => emit(
                "decrypt_round_trip_matches",
                true,
                format!("recovered {}B plaintext", r.data.len()),
            ),
            Some(Response::DecryptResponse(r)) => record_fail(
                "decrypt_round_trip_matches",
                format!("plaintext mismatch: got {}B", r.data.len()),
            ),
            other => record_fail(
                "decrypt_round_trip_matches",
                format!("expected DecryptResponse, got {other:?}"),
            ),
        }

        drop(tx);
        drop(resp);
        drr_proto
    };

    emit(
        "summary",
        all_pass,
        format!("drr_data_len={}", drr.data.len()),
    );
    if all_pass {
        0
    } else {
        1
    }
}

async fn run_encrypt(cli: &Cli) -> i32 {
    let mut client = connect(cli.socket.clone()).await;
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let stream = ReceiverStream::new(rx);
    let resp = client.session(stream).await.expect("session rpc");
    let mut resp = resp.into_inner();
    tx.send(req(Request::GetSession(GetSession {
        partition_id: cli.partition.clone(),
    })))
    .await
    .unwrap();
    let _ = resp.next().await.unwrap().unwrap();
    tx.send(req(Request::Encrypt(Encrypt {
        data: cli.payload.as_bytes().to_vec(),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().expect("encrypt response");
    let drr_proto = match msg.response {
        Some(Response::EncryptResponse(r)) => r.data_row_record.expect("DRR field"),
        other => {
            eprintln!("encrypt failed: {other:?}");
            return 1;
        }
    };
    let drr = DrrJson::from_proto(drr_proto);
    println!("{}", serde_json::to_string(&drr).expect("json"));
    drop(tx);
    drop(resp);
    0
}

async fn run_decrypt(cli: &Cli) -> i32 {
    let mut input = String::new();
    use std::io::Read;
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("stdin read");
    let drr: DrrJson = serde_json::from_str(input.trim()).expect("parse DRR JSON");

    let mut client = connect(cli.socket.clone()).await;
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let stream = ReceiverStream::new(rx);
    let resp = client.session(stream).await.expect("session rpc");
    let mut resp = resp.into_inner();
    tx.send(req(Request::GetSession(GetSession {
        partition_id: cli.partition.clone(),
    })))
    .await
    .unwrap();
    let _ = resp.next().await.unwrap().unwrap();
    tx.send(req(Request::Decrypt(Decrypt {
        data_row_record: Some(drr.into_proto()),
    })))
    .await
    .unwrap();
    let msg = resp.next().await.unwrap().expect("decrypt response");
    match msg.response {
        Some(Response::DecryptResponse(r)) => {
            let matches = r.data == cli.payload.as_bytes();
            println!(
                "{}",
                serde_json::json!({"plaintext_match": matches, "len": r.data.len()})
            );
            if matches {
                0
            } else {
                1
            }
        }
        other => {
            eprintln!("decrypt failed: {other:?}");
            println!("{}", serde_json::json!({"plaintext_match": false}));
            1
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = match cli.mode {
        Mode::Suite => run_suite(&cli).await,
        Mode::Encrypt => run_encrypt(&cli).await,
        Mode::Decrypt => run_decrypt(&cli).await,
    };
    std::process::exit(code);
}
