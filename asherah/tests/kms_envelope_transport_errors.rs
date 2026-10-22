#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]
//! `AwsKmsEnvelope` failures that never get an answer from a KMS endpoint:
//! connection refused, connect timeout, and no region configured.
//!
//! Each scenario needs its own endpoint or region environment, and both
//! are process-wide, so the scenarios run sequentially from one test. Each
//! re-applies the full fence (dummy credentials, no config files, IMDS
//! off, loopback endpoint) and re-checks it before building a client, and
//! each call runs under a deadline so an unexpected wait fails the test.

#[path = "support/kms_fence.rs"]
mod kms_fence;

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use asherah::aead::AES256GCM;
use asherah::kms_aws_envelope::AwsKmsEnvelope;
use asherah::traits::KeyManagementService;
use base64::Engine as _;
use kms_fence::{
    assert_clean, assert_loopback_only, assert_records_clean, bounded, envelope_error_line,
    fence_env, install_capture, take_all_records, Creds, Rec, RegionEnv,
};

const KEY_ID: &str = "arn:aws:kms:us-west-2:000000000000:key/transport";

fn envelope_json(region: &str) -> Vec<u8> {
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    serde_json::to_vec(&serde_json::json!({
        "encryptedKey": b64(&[1, 2, 3, 4]),
        "kmsKeks": [{ "region": region, "arn": KEY_ID, "encryptedKek": b64(b"kek") }],
    }))
    .unwrap()
}

struct Outcome {
    encrypt: String,
    decrypt: String,
    records: Vec<Rec>,
}

/// Fence for `endpoint`, then build a client (region from `region`, or the
/// default chain when `None`) and run one encrypt and one decrypt of an
/// envelope whose KEK region is `envelope_region`.
fn run(
    endpoint: &str,
    env_region: RegionEnv,
    region: Option<&str>,
    envelope_region: &'static str,
) -> Outcome {
    fence_env(endpoint, Creds::Dummy, env_region);
    assert_loopback_only(endpoint, Creds::Dummy);
    drop(take_all_records());
    let region = region.map(str::to_string);
    bounded(30, move || {
        let kms = AwsKmsEnvelope::new_single(
            Arc::new(AES256GCM::new()),
            KEY_ID.to_string(),
            region,
            None,
        )
        .unwrap();
        let encrypt = format!("{:#}", kms.encrypt_key(&(), &[1_u8; 32]).unwrap_err());
        let decrypt = format!(
            "{:#}",
            kms.decrypt_key(&(), &envelope_json(envelope_region))
                .unwrap_err()
        );
        Outcome {
            encrypt,
            decrypt,
            records: take_all_records(),
        }
    })
}

fn check(label: &str, out: &Outcome, encrypt: &str, decrypt_detail: &str, port: u16) {
    let line = envelope_error_line(&out.records);
    println!("{label}, encrypt\n  error: {}", out.encrypt);
    println!(
        "{label}, decrypt\n  error: {}\n  error log: {line}",
        out.decrypt
    );
    assert_eq!(out.encrypt, encrypt, "{label}");
    assert_eq!(
        out.decrypt,
        format!("all KMS backends failed to decrypt ({decrypt_detail})"),
        "{label}"
    );
    assert_eq!(
        line,
        format!("AwsKmsEnvelope decrypt_key: all backends failed: {decrypt_detail}"),
        "{label}"
    );
    // Connector errors' Display carries the address; it must not leak.
    let port = port.to_string();
    for s in [&out.encrypt, &out.decrypt] {
        assert_clean(label, s);
        assert!(!s.contains("127.0.0.1"), "{label}: address in {s}");
        assert!(!s.contains(&port), "{label}: port in {s}");
        assert!(!s.contains("tcp connect"), "{label}: connector text in {s}");
    }
    assert_records_clean(&out.records);
    for r in &out.records {
        assert!(!r.message.contains("127.0.0.1"), "{label}: {}", r.message);
    }
}

#[test]
fn client_side_failures_name_their_cause() {
    install_capture();

    // Connection refused: a loopback port with no listener.
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let out = run(
        &format!("http://127.0.0.1:{port}"),
        RegionEnv::Set,
        Some("us-west-2"),
        "us-west-2",
    );
    check(
        "connection refused",
        &out,
        "KMS GenerateDataKey failed in region us-west-2: dispatch failure (io: connection refused)",
        "tried regions: us-west-2 [Decrypt dispatch failure (io: connection refused)]",
        port,
    );

    // No region: AWS_REGION unset and no region passed, so the client
    // resolves none. Nothing is sent; the listener counts connections.
    static CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            CONNECTIONS.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    }));
    let endpoint = format!("http://127.0.0.1:{port}");
    // An envelope written for a real region: the reader has no region to
    // match it with.
    let out = run(&endpoint, RegionEnv::Unset, None, "us-west-2");
    check(
        "no region, ordinary envelope",
        &out,
        "KMS GenerateDataKey not sent: no region configured",
        "no matching regions found; configured regions: <unrecognized region>; \
         envelope regions: us-west-2",
        port,
    );
    // An envelope whose KEK region is empty matches the empty resolved
    // region, which reaches the no-region check on the decrypt path.
    let out = run(&endpoint, RegionEnv::Unset, None, "");
    check(
        "no region, empty-region envelope",
        &out,
        "KMS GenerateDataKey not sent: no region configured",
        "tried regions: <unrecognized region> [Decrypt not sent: no region configured]",
        port,
    );
    assert_eq!(CONNECTIONS.load(Ordering::SeqCst), 0);

    // Connect timeout: a listener that never accepts, with its accept
    // backlog filled so further connection attempts get no answer. The
    // SDK's default connect timeout (3.1 s) then fires on each call.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let mut held: Vec<TcpStream> = Vec::new();
    let mut backlog_full = false;
    for _ in 0..4096 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(s) => held.push(s),
            Err(_) => {
                backlog_full = true;
                break;
            }
        }
    }
    assert!(
        backlog_full,
        "could not fill the accept backlog after {} connections; the connect-timeout \
         scenario cannot be produced on this host",
        held.len()
    );
    let t0 = Instant::now();
    let out = run(
        &format!("http://{addr}"),
        RegionEnv::Set,
        Some("us-west-2"),
        "us-west-2",
    );
    println!(
        "connect timeout: backlog filled after {} connections, both calls took {:?}",
        held.len(),
        t0.elapsed()
    );
    check(
        "connect timeout",
        &out,
        "KMS GenerateDataKey failed in region us-west-2: dispatch failure (timeout)",
        "tried regions: us-west-2 [Decrypt dispatch failure (timeout)]",
        addr.port(),
    );
    drop(held);
    drop(listener);
}
