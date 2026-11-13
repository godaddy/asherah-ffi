#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]
//! `AwsKmsEnvelope` with a container credentials endpoint that refuses
//! the connection.
//!
//! The failure's source chain holds a `CredentialsError` above an
//! `std::io::Error` (connection refused). The label must name the
//! credentials failure, not the I/O error beneath it, which would read as
//! though the KMS endpoint had refused the connection.
//!
//! Its own binary because the fence differs: no access key is set and
//! `AWS_CONTAINER_CREDENTIALS_FULL_URI` points at a closed loopback port,
//! so the default credential chain reaches the container provider and
//! fails there. The KMS endpoint is a loopback listener that counts
//! connections; none is expected.

#[path = "support/kms_fence.rs"]
mod kms_fence;

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use asherah::aead::AES256GCM;
use asherah::kms_aws_envelope::AwsKmsEnvelope;
use asherah::traits::KeyManagementService;
use base64::Engine as _;
use kms_fence::{
    assert_clean, assert_loopback_only, assert_records_clean, bounded, envelope_error_line,
    fence_env, host_of, install_capture, take_all_records, Creds, RegionEnv,
};

static CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

#[test]
fn credentials_failure_is_named_before_the_io_error_beneath_it() {
    let kms_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!(
        "http://127.0.0.1:{}",
        kms_listener.local_addr().unwrap().port()
    );
    drop(std::thread::spawn(move || {
        for s in kms_listener.incoming().flatten() {
            CONNECTIONS.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    }));
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let creds_port = closed.local_addr().unwrap().port();
    drop(closed);
    let creds_uri = format!("http://127.0.0.1:{creds_port}/creds");

    fence_env(&endpoint, Creds::Absent, RegionEnv::Set);
    std::env::set_var("AWS_CONTAINER_CREDENTIALS_FULL_URI", &creds_uri);
    assert_eq!(
        host_of(&std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI").unwrap()),
        "127.0.0.1",
        "refusing to run: container credentials URI is not loopback"
    );
    assert_loopback_only(&endpoint, Creds::Absent);
    install_capture();
    drop(take_all_records());

    let (enc, dec, recs) = bounded(60, || {
        let kms = AwsKmsEnvelope::new_single(
            Arc::new(AES256GCM::new()),
            "arn:aws:kms:us-west-2:000000000000:key/container-creds".to_string(),
            Some("us-west-2".to_string()),
            None,
        )
        .unwrap();
        let enc = format!("{:#}", kms.encrypt_key(&(), &[1_u8; 32]).unwrap_err());
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let blob = serde_json::to_vec(&serde_json::json!({
            "encryptedKey": b64(&[1, 2, 3, 4]),
            "kmsKeks": [{
                "region": "us-west-2",
                "arn": "arn:aws:kms:us-west-2:000000000000:key/container-creds",
                "encryptedKek": b64(b"kek"),
            }],
        }))
        .unwrap();
        let dec = format!("{:#}", kms.decrypt_key(&(), &blob).unwrap_err());
        (enc, dec, take_all_records())
    });
    let line = envelope_error_line(&recs);
    println!("container credentials refused, encrypt\n  error: {enc}");
    println!("container credentials refused, decrypt\n  error: {dec}\n  error log: {line}");

    assert_eq!(
        enc,
        "KMS GenerateDataKey failed in region us-west-2: \
         dispatch failure (other: unexpected credentials provider failure)"
    );
    let detail = "tried regions: us-west-2 \
                  [Decrypt dispatch failure (other: unexpected credentials provider failure)]";
    assert_eq!(
        dec,
        format!("all KMS backends failed to decrypt ({detail})")
    );
    assert_eq!(
        line,
        format!("AwsKmsEnvelope decrypt_key: all backends failed: {detail}")
    );
    let port = creds_port.to_string();
    for s in [&enc, &dec] {
        assert_clean("container-credentials error", s);
        assert!(!s.contains("127.0.0.1"), "address in {s}");
        assert!(!s.contains(&port), "port in {s}");
        assert!(
            !s.contains("connection refused"),
            "io label won over credentials: {s}"
        );
    }
    assert_records_clean(&recs);
    assert_eq!(
        CONNECTIONS.load(Ordering::SeqCst),
        0,
        "no request may reach the KMS endpoint"
    );
}
