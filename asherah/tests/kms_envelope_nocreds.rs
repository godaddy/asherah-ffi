#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]
//! `AwsKmsEnvelope` with no AWS credentials available.
//!
//! Its own binary because the fence differs from the other error-path
//! tests: no access key is set, so the default credential chain finds
//! nothing (config files point nowhere, IMDS is disabled). The guard
//! confirms that before any client is built. The endpoint is a loopback
//! listener that counts connections; none is expected, because the SDK
//! fails while resolving credentials, before dispatch.

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
    fence_env, install_capture, take_all_records, Creds, RegionEnv,
};

static CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Text from the credential chain's Display that must not reach a sink.
const CHAIN_TEXT: &[&str] = &[
    "credential provider",
    "environment variable",
    "Environment",
    "Profile",
    "WebIdentityToken",
    "IMDS",
    "Ec2InstanceMetadata",
    "nonexistent",
];

#[test]
fn missing_credentials_are_named() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    drop(std::thread::spawn(move || {
        for s in listener.incoming().flatten() {
            CONNECTIONS.fetch_add(1, Ordering::SeqCst);
            drop(s);
        }
    }));
    fence_env(&endpoint, Creds::Absent, RegionEnv::Set);
    assert_loopback_only(&endpoint, Creds::Absent);
    install_capture();

    let (enc, dec, recs) = bounded(30, || {
        let kms = AwsKmsEnvelope::new_single(
            Arc::new(AES256GCM::new()),
            "arn:aws:kms:us-west-2:000000000000:key/nocreds".to_string(),
            Some("us-west-2".to_string()),
            None,
        )
        .unwrap();
        let enc = format!("{:#}", kms.encrypt_key(&(), &[1_u8; 32]).unwrap_err());
        let blob = serde_json::to_vec(&serde_json::json!({
            "encryptedKey": base64::engine::general_purpose::STANDARD.encode([1, 2, 3, 4]),
            "kmsKeks": [{
                "region": "us-west-2",
                "arn": "arn:aws:kms:us-west-2:000000000000:key/nocreds",
                "encryptedKek": base64::engine::general_purpose::STANDARD.encode(b"kek"),
            }],
        }))
        .unwrap();
        let dec = format!("{:#}", kms.decrypt_key(&(), &blob).unwrap_err());
        (enc, dec, take_all_records())
    });
    let line = envelope_error_line(&recs);
    println!("no credentials, encrypt\n  error: {enc}");
    println!("no credentials, decrypt\n  error: {dec}\n  error log: {line}");

    assert_eq!(
        enc,
        "KMS GenerateDataKey failed in region us-west-2: \
         dispatch failure (other: no credentials available)"
    );
    let detail =
        "tried regions: us-west-2 [Decrypt dispatch failure (other: no credentials available)]";
    assert_eq!(
        dec,
        format!("all KMS backends failed to decrypt ({detail})")
    );
    assert_eq!(
        line,
        format!("AwsKmsEnvelope decrypt_key: all backends failed: {detail}")
    );
    for s in [&enc, &dec] {
        assert_clean("no-credentials error", s);
        for t in CHAIN_TEXT {
            assert!(!s.contains(t), "credential chain text {t:?} in {s}");
        }
    }
    assert_records_clean(&recs);
    for r in &recs {
        for t in CHAIN_TEXT {
            assert!(
                !r.message.contains(t),
                "credential chain text {t:?} in [{} {}] {}",
                r.level,
                r.target,
                r.message
            );
        }
    }
    assert_eq!(
        CONNECTIONS.load(Ordering::SeqCst),
        0,
        "no request may leave the client"
    );
}
