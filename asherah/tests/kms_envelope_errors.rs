#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]
//! Error-path tests for `AwsKmsEnvelope` against an offline fake KMS.
//!
//! The fake speaks the KMS JSON 1.1 protocol on an ephemeral 127.0.0.1
//! port. Before any SDK client is built, `fake()` points every AWS
//! configuration source at nothing (no config/credentials files, no
//! profile, no IMDS, no proxies), installs dummy static credentials,
//! sets `AWS_ENDPOINT_URL` to the fake, and fails if the SDK would
//! resolve any other endpoint. `AWS_MAX_ATTEMPTS=1` disables retries so
//! throttling and dropped-connection cases return immediately.
//!
//! The behaviour a mode triggers is selected by the key id the client
//! sends (`…:key/<test-tag>.<mode>`), so tests can run in parallel
//! against one server without shared mutable mode state.
//!
//! Failures that never reach a KMS endpoint (no credentials, no region,
//! connection refused, connect timeout) need a different fence and live
//! in `kms_envelope_nocreds.rs` and `kms_envelope_transport_errors.rs`.

#[path = "support/kms_fence.rs"]
mod kms_fence;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};

use asherah::aead::AES256GCM;
use asherah::kms_aws_envelope::AwsKmsEnvelope;
use asherah::kms_multi::MultiKms;
use asherah::traits::KeyManagementService;
use base64::Engine as _;
use kms_fence::{
    assert_clean, assert_loopback_only, assert_records_clean, envelope_error_line, fence_env,
    install_capture, take_thread_records, Creds, Rec, RegionEnv,
};

type Envelope = AwsKmsEnvelope<AES256GCM>;

const REQUEST_ID: &str = "4f6c8a1e-2b3d-4c5e-9f70-81a2b3c4d5e6";
const PLANTED_MESSAGE: &str =
    "User: arn:aws:sts::123456789012:assumed-role/planted-role/planted-session \
     is not authorized to perform: kms:Decrypt on resource: \
     arn:aws:kms:us-west-2:123456789012:key/planted-key because no identity-based policy allows it";
/// A region map with key and value swapped puts this where a region
/// belongs.
const SWAPPED_REGION: &str = "arn:aws:kms:us-west-2:111122223333:key/swapped-map-key";
const DATA_KEY: [u8; 32] = [0x42; 32];
const WRONG_DATA_KEY: [u8; 32] = [0x24; 32];

// ─────────────────────────────── fake KMS ───────────────────────────────

struct Fake {
    hits: Mutex<HashMap<String, usize>>,
}

impl Fake {
    fn hits(&self, op: &str, key_id: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .get(&format!("{op} {key_id}"))
            .copied()
            .unwrap_or(0)
    }
}

static FAKE: OnceLock<&'static Fake> = OnceLock::new();

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

struct Reply {
    status: u16,
    body: String,
    request_id: Option<String>,
    /// Content-Length to declare instead of the body's length; the fake
    /// then closes the connection after sending the shorter body.
    declared_len: Option<usize>,
}

fn error_reply(code: &str, request_id: Option<String>) -> Reply {
    Reply {
        status: 400,
        body: serde_json::json!({ "__type": code, "message": PLANTED_MESSAGE }).to_string(),
        request_id,
        declared_len: None,
    }
}

fn ok_reply(body: serde_json::Value) -> Reply {
    Reply {
        status: 200,
        body: body.to_string(),
        request_id: Some(REQUEST_ID.to_string()),
        declared_len: None,
    }
}

/// Map `(operation, mode)` to the fake's reply; `None` drops the connection.
fn reply_for(op: &str, mode: &str) -> Option<Reply> {
    let writer_arn = "arn:aws:kms:us-west-2:000000000000:key/fake-writer";
    match (op, mode) {
        (_, "drop") => None,
        ("GenerateDataKey", "ok") => Some(ok_reply(serde_json::json!({
            "CiphertextBlob": b64(b"fake-kek-ciphertext"),
            "KeyId": writer_arn,
            "Plaintext": b64(&DATA_KEY),
        }))),
        ("Encrypt", "ok") => Some(ok_reply(serde_json::json!({
            "CiphertextBlob": b64(b"fake-kek-ciphertext-secondary"),
            "KeyId": writer_arn,
        }))),
        ("Decrypt", "ok") => Some(ok_reply(serde_json::json!({
            "KeyId": writer_arn,
            "Plaintext": b64(&DATA_KEY),
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
        }))),
        ("Decrypt", "noplaintext") => Some(ok_reply(serde_json::json!({
            "KeyId": writer_arn,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
        }))),
        ("Decrypt", "wrongplaintext") => Some(ok_reply(serde_json::json!({
            "KeyId": writer_arn,
            "Plaintext": b64(&WRONG_DATA_KEY),
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
        }))),
        ("GenerateDataKey", "noplaintext") => Some(ok_reply(serde_json::json!({
            "CiphertextBlob": b64(b"fake-kek-ciphertext"),
            "KeyId": writer_arn,
        }))),
        (_, "badcode") => Some(error_reply(
            "Access Denied <script>",
            Some(REQUEST_ID.into()),
        )),
        (_, "longcode") => Some(error_reply(&"A".repeat(65), Some(REQUEST_ID.into()))),
        (_, "noreqid") => Some(error_reply("AccessDeniedException", None)),
        (_, "badreqid") => Some(error_reply(
            "AccessDeniedException",
            Some("req id; arn:aws:iam::123456789012".into()),
        )),
        (_, "longreqid") => Some(error_reply("AccessDeniedException", Some("a".repeat(65)))),
        (_, "digitreqid") => Some(error_reply(
            "AccessDeniedException",
            Some("123456789012".into()),
        )),
        (_, "html500") => Some(Reply {
            status: 500,
            body: format!("<html><body>proxy error {PLANTED_MESSAGE}</body></html>"),
            request_id: None,
            declared_len: None,
        }),
        (_, "truncated") => Some(Reply {
            status: 400,
            body: format!(r#"{{"__type":"AccessDeniedException","message":"{PLANTED_MESSAGE}"#),
            request_id: Some(REQUEST_ID.into()),
            declared_len: Some(8192),
        }),
        (_, code) => Some(error_reply(code, Some(REQUEST_ID.into()))),
    }
}

fn handle(mut s: TcpStream, fake: &'static Fake) {
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 4096];
    let header_end = loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p + 4;
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut target = String::new();
    let mut clen = 0_usize;
    for line in head.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "x-amz-target" => target = v.trim().to_string(),
            "content-length" => clen = v.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    while buf.len() < header_end + clen {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    let body: serde_json::Value =
        serde_json::from_slice(&buf[header_end..header_end + clen]).unwrap_or_default();
    let key_id = body
        .get("KeyId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let op = target
        .strip_prefix("TrentService.")
        .unwrap_or(&target)
        .to_string();
    *fake
        .hits
        .lock()
        .unwrap()
        .entry(format!("{op} {key_id}"))
        .or_default() += 1;
    let mode = key_id.rsplit('.').next().unwrap_or("");
    let Some(reply) = reply_for(&op, mode) else {
        drop(s.shutdown(Shutdown::Both));
        return;
    };
    let mut resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/x-amz-json-1.1\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        if reply.status == 200 { "OK" } else { "Error" },
        reply.declared_len.unwrap_or(reply.body.len())
    );
    if let Some(rid) = &reply.request_id {
        resp.push_str(&format!("x-amzn-RequestId: {rid}\r\n"));
    }
    resp.push_str("\r\n");
    resp.push_str(&reply.body);
    drop(s.write_all(resp.as_bytes()));
}

/// Start the fake once per process, fence the environment, verify the
/// fence, and install the log capture. Every test calls this before it
/// constructs a client.
fn fake() -> &'static Fake {
    FAKE.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        fence_env(&endpoint, Creds::Dummy, RegionEnv::Set);
        assert_loopback_only(&endpoint, Creds::Dummy);
        let fake: &'static Fake = Box::leak(Box::new(Fake {
            hits: Mutex::new(HashMap::new()),
        }));
        drop(std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                drop(std::thread::spawn(move || handle(s, fake)));
            }
        }));
        install_capture();
        fake
    })
}

// ─────────────────────────────── helpers ───────────────────────────────

fn key_arn(region: &str, tag: &str, mode: &str) -> String {
    format!("arn:aws:kms:{region}:000000000000:key/{tag}.{mode}")
}

fn single(region: &str, tag: &str, mode: &str) -> Envelope {
    Envelope::new_single(
        Arc::new(AES256GCM::new()),
        key_arn(region, tag, mode),
        Some(region.to_string()),
        None,
    )
    .unwrap()
}

fn multi(tag: &str, entries: &[(&str, &str)]) -> Envelope {
    Envelope::new_multi(
        Arc::new(AES256GCM::new()),
        0,
        entries
            .iter()
            .map(|(region, mode)| (region.to_string(), key_arn(region, tag, mode)))
            .collect(),
        None,
    )
    .unwrap()
}

/// An envelope whose KEK for `us-west-2` the fake's "ok" Decrypt unwraps.
fn written_envelope(tag: &str) -> Vec<u8> {
    let writer = single("us-west-2", tag, "ok");
    writer.encrypt_key(&(), &[7_u8; 32]).unwrap()
}

// ──────────────────────────────── tests ────────────────────────────────

#[test]
fn fence_resolves_loopback_endpoint_and_dummy_credentials() {
    let _ = fake();
    let ep = std::env::var("AWS_ENDPOINT_URL").unwrap();
    assert_loopback_only(&ep, Creds::Dummy);
}

#[test]
fn roundtrip_through_fake_succeeds() {
    let fake = fake();
    let tag = "roundtrip";
    let blob = written_envelope(tag);
    let reader = single("us-west-2", tag, "ok");
    assert_eq!(reader.decrypt_key(&(), &blob).unwrap(), vec![7_u8; 32]);
    assert_eq!(fake.hits("Decrypt", &key_arn("us-west-2", tag, "ok")), 1);
}

#[test]
fn decrypt_failure_modes_name_the_failed_step() {
    let fake = fake();
    let tag = "modes";
    let blob = written_envelope(tag);
    let rid = format!(", request id {REQUEST_ID}");
    let cases: Vec<(&str, &str, String)> = vec![
        (
            "AccessDeniedException",
            "us-west-2",
            format!("us-west-2 [Decrypt service error AccessDeniedException{rid}]"),
        ),
        (
            "IncorrectKeyException",
            "us-west-2",
            format!("us-west-2 [Decrypt service error IncorrectKeyException{rid}]"),
        ),
        (
            "InvalidCiphertextException",
            "us-west-2",
            format!("us-west-2 [Decrypt service error InvalidCiphertextException{rid}]"),
        ),
        (
            "DisabledException",
            "us-west-2",
            format!("us-west-2 [Decrypt service error DisabledException{rid}]"),
        ),
        (
            "NotFoundException",
            "us-west-2",
            format!("us-west-2 [Decrypt service error NotFoundException{rid}]"),
        ),
        (
            "KMSInvalidStateException",
            "us-west-2",
            format!("us-west-2 [Decrypt service error KMSInvalidStateException{rid}]"),
        ),
        (
            "ThrottlingException",
            "us-west-2",
            format!("us-west-2 [Decrypt service error ThrottlingException{rid}]"),
        ),
        (
            "drop",
            "us-west-2",
            "us-west-2 [Decrypt dispatch failure (other: transient error)]".to_string(),
        ),
        (
            "noplaintext",
            "us-west-2",
            format!("us-west-2 [Decrypt returned no plaintext{rid}]"),
        ),
        (
            "wrongplaintext",
            "us-west-2",
            format!("us-west-2 [data key failed envelope authentication{rid}]"),
        ),
        (
            "ok",
            "us-east-1",
            "no matching regions found; configured regions: us-east-1; envelope regions: us-west-2"
                .to_string(),
        ),
    ];
    drop(take_thread_records());
    let mut seen: Vec<(String, String)> = Vec::new();
    for (mode, region, expected) in &cases {
        let reader = single(region, tag, mode);
        let t0 = std::time::Instant::now();
        let err = reader.decrypt_key(&(), &blob).unwrap_err();
        let elapsed = t0.elapsed();
        let msg = format!("{err:#}");
        let recs = take_thread_records();
        let line = envelope_error_line(&recs);
        println!("mode={mode} region={region} elapsed={elapsed:?}");
        println!("  error: {msg}");
        println!("  error log: {line}");
        for r in recs
            .iter()
            .filter(|r| r.target == "asherah::kms_aws_envelope" && r.level != log::Level::Error)
        {
            println!("  [{}] {}", r.level, r.message);
        }
        let detail = if *region == "us-west-2" {
            format!("tried regions: {expected}")
        } else {
            expected.clone()
        };
        // Exact strings: nothing beyond the classification may be appended.
        assert_eq!(
            msg,
            format!("all KMS backends failed to decrypt ({detail})")
        );
        assert_eq!(
            line,
            format!("AwsKmsEnvelope decrypt_key: all backends failed: {detail}")
        );
        if *region == "us-west-2" {
            let reason = expected
                .strip_prefix("us-west-2 [")
                .and_then(|r| r.strip_suffix(']'))
                .unwrap();
            let debug_lines: Vec<&str> = recs
                .iter()
                .filter(|r| r.target == "asherah::kms_aws_envelope" && r.level == log::Level::Debug)
                .map(|r| r.message.as_str())
                .collect();
            assert_eq!(
                debug_lines,
                vec![format!(
                    "AwsKmsEnvelope decrypt_key: region=us-west-2 failed: {reason}"
                )],
                "mode {mode} debug lines"
            );
            assert_eq!(
                fake.hits("Decrypt", &key_arn(region, tag, mode)),
                1,
                "mode {mode} must reach the fake exactly once (retries disabled)"
            );
        } else {
            assert_eq!(fake.hits("Decrypt", &key_arn(region, tag, mode)), 0);
        }
        assert_clean(&format!("mode {mode} error"), &msg);
        assert_records_clean(&recs);
        assert!(!msg.contains("authentication tag"), "AEAD detail: {msg}");
        seen.push(((*mode).to_string(), msg));
    }
    for (i, (ma, a)) in seen.iter().enumerate() {
        for (mb, b) in seen.iter().skip(i + 1) {
            assert_ne!(a, b, "modes {ma} and {mb} are indistinguishable");
        }
    }
}

#[test]
fn server_supplied_identifiers_are_bounded() {
    let _ = fake();
    let tag = "bounded";
    let blob = written_envelope(tag);
    let cases = [
        (
            "badcode",
            "Decrypt service error <unrecognized error code>, request id 4f6c8a1e",
        ),
        (
            "longcode",
            "Decrypt service error <unrecognized error code>, request id 4f6c8a1e",
        ),
        ("noreqid", "Decrypt service error AccessDeniedException]"),
        (
            "badreqid",
            "Decrypt service error AccessDeniedException, request id <unrecognized request id>]",
        ),
        (
            "longreqid",
            "Decrypt service error AccessDeniedException, request id <unrecognized request id>]",
        ),
        (
            "digitreqid",
            "Decrypt service error AccessDeniedException, request id <unrecognized request id>]",
        ),
    ];
    drop(take_thread_records());
    for (mode, expected) in cases {
        let err = single("us-west-2", tag, mode)
            .decrypt_key(&(), &blob)
            .unwrap_err();
        let msg = format!("{err:#}");
        let recs = take_thread_records();
        println!("mode={mode}\n  error: {msg}");
        assert!(msg.contains(expected), "mode {mode}: {msg}");
        assert!(!msg.contains("script"), "{msg}");
        assert!(!msg.contains("AAAAAAAA"), "{msg}");
        assert!(!msg.contains("aaaaaaaa"), "{msg}");
        assert!(!msg.contains("req id"), "{msg}");
        assert_clean(&format!("mode {mode} error"), &msg);
        assert_records_clean(&recs);
    }
}

#[test]
fn unparseable_error_response_is_classified_without_body_text() {
    let _ = fake();
    let tag = "html";
    let blob = written_envelope(tag);
    drop(take_thread_records());
    let err = single("us-west-2", tag, "html500")
        .decrypt_key(&(), &blob)
        .unwrap_err();
    let msg = format!("{err:#}");
    let recs = take_thread_records();
    println!("mode=html500\n  error: {msg}");
    assert!(
        msg.contains("tried regions: us-west-2 [Decrypt service error (no error code, HTTP 500)]"),
        "{msg}"
    );
    assert!(!msg.contains("proxy error"), "{msg}");
    assert!(!msg.contains("html"), "{msg}");
    assert_clean("html500 error", &msg);
    assert_records_clean(&recs);
}

#[test]
fn multi_region_decrypt_reports_each_attempted_region() {
    let fake = fake();
    let tag = "multi";
    let writer = multi(tag, &[("us-west-2", "ok"), ("us-east-1", "ok")]);
    let blob = writer.encrypt_key(&(), &[9_u8; 32]).unwrap();
    assert_eq!(
        fake.hits("GenerateDataKey", &key_arn("us-west-2", tag, "ok")),
        1
    );
    assert_eq!(fake.hits("Encrypt", &key_arn("us-east-1", tag, "ok")), 1);

    let reader = multi(
        tag,
        &[
            ("us-west-2", "AccessDeniedException"),
            ("us-east-1", "ThrottlingException"),
        ],
    );
    drop(take_thread_records());
    let err = reader.decrypt_key(&(), &blob).unwrap_err();
    let msg = format!("{err:#}");
    let recs = take_thread_records();
    let line = envelope_error_line(&recs);
    println!("multi-region\n  error: {msg}\n  error log: {line}");
    let expected = format!(
        "all KMS backends failed to decrypt (tried regions: \
         us-west-2 [Decrypt service error AccessDeniedException, request id {REQUEST_ID}]; \
         us-east-1 [Decrypt service error ThrottlingException, request id {REQUEST_ID}])"
    );
    assert_eq!(msg, expected);
    assert!(
        line.ends_with(&expected["all KMS backends failed to decrypt (".len()..expected.len() - 1])
    );
    assert_clean("multi-region error", &msg);
    assert_records_clean(&recs);

    // One region fails, the other succeeds: the success path is unchanged.
    let mixed = multi(
        tag,
        &[("us-west-2", "AccessDeniedException"), ("us-east-1", "ok")],
    );
    assert_eq!(mixed.decrypt_key(&(), &blob).unwrap(), vec![9_u8; 32]);
}

#[test]
fn encrypt_errors_name_operation_and_region_without_aws_message() {
    let _ = fake();
    let tag = "encrypt";
    drop(take_thread_records());

    let err = single("us-west-2", tag, "AccessDeniedException")
        .encrypt_key(&(), &[1_u8; 32])
        .unwrap_err();
    let msg = format!("{err:#}");
    println!("GenerateDataKey AccessDenied\n  error: {msg}");
    assert_eq!(
        msg,
        format!(
            "KMS GenerateDataKey failed in region us-west-2: \
             service error AccessDeniedException, request id {REQUEST_ID}"
        )
    );
    assert_eq!(err.chain().count(), 1, "no SdkError source chain");
    assert_clean("GenerateDataKey error", &msg);

    let err = single("us-west-2", tag, "noplaintext")
        .encrypt_key(&(), &[1_u8; 32])
        .unwrap_err();
    let msg = format!("{err:#}");
    println!("GenerateDataKey no plaintext\n  error: {msg}");
    assert_eq!(
        msg,
        format!("KMS GenerateDataKey returned no plaintext in region us-west-2, request id {REQUEST_ID}")
    );

    let err = multi(
        tag,
        &[("us-west-2", "ok"), ("us-east-1", "DisabledException")],
    )
    .encrypt_key(&(), &[1_u8; 32])
    .unwrap_err();
    let msg = format!("{err:#}");
    println!("Encrypt (secondary region) Disabled\n  error: {msg}");
    assert_eq!(
        msg,
        format!(
            "KMS Encrypt failed in region us-east-1: \
             service error DisabledException, request id {REQUEST_ID}"
        )
    );
    assert_clean("Encrypt error", &msg);
    assert_records_clean(&take_thread_records());
}

#[test]
fn session_decrypt_error_chain_carries_region_detail() {
    let _ = fake();
    let tag = "session";
    let crypto = Arc::new(AES256GCM::new());
    let store = Arc::new(asherah::metastore::InMemoryMetastore::new());
    let cfg = || asherah::Config::new("svc", "prod");
    let writer_kms = Arc::new(single("us-west-2", tag, "ok"));
    let writer =
        asherah::api::new_session_factory(cfg(), store.clone(), writer_kms, crypto.clone());
    let drr = writer.get_session("p1").encrypt(b"payload").unwrap();

    let reader_kms = Arc::new(single("us-west-2", tag, "AccessDeniedException"));
    let reader = asherah::api::new_session_factory(cfg(), store, reader_kms, crypto);
    drop(take_thread_records());
    let err = reader.get_session("p1").decrypt(drr).unwrap_err();
    let chain = format!("{err:#}");
    let outer = format!("{err}");
    let recs = take_thread_records();
    println!("PublicSession::decrypt {{:#}}: {chain}");
    println!("PublicSession::decrypt {{}}: {outer}");
    for r in recs.iter().filter(|r| r.level <= log::Level::Warn) {
        println!("  [{} {}] {}", r.level, r.target, r.message);
    }
    let detail = format!(
        "all KMS backends failed to decrypt (tried regions: \
         us-west-2 [Decrypt service error AccessDeniedException, request id {REQUEST_ID}])"
    );
    assert!(chain.ends_with(&detail), "{chain}");
    assert_clean("session error chain", &chain);
    assert_records_clean(&recs);
}

/// An envelope with one KEK for `region` (the KEK bytes are never
/// decrypted successfully in the tests that use this).
fn envelope_json(region: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "encryptedKey": b64(&[1, 2, 3, 4]),
        "kmsKeks": [{
            "region": region,
            "arn": "arn:aws:kms:us-west-2:000000000000:key/fake-writer",
            "encryptedKek": b64(b"kek"),
        }],
    }))
    .unwrap()
}

fn assert_all_sinks_clean(what: &str, msg: &str, recs: &[Rec]) {
    assert_clean(what, msg);
    assert_records_clean(recs);
}

#[test]
fn swapped_region_map_never_prints_the_key_arn() {
    let fake = fake();
    let tag = "swapped";
    // REGION_MAP {"<key ARN>": "us-west-2"}: the ARN lands where the region
    // belongs, and "us-west-2" where the key id belongs.
    let swapped = || {
        Envelope::new_multi(
            Arc::new(AES256GCM::new()),
            0,
            vec![(SWAPPED_REGION.to_string(), "us-west-2".to_string())],
            None,
        )
        .unwrap()
    };
    let blob = written_envelope(tag);
    drop(take_thread_records());

    // Decrypt of an ordinary envelope: no region matches.
    let err = swapped().decrypt_key(&(), &blob).unwrap_err();
    let msg = format!("{err:#}");
    let recs = take_thread_records();
    let line = envelope_error_line(&recs);
    println!("swapped map, decrypt\n  error: {msg}\n  error log: {line}");
    let detail = "no matching regions found; configured regions: <unrecognized region>; \
                  envelope regions: us-west-2";
    assert_eq!(
        msg,
        format!("all KMS backends failed to decrypt ({detail})")
    );
    assert_eq!(
        line,
        format!("AwsKmsEnvelope decrypt_key: all backends failed: {detail}")
    );
    assert!(
        recs.iter().any(|r| r.level == log::Level::Debug
            && r.message
                == "AwsKmsEnvelope decrypt_key: no KEK for region=<unrecognized region>, skipping"),
        "debug line"
    );
    assert_all_sinks_clean("swapped map decrypt", &msg, &recs);

    // Decrypt of an envelope whose KEK region is the same ARN: the region
    // matches, and the SDK rejects it before dispatch.
    let err = swapped()
        .decrypt_key(&(), &envelope_json(SWAPPED_REGION))
        .unwrap_err();
    let msg = format!("{err:#}");
    let recs = take_thread_records();
    let line = envelope_error_line(&recs);
    println!("swapped map, decrypt, matching envelope\n  error: {msg}\n  error log: {line}");
    let detail = "tried regions: <unrecognized region> \
                  [Decrypt request construction failure (invalid endpoint parameters)]";
    assert_eq!(
        msg,
        format!("all KMS backends failed to decrypt ({detail})")
    );
    assert_eq!(
        line,
        format!("AwsKmsEnvelope decrypt_key: all backends failed: {detail}")
    );
    assert_all_sinks_clean("swapped map decrypt (matching)", &msg, &recs);

    // Encrypt.
    let err = swapped().encrypt_key(&(), &[1_u8; 32]).unwrap_err();
    let msg = format!("{err:#}");
    let recs = take_thread_records();
    println!("swapped map, encrypt\n  error: {msg}");
    assert_eq!(
        msg,
        "KMS GenerateDataKey failed in region <unrecognized region>: \
         request construction failure (invalid endpoint parameters)"
    );
    assert_all_sinks_clean("swapped map encrypt", &msg, &recs);
    assert_eq!(fake.hits("GenerateDataKey", "us-west-2"), 0);
    assert_eq!(fake.hits("Decrypt", "us-west-2"), 0);
}

#[test]
fn truncated_response_is_a_response_error_with_io_kind() {
    let _ = fake();
    let tag = "truncated";
    let blob = written_envelope(tag);
    drop(take_thread_records());

    let err = single("us-west-2", tag, "truncated")
        .decrypt_key(&(), &blob)
        .unwrap_err();
    let msg = format!("{err:#}");
    let recs = take_thread_records();
    let line = envelope_error_line(&recs);
    println!("truncated, decrypt\n  error: {msg}\n  error log: {line}");
    let detail = format!(
        "tried regions: us-west-2 [Decrypt response error (HTTP 400, unexpected end of file), \
         request id {REQUEST_ID}]"
    );
    assert_eq!(
        msg,
        format!("all KMS backends failed to decrypt ({detail})")
    );
    assert_eq!(
        line,
        format!("AwsKmsEnvelope decrypt_key: all backends failed: {detail}")
    );
    assert_all_sinks_clean("truncated decrypt", &msg, &recs);

    let err = single("us-west-2", tag, "truncated")
        .encrypt_key(&(), &[1_u8; 32])
        .unwrap_err();
    let msg = format!("{err:#}");
    println!("truncated, encrypt\n  error: {msg}");
    assert_eq!(
        msg,
        format!(
            "KMS GenerateDataKey failed in region us-west-2: \
             response error (HTTP 400, unexpected end of file), request id {REQUEST_ID}"
        )
    );
    assert_all_sinks_clean("truncated encrypt", &msg, &take_thread_records());
}

/// `MultiKms::is_terminal_kms_error` substring-matches the error text, and
/// the envelope's error now carries the KMS error code, so a MultiKms
/// composed over AwsKmsEnvelope backends stops at the preferred backend
/// for AccessDenied, Disabled and InvalidKeyUsage, and still falls back
/// for other failures.
#[test]
fn multikms_over_envelope_stops_on_terminal_codes() {
    let fake = fake();
    let blob = written_envelope("multikms");
    let cases = [
        ("AccessDeniedException", true),
        ("DisabledException", true),
        ("InvalidKeyUsageException", true),
        ("ThrottlingException", false),
        ("IncorrectKeyException", false),
        ("KMSInvalidStateException", false),
    ];
    for (mode, terminal) in cases {
        let tag = format!("multikms-{mode}");
        let fallback_key = key_arn("us-west-2", &tag, "ok");
        let backends: Vec<Arc<dyn KeyManagementService>> = vec![
            Arc::new(single("us-west-2", &tag, mode)),
            Arc::new(single("us-west-2", &tag, "ok")),
        ];
        let m = MultiKms::new(0, backends).unwrap();
        let res = m.decrypt_key(&(), &blob);
        println!(
            "MultiKms preferred={mode}: {:?}, fallback Decrypt hits={}",
            res.as_ref().map(Vec::len).map_err(|e| format!("{e:#}")),
            fake.hits("Decrypt", &fallback_key)
        );
        if terminal {
            let msg = format!("{:#}", res.unwrap_err());
            assert_eq!(
                msg,
                format!(
                    "preferred KMS backend failed terminally: all KMS backends failed to \
                     decrypt (tried regions: us-west-2 [Decrypt service error {mode}, \
                     request id {REQUEST_ID}])"
                )
            );
            assert_eq!(fake.hits("Decrypt", &fallback_key), 0, "{mode}");
        } else {
            assert_eq!(res.unwrap(), vec![7_u8; 32], "{mode}");
            assert_eq!(fake.hits("Decrypt", &fallback_key), 1, "{mode}");
        }
    }

    // The async path applies the same policy.
    let tag = "multikms-async";
    let fallback_key = key_arn("us-west-2", tag, "ok");
    let backends: Vec<Arc<dyn KeyManagementService>> = vec![
        Arc::new(single("us-west-2", tag, "AccessDeniedException")),
        Arc::new(single("us-west-2", tag, "ok")),
    ];
    let m = MultiKms::new(0, backends).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt.block_on(m.decrypt_key_async(&(), &blob)).unwrap_err();
    assert!(
        format!("{err:#}").starts_with("preferred KMS backend failed terminally: "),
        "{err:#}"
    );
    assert_eq!(fake.hits("Decrypt", &fallback_key), 0);
    drop(take_thread_records());
}
