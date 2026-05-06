//! Regression for the Vault Transit HTTP-status check before JSON parse
//! (commit 32a86a0). When Vault (or a reverse proxy in front of it)
//! returns a non-2xx status — 5xx with HTML, 401/403 from a proxy, etc. —
//! the previous implementation called `.json()` directly and surfaced an
//! opaque "failed to parse response" error that masked the actual HTTP
//! failure. The fix inspects `resp.status()` first and bails with a
//! status-shaped error.
//!
//! These tests spin up a tiny single-shot TCP listener that replies with
//! the status line + body we want, then assert the resulting error
//! mentions the HTTP status, not a JSON-parse failure.
//!
//! Gated behind the `vault` feature because `kms_vault_transit` is an
//! optional module. Run with:
//!   cargo test -p asherah --features vault --test vault_transit_http_status

#![cfg(feature = "vault")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::thread;

use asherah::kms_vault_transit::VaultTransitKms;
use asherah::traits::KeyManagementService;

/// Serialize tests because they mutate the `VAULT_TOKEN` env var.
static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// Spawn a one-shot HTTP responder on a random localhost port.
/// Reads (and discards) one request, writes one response, exits.
fn spawn_one_shot_responder(
    status_line: &'static str,
    content_type: &'static str,
    body: &'static str,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("http://{addr}");
    let response = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    let h = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Drain the request — we don't care about its content.
            drop(stream.set_read_timeout(Some(std::time::Duration::from_secs(2))));
            let mut buf = [0_u8; 4096];
            drop(stream.read(&mut buf));
            drop(stream.write_all(response.as_bytes()));
            drop(stream.flush());
        }
    });
    (url, h)
}

#[test]
fn vault_transit_5xx_with_json_body_surfaces_http_status() {
    let _guard = ENV_MUTEX.lock().unwrap();
    std::env::set_var("VAULT_TOKEN", "fake-token-for-test");

    // Body looks JSON-ish — the previous code would have happily parsed
    // it and produced a misleading "missing field 'data'" error instead
    // of saying HTTP 503.
    let (url, _h) = spawn_one_shot_responder(
        "503 Service Unavailable",
        "application/json",
        r#"{"errors": ["upstream backend timed out"]}"#,
    );

    let kms = VaultTransitKms::new(&url, "test-key", None).expect("construction");
    let err = kms
        .encrypt_key(&(), &[0_u8; 32])
        .expect_err("must error on 5xx");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("HTTP 503"),
        "error must mention HTTP 503 status; got: {msg}"
    );
    assert!(
        !msg.contains("missing field"),
        "error must not be a JSON-parse error masking the real status; got: {msg}"
    );

    std::env::remove_var("VAULT_TOKEN");
}

#[test]
fn vault_transit_4xx_with_html_body_surfaces_http_status() {
    let _guard = ENV_MUTEX.lock().unwrap();
    std::env::set_var("VAULT_TOKEN", "fake-token-for-test");

    // 401 from a reverse proxy in front of Vault, body is HTML.
    let (url, _h) = spawn_one_shot_responder(
        "401 Unauthorized",
        "text/html; charset=utf-8",
        "<html><body>401 Unauthorized: token expired</body></html>",
    );

    let kms = VaultTransitKms::new(&url, "test-key", None).expect("construction");
    let err = kms
        .encrypt_key(&(), &[0_u8; 32])
        .expect_err("must error on 4xx");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("HTTP 401"),
        "error must mention HTTP 401 status; got: {msg}"
    );

    std::env::remove_var("VAULT_TOKEN");
}

#[test]
fn vault_transit_4xx_decrypt_path_surfaces_http_status() {
    let _guard = ENV_MUTEX.lock().unwrap();
    std::env::set_var("VAULT_TOKEN", "fake-token-for-test");

    let (url, _h) = spawn_one_shot_responder(
        "403 Forbidden",
        "application/json",
        r#"{"errors": ["permission denied"]}"#,
    );

    let kms = VaultTransitKms::new(&url, "test-key", None).expect("construction");
    let err = kms
        .decrypt_key(&(), b"vault:v1:fake-blob")
        .expect_err("must error on 4xx");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("HTTP 403"),
        "decrypt error must mention HTTP 403 status; got: {msg}"
    );

    std::env::remove_var("VAULT_TOKEN");
}
