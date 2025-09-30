#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::process::{Command, Stdio};
use std::sync::Arc;

use cucumber::{given, then, when, World as _};
use serde::{Deserialize, Serialize};

use asherah as ael;
use base64::{engine::general_purpose::STANDARD, Engine as _};

#[derive(Debug, Default, cucumber::World)]
struct World {
    master_hex: String,
    service: String,
    product: String,
    partition: String,
    node_blob: Option<String>,
    rust_blob: Option<String>,
}

#[given(regex = "a StaticKMS master key \"([0-9a-fA-F]{64})\"")]
fn master_key(w: &mut World, hex: String) {
    w.master_hex = hex;
}

#[given(regex = "service \"([^\"]+)\" and product \"([^\"]+)\" and partition \"([^\"]+)\"")]
fn cfg_parts(w: &mut World, service: String, product: String, partition: String) {
    w.service = service;
    w.product = product;
    w.partition = partition;
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let b = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i..i + 2]), 16).unwrap();
        out.push(b);
    }
    out
}

#[derive(Serialize, Deserialize)]
struct NodeBundle {
    metastore: Vec<ael::EnvelopeKeyRecord>,
    drr: ael::DataRowRecord,
}

fn have_node() -> bool {
    which::which("node").is_ok()
        && std::path::Path::new("cucumber/js/node_modules/asherah").exists()
}

#[when(regex = "Node encrypts payload \"([^\"]+)\" using the same config")]
fn node_encrypt(w: &mut World, payload: String) {
    assert!(
        have_node(),
        "Install Node deps: cd cucumber/js && npm install"
    );
    // Run node helper script to produce bundle JSON
    let script = "cucumber/js/gen.js";
    let master = &w.master_hex;
    let out = Command::new("node")
        .arg(script)
        .arg("encrypt")
        .arg(&w.service)
        .arg(&w.product)
        .arg(&w.partition)
        .arg(master)
        .arg(STANDARD.encode(payload.as_bytes()))
        .stdout(Stdio::piped())
        .output()
        .expect("node run");
    assert!(
        out.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    w.node_blob = Some(String::from_utf8(out.stdout).unwrap());
}

#[then(regex = "Rust decrypts it successfully and plaintext equals \"([^\"]+)\"")]
fn rust_decrypt(w: &mut World, expect: String) {
    let blob = w.node_blob.as_ref().expect("node blob");
    let bundle: NodeBundle = serde_json::from_str(blob).expect("bundle json");
    // Use shared metastore (RDBMS) so Rust can load IK/SK
    let store = create_store();
    // Build factory/session with StaticKMS master key
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    // Use StaticKMS with the provided master key (hex)
    let kms = Arc::new(ael::kms::StaticKMS::new(
        crypto.clone(),
        hex_to_bytes(&w.master_hex),
    ));
    let cfg = ael::Config::new(&w.service, &w.product);
    let f = ael::api::new_session_factory(cfg, store, kms, crypto);
    let s = f.get_session(&w.partition);
    let pt = s.decrypt(bundle.drr).expect("decrypt");
    assert_eq!(pt, expect.as_bytes());
}

#[when(regex = "Rust encrypts payload \"([^\"]+)\"")]
fn rust_encrypt(w: &mut World, payload: String) {
    let store = create_store();
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(
        crypto.clone(),
        hex_to_bytes(&w.master_hex),
    ));
    let cfg = ael::Config::new(&w.service, &w.product);
    let f = ael::api::new_session_factory(cfg, store.clone(), kms, crypto);
    let s = f.get_session(&w.partition);
    let drr = s.encrypt(payload.as_bytes()).expect("encrypt");
    // Node uses shared metastore; only pass DRR
    let bundle = NodeBundle {
        metastore: vec![],
        drr,
    };
    w.rust_blob = Some(serde_json::to_string(&bundle).unwrap());
}

#[then(regex = "Node decrypts it successfully and plaintext equals \"([^\"]+)\"")]
fn node_decrypt(w: &mut World, expect: String) {
    assert!(
        have_node(),
        "Install Node deps: cd cucumber/js && npm install"
    );
    let blob = w.rust_blob.as_ref().expect("rust bundle");
    let script = "cucumber/js/gen.js";
    let out = Command::new("node")
        .arg(script)
        .arg("decrypt")
        .arg(&w.service)
        .arg(&w.product)
        .arg(&w.partition)
        .arg(&w.master_hex)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn node");
    let mut child = out;
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("child stdin")
            .write_all(blob.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().expect("wait");
    assert!(
        output.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pt_b64 = String::from_utf8(output.stdout).unwrap();
    let pt = STANDARD.decode(pt_b64.trim()).unwrap();
    assert_eq!(pt, expect.as_bytes());
}

#[cfg(feature = "postgres")]
fn create_store() -> Arc<ael::metastore_postgres::PostgresMetastore> {
    let url = std::env::var("POSTGRES_URL").expect("Set POSTGRES_URL");
    Arc::new(ael::metastore_postgres::PostgresMetastore::connect(&url).expect("pg connect"))
}
#[cfg(all(not(feature = "postgres"), feature = "mysql"))]
fn create_store() -> Arc<ael::metastore_mysql::MySqlMetastore> {
    let url = std::env::var("MYSQL_URL").expect("Set MYSQL_URL");
    Arc::new(ael::metastore_mysql::MySqlMetastore::connect(&url).expect("mysql connect"))
}

#[cfg(all(
    not(feature = "postgres"),
    not(feature = "mysql"),
    feature = "dynamodb"
))]
fn create_store() -> Arc<ael::metastore_dynamodb::DynamoDbMetastore> {
    panic!("DynamoDB not supported in StaticKMS Cucumber profile; use Postgres or MySQL")
}

#[tokio::main(flavor = "multi_thread")] // cucumber needs an async runtime
async fn main() {
    World::cucumber().fail_on_skipped().run("features").await;
}
