#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic
)]
use std::process::{Command, Stdio};
use std::sync::Arc;

use cucumber::{given, then, when, World as _};
use serde::{Deserialize, Serialize};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

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
        .stderr(Stdio::piped())
        .output()
        .expect("node run");
    assert!(
        out.status.success(),
        "node encrypt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    w.node_blob = Some(String::from_utf8(out.stdout).unwrap());
}

#[then(regex = "Rust decrypts it successfully and plaintext equals \"([^\"]+)\"")]
fn rust_decrypt(w: &mut World, expect: String) {
    let blob = w.node_blob.as_ref().expect("node blob").clone();
    let master_hex = w.master_hex.clone();
    let service = w.service.clone();
    let product = w.product.clone();
    let partition = w.partition.clone();
    // Run on a separate thread to avoid tokio runtime conflict
    // (asherah internally creates its own tokio runtime)
    let result = std::thread::spawn(move || {
        let bundle: NodeBundle = serde_json::from_str(&blob).expect("bundle json");
        let store = create_store();
        let crypto = Arc::new(ael::aead::AES256GCM::new());
        let kms =
            Arc::new(ael::kms::StaticKMS::new(crypto.clone(), hex_to_bytes(&master_hex)).unwrap());
        let cfg = ael::Config::new(&service, &product);
        let f = ael::api::new_session_factory(cfg, store, kms, crypto);
        let s = f.get_session(&partition);
        s.decrypt(bundle.drr).expect("decrypt")
    })
    .join()
    .expect("thread panicked");
    assert_eq!(result, expect.as_bytes());
}

#[when(regex = "Rust encrypts payload \"([^\"]+)\"")]
fn rust_encrypt(w: &mut World, payload: String) {
    let master_hex = w.master_hex.clone();
    let service = w.service.clone();
    let product = w.product.clone();
    let partition = w.partition.clone();
    // Run on a separate thread to avoid tokio runtime conflict
    let blob = std::thread::spawn(move || {
        let store = create_store();
        let crypto = Arc::new(ael::aead::AES256GCM::new());
        let kms =
            Arc::new(ael::kms::StaticKMS::new(crypto.clone(), hex_to_bytes(&master_hex)).unwrap());
        let cfg = ael::Config::new(&service, &product);
        let f = ael::api::new_session_factory(cfg, store.clone(), kms, crypto);
        let s = f.get_session(&partition);
        let drr = s.encrypt(payload.as_bytes()).expect("encrypt");
        let bundle = NodeBundle {
            metastore: vec![],
            drr,
        };
        serde_json::to_string(&bundle).unwrap()
    })
    .join()
    .expect("thread panicked");
    w.rust_blob = Some(blob);
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
        .stderr(Stdio::piped())
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
        "node decrypt failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pt_b64 = String::from_utf8(output.stdout).unwrap();
    let pt = STANDARD.decode(pt_b64.trim()).unwrap();
    assert_eq!(pt, expect.as_bytes());
}

/// Create a MySQL-backed metastore from MYSQL_URL.
/// Go asherah-cobhan uses MySQL for the `rdbms` metastore type.
fn create_store() -> Arc<ael::metastore_mysql::MySqlMetastore> {
    let url = std::env::var("MYSQL_URL").expect("MYSQL_URL must be set");
    Arc::new(ael::metastore_mysql::MySqlMetastore::connect(&url).expect("mysql connect"))
}

/// Start a MySQL container and return (container, connection_url).
async fn start_mysql() -> (testcontainers::ContainerAsync<GenericImage>, String) {
    for attempt in 0..3 {
        let container = GenericImage::new("mysql", "8.1")
            .with_exposed_port(3306.tcp())
            .with_wait_for(WaitFor::message_on_stderr("port: 3306"))
            .with_env_var("MYSQL_DATABASE", "test")
            .with_env_var("MYSQL_ALLOW_EMPTY_PASSWORD", "yes")
            .with_startup_timeout(std::time::Duration::from_secs(120))
            .start()
            .await
            .unwrap_or_else(|e| panic!("Docker must be available for cross-language tests: {e}"));

        match container.get_host_port_ipv4(3306).await {
            Ok(port) => {
                let url = format!("mysql://root@127.0.0.1:{port}/test");
                let url_clone = url.clone();
                let table_ok = tokio::task::spawn_blocking(move || {
                    use mysql::prelude::Queryable;
                    for _ in 0..30 {
                        if let Ok(pool) =
                            mysql::Pool::new(mysql::Opts::try_from(url_clone.as_str()).unwrap())
                        {
                            if let Ok(mut conn) = pool.get_conn() {
                                if conn
                                    .query_drop(
                                        r#"CREATE TABLE IF NOT EXISTS encryption_key (
                                        id VARCHAR(255) NOT NULL,
                                        created TIMESTAMP NOT NULL,
                                        key_record JSON NOT NULL,
                                        PRIMARY KEY(id, created)
                                    ) ENGINE=InnoDB"#,
                                    )
                                    .is_ok()
                                {
                                    return true;
                                }
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                    false
                })
                .await
                .unwrap();
                if table_ok {
                    return (container, url);
                }
                eprintln!("MySQL table creation failed after retries (attempt {attempt})");
            }
            Err(e) => {
                eprintln!("MySQL get_host_port_ipv4 failed (attempt {attempt}): {e}");
            }
        }
    }
    panic!("Failed to start MySQL container after 3 attempts");
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    assert!(
        have_node(),
        "Cross-language tests require Node.js with asherah installed. Run: cd cucumber/js && npm install"
    );

    // Start MySQL container for shared metastore (Go asherah-cobhan uses MySQL for 'rdbms')
    let (_container, mysql_url) = start_mysql().await;

    // Set MYSQL_URL so both Rust create_store() and Node gen.js can use it
    std::env::set_var("MYSQL_URL", &mysql_url);

    World::cucumber().fail_on_skipped().run("features").await;
}
