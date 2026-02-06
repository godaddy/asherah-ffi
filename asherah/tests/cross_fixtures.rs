#![allow(clippy::unwrap_used, clippy::expect_used)]
use asherah as ael;
use asherah::Metastore;
use std::fs;
use std::path::Path;

// Optional cross-language fixture test: looks for JSON bundles in FIXTURES_DIR.
// Bundle format: { "metastore": [EnvelopeKeyRecord...], "drr": DataRowRecord, "kms": "static", "master_hex": "..." }

#[test]
fn cross_language_fixtures_if_present() {
    let dir = match std::env::var("FIXTURES_DIR") {
        Ok(v) => v,
        Err(_) => return,
    }; // skip if not provided
    let p = Path::new(&dir);
    if !p.exists() {
        return;
    }
    for entry in fs::read_dir(p).unwrap() {
        let ent = entry.unwrap();
        if ent.file_type().unwrap().is_file() {
            if ent.path().extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let txt = fs::read_to_string(ent.path()).unwrap();
            let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
            let kms = v.get("kms").and_then(|x| x.as_str()).unwrap_or("static");
            if kms != "static" {
                continue;
            }
            let master = v.get("master_hex").and_then(|x| x.as_str()).unwrap_or("00");
            // Build components
            let crypto = std::sync::Arc::new(ael::aead::AES256GCM::new());
            let kms = std::sync::Arc::new(ael::kms::StaticKMS::new(
                crypto.clone(),
                hex_to_bytes(master),
            ).unwrap());
            let store = std::sync::Arc::new(ael::metastore::InMemoryMetastore::new());
            // Load metastore records if provided
            if let Some(arr) = v.get("metastore").and_then(|x| x.as_array()) {
                for item in arr {
                    let mut ekr: ael::EnvelopeKeyRecord =
                        serde_json::from_value(item.clone()).unwrap();
                    // In-memory key under test expects an id; fill if omitted
                    if ekr.parent_key_meta.is_none() {
                        ekr.id = "_SK_fixture".into();
                    } else {
                        ekr.id = ekr.parent_key_meta.as_ref().unwrap().id.clone();
                    }
                    store.store(&ekr.id, ekr.created, &ekr).unwrap();
                }
            }
            let cfg = ael::Config::new("svc", "prod");
            let f = ael::api::new_session_factory(cfg, store, kms, crypto);
            let s = f.get_session("p1");
            let drr: ael::DataRowRecord =
                serde_json::from_value(v.get("drr").unwrap().clone()).unwrap();
            let pt = s.decrypt(drr).unwrap();
            // optional expected field
            if let Some(exp) = v.get("expected").and_then(|x| x.as_str()) {
                assert_eq!(pt, exp.as_bytes());
            }
        }
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let b = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i..i + 2]), 16).unwrap_or(0);
        out.push(b);
    }
    out
}
