use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use asherah::aead::AES256GCM;
use asherah::api::{new_session_factory_with_options, FactoryOption};
use asherah::config::Config;
use asherah::kms::StaticKMS;
use asherah::metastore::InMemoryMetastore;

fn main() -> anyhow::Result<()> {
    let master_key = vec![0x22u8; 32];
    let crypto = Arc::new(AES256GCM::new());
    let metastore = Arc::new(InMemoryMetastore::new());
    let kms = Arc::new(StaticKMS::new(crypto.clone(), master_key)?);

    let cfg = Config::new("bench-svc", "bench-prod");

    let factory = new_session_factory_with_options(
        cfg,
        metastore,
        kms,
        crypto,
        &[FactoryOption::Metrics(false)],
    );
    let session = factory.get_session("bench-partition");

    let sizes = [64, 1024, 8192];
    let warmup = 500;
    let iterations = 5000;

    println!("=== Rust Asherah (native, no FFI) ===\n");

    for &size in &sizes {
        let mut payload = vec![0u8; size];
        rand::fill(&mut payload[..]);

        // Warmup
        for _ in 0..warmup {
            let drr = session.encrypt(black_box(&payload))?;
            black_box(session.decrypt(drr)?);
        }

        // Benchmark encrypt
        let start = Instant::now();
        let mut last_drr = None;
        for _ in 0..iterations {
            last_drr = Some(black_box(session.encrypt(black_box(&payload))?));
        }
        let enc_dur = start.elapsed();
        let enc_us = enc_dur.as_micros() as f64 / iterations as f64;

        // Serialize to JSON (like Go does with json.Marshal)
        let json_bytes = serde_json::to_string(&last_drr.unwrap()).expect("serialization");

        // Benchmark decrypt with JSON parse (apples-to-apples with Go)
        let start = Instant::now();
        for _ in 0..iterations {
            let drr: asherah::types::DataRowRecord =
                serde_json::from_str(black_box(&json_bytes)).expect("json parse");
            black_box(session.decrypt(drr)?);
        }
        let dec_dur = start.elapsed();
        let dec_us = dec_dur.as_micros() as f64 / iterations as f64;

        // Benchmark decrypt without JSON parse (pure crypto)
        let drr_template: asherah::types::DataRowRecord =
            serde_json::from_str(&json_bytes).expect("json parse");
        let start_pure = Instant::now();
        for _ in 0..iterations {
            black_box(session.decrypt(black_box(drr_template.clone()))?);
        }
        let dec_pure_dur = start_pure.elapsed();
        let dec_pure_us = dec_pure_dur.as_micros() as f64 / iterations as f64;

        println!(
            "  {:5}B  encrypt: {:10.2} µs  decrypt(+json): {:10.2} µs  decrypt(pure): {:10.2} µs",
            size, enc_us, dec_us, dec_pure_us
        );
    }

    session.close()?;
    factory.close()?;

    Ok(())
}
