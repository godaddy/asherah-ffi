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
        cfg, metastore, kms, crypto,
        &[FactoryOption::Metrics(false)],
    );
    let session = factory.get_session("bench-partition");

    let payload = b"Bo wants proof this isn't a no-op";
    let iterations = 5000;

    // Warmup
    for _ in 0..500 {
        let drr = session.encrypt(payload)?;
        session.decrypt(drr)?;
    }

    // 1. Verify every encrypt produces DIFFERENT ciphertext (nonce is random)
    let drr1 = session.encrypt(payload)?;
    let drr2 = session.encrypt(payload)?;
    let json1 = drr1.to_json_fast();
    let json2 = drr2.to_json_fast();
    assert_ne!(json1, json2, "Two encrypts should produce different ciphertext");
    println!("PASS: Each encrypt produces unique ciphertext");
    println!("  drr1: {}...  ({} bytes)", &json1[..80], json1.len());
    println!("  drr2: {}...  ({} bytes)", &json2[..80], json2.len());

    // 2. Verify decrypt recovers the original plaintext
    let drr = session.encrypt(payload)?;
    let recovered = session.decrypt(drr)?;
    assert_eq!(&recovered, payload, "Decrypt must recover original plaintext");
    println!("PASS: Decrypt recovers original plaintext: {:?}", std::str::from_utf8(&recovered).unwrap());

    // 3. Verify the DRR has real structure (Key + Data fields with base64)
    let drr = session.encrypt(payload)?;
    let json = drr.to_json_fast();
    assert!(json.contains("\"Key\":{"), "DRR must contain Key object");
    assert!(json.contains("\"Data\":\""), "DRR must contain Data field");
    println!("PASS: DRR JSON has real Key and Data fields");

    // 4. Timed run with round-trip verification on EVERY iteration
    let start = Instant::now();
    for _ in 0..iterations {
        let drr = session.encrypt(payload)?;
        let recovered = session.decrypt(drr)?;
        assert_eq!(recovered.len(), payload.len());
    }
    let dur = start.elapsed();
    let us_per = dur.as_micros() as f64 / iterations as f64;
    println!("\nVerified round-trip (encrypt+decrypt) x{}: {:.2} µs/iter", iterations, us_per);

    // 5. Timed encrypt-only (what the benchmark measures), with black_box to prevent elision
    let mut payload_64 = [0u8; 64];
    rand::fill(&mut payload_64[..]);
    let start = Instant::now();
    for _ in 0..iterations {
        let drr = session.encrypt(&payload_64)?;
        // Force the compiler to materialize the result
        std::hint::black_box(&drr);
    }
    let dur = start.elapsed();
    let enc_us = dur.as_micros() as f64 / iterations as f64;
    println!("Encrypt-only 64B with black_box: {:.2} µs/iter", enc_us);

    session.close()?;
    factory.close()?;
    Ok(())
}
