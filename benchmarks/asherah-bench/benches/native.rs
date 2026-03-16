use std::sync::Arc;

use asherah::aead::AES256GCM;
use asherah::api::{new_session_factory_with_options, FactoryOption};
use asherah::config::Config;
use asherah::kms::StaticKMS;
use asherah::metastore::InMemoryMetastore;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};

fn setup_factory() -> asherah::SessionFactory<AES256GCM, StaticKMS<AES256GCM>, InMemoryMetastore> {
    let master_key = vec![0x22u8; 32];
    let crypto = Arc::new(AES256GCM::new());
    let metastore = Arc::new(InMemoryMetastore::new());
    let kms = Arc::new(StaticKMS::new(crypto.clone(), master_key).expect("kms"));

    let cfg = Config::new("bench-svc", "bench-prod");
    new_session_factory_with_options(cfg, metastore, kms, crypto, &[FactoryOption::Metrics(false)])
}

fn bench_encrypt(c: &mut Criterion) {
    let factory = setup_factory();
    let session = factory.get_session("bench-partition");

    let mut rng = StdRng::seed_from_u64(12345);
    let sizes = [64, 1024, 4096, 8192];

    let mut group = c.benchmark_group("native_encrypt");
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        // Verify round-trip correctness before benchmarking
        let drr = session.encrypt(&data).expect("verify encrypt");
        let decrypted = session.decrypt(drr).expect("verify decrypt");
        assert_eq!(decrypted, data, "round-trip verification failed for {size}B");

        group.bench_function(BenchmarkId::new("rust_native", size), |b| {
            b.iter(|| {
                black_box(session.encrypt(black_box(&data)).expect("encrypt"))
            })
        });
    }
    group.finish();

    session.close().ok();
    factory.close().ok();
}

fn bench_decrypt(c: &mut Criterion) {
    let factory = setup_factory();
    let session = factory.get_session("bench-partition");

    let mut rng = StdRng::seed_from_u64(67890);
    let sizes = [64, 1024, 4096, 8192];

    let mut group = c.benchmark_group("native_decrypt");
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        let drr = session.encrypt(&data).expect("encrypt for decrypt setup");

        // Verify decrypt correctness before benchmarking
        let decrypted = session.decrypt(drr.clone()).expect("verify decrypt");
        assert_eq!(decrypted, data, "decrypt verification failed for {size}B");

        group.bench_function(BenchmarkId::new("rust_native", size), |b| {
            b.iter(|| {
                black_box(session.decrypt(black_box(drr.clone())).expect("decrypt"))
            })
        });
    }
    group.finish();

    session.close().ok();
    factory.close().ok();
}

fn bench_decrypt_from_json(c: &mut Criterion) {
    let factory = setup_factory();
    let session = factory.get_session("bench-partition");

    let mut rng = StdRng::seed_from_u64(11111);
    let sizes = [64, 1024, 4096, 8192];

    let mut group = c.benchmark_group("native_decrypt_from_json");
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        let drr = session.encrypt(&data).expect("encrypt for decrypt setup");
        let json = drr.to_json_fast();

        // Verify JSON round-trip correctness before benchmarking
        let drr_parsed: asherah::types::DataRowRecord =
            serde_json::from_str(&json).expect("verify json parse");
        let decrypted = session.decrypt(drr_parsed).expect("verify decrypt from json");
        assert_eq!(decrypted, data, "JSON decrypt verification failed for {size}B");

        group.bench_function(BenchmarkId::new("rust_native", size), |b| {
            b.iter(|| {
                let drr: asherah::types::DataRowRecord =
                    serde_json::from_str(black_box(&json)).expect("json parse");
                black_box(session.decrypt(drr).expect("decrypt"))
            })
        });
    }
    group.finish();

    session.close().ok();
    factory.close().ok();
}

criterion_group!(benches, bench_encrypt, bench_decrypt, bench_decrypt_from_json);
criterion_main!(benches);
