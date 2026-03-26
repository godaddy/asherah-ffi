//! Cold-cache benchmarks: simulate cross-instance decrypt where the decrypting
//! node has never seen the intermediate key before. This measures the full cost
//! of a cache miss: metastore load + system key decrypt + intermediate key decrypt.
//!
//! Uses a shared InMemoryMetastore so factory B can find factory A's keys,
//! but factory B has its own empty key cache — just like a different production
//! instance would.

use std::sync::Arc;

use asherah::aead::AES256GCM;
use asherah::api::{new_session_factory_with_options, FactoryOption};
use asherah::config::Config;
use asherah::kms::StaticKMS;
use asherah::metastore::InMemoryMetastore;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};

type Factory = asherah::SessionFactory<AES256GCM, StaticKMS<AES256GCM>, InMemoryMetastore>;

struct SharedEnv {
    metastore: Arc<InMemoryMetastore>,
    crypto: Arc<AES256GCM>,
    kms: Arc<StaticKMS<AES256GCM>>,
}

impl SharedEnv {
    fn new() -> Self {
        let master_key = vec![0x22u8; 32];
        let crypto = Arc::new(AES256GCM::new());
        let kms = Arc::new(StaticKMS::new(crypto.clone(), master_key).expect("kms"));
        let metastore = Arc::new(InMemoryMetastore::new());
        Self {
            metastore,
            crypto,
            kms,
        }
    }

    fn make_factory(&self) -> Factory {
        let cfg = Config::new("bench-svc", "bench-prod");
        new_session_factory_with_options(
            cfg,
            self.metastore.clone(),
            self.kms.clone(),
            self.crypto.clone(),
            &[FactoryOption::Metrics(false)],
        )
    }
}

/// Benchmark: hot cache decrypt (same factory, cache warm) — baseline for comparison.
fn bench_hot_decrypt(c: &mut Criterion) {
    let env = SharedEnv::new();
    let factory = env.make_factory();
    let session = factory.get_session("bench-partition");

    let mut rng = StdRng::seed_from_u64(12345);
    let sizes = [64, 1024, 8192];

    let mut group = c.benchmark_group("hot_cache_decrypt");
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        let drr = session.encrypt(&data).expect("encrypt");

        // Warm the cache
        let _ = session.decrypt(drr.clone()).expect("warm decrypt");

        group.bench_function(BenchmarkId::new("same_instance", size), |b| {
            b.iter(|| black_box(session.decrypt(black_box(drr.clone())).expect("decrypt")))
        });
    }
    group.finish();

    session.close().ok();
    factory.close().ok();
}

/// Benchmark: cold cache decrypt — different factory, empty key cache.
/// Factory A encrypts, factory B decrypts. B must load IK + SK from the
/// shared metastore on every iteration (fresh session each time to ensure
/// the cache is cold).
fn bench_cold_decrypt(c: &mut Criterion) {
    let env = SharedEnv::new();

    // Factory A: encryptor
    let factory_a = env.make_factory();
    let session_a = factory_a.get_session("bench-partition");

    let mut rng = StdRng::seed_from_u64(67890);
    let sizes = [64, 1024, 8192];

    // Pre-encrypt test data with factory A
    let mut test_data: Vec<(usize, Vec<u8>, asherah::types::DataRowRecord)> = Vec::new();
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        let drr = session_a.encrypt(&data).expect("encrypt");

        // Verify correctness: factory B can decrypt factory A's data
        let factory_b_verify = env.make_factory();
        let session_b_verify = factory_b_verify.get_session("bench-partition");
        let decrypted = session_b_verify
            .decrypt(drr.clone())
            .expect("cross-factory decrypt");
        assert_eq!(decrypted, data, "cross-factory verification failed for {size}B");
        session_b_verify.close().ok();
        factory_b_verify.close().ok();

        test_data.push((size, data, drr));
    }

    let mut group = c.benchmark_group("cold_cache_decrypt");
    for (size, _data, drr) in &test_data {
        group.bench_function(BenchmarkId::new("cross_instance", *size), |b| {
            b.iter(|| {
                // Create a fresh factory + session each iteration = guaranteed cold cache
                let factory_b = env.make_factory();
                let session_b = factory_b.get_session("bench-partition");
                let result =
                    black_box(session_b.decrypt(black_box(drr.clone())).expect("cold decrypt"));
                session_b.close().ok();
                factory_b.close().ok();
                result
            })
        });
    }
    group.finish();

    session_a.close().ok();
    factory_a.close().ok();
}

/// Benchmark: cold cache decrypt from JSON — same as cold_cache_decrypt but
/// includes JSON deserialization (matches the FFI path where ciphertext
/// arrives as JSON over the wire).
fn bench_cold_decrypt_from_json(c: &mut Criterion) {
    let env = SharedEnv::new();

    let factory_a = env.make_factory();
    let session_a = factory_a.get_session("bench-partition");

    let mut rng = StdRng::seed_from_u64(11111);
    let sizes = [64, 1024, 8192];

    let mut test_data: Vec<(usize, String)> = Vec::new();
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        let drr = session_a.encrypt(&data).expect("encrypt");
        let json = drr.to_json_fast();
        test_data.push((size, json));
    }

    let mut group = c.benchmark_group("cold_cache_decrypt_json");
    for (size, json) in &test_data {
        group.bench_function(BenchmarkId::new("cross_instance", *size), |b| {
            b.iter(|| {
                let factory_b = env.make_factory();
                let session_b = factory_b.get_session("bench-partition");
                let drr: asherah::types::DataRowRecord =
                    serde_json::from_str(black_box(json)).expect("json parse");
                let result =
                    black_box(session_b.decrypt(drr).expect("cold decrypt"));
                session_b.close().ok();
                factory_b.close().ok();
                result
            })
        });
    }
    group.finish();

    session_a.close().ok();
    factory_a.close().ok();
}

criterion_group!(
    benches,
    bench_hot_decrypt,
    bench_cold_decrypt,
    bench_cold_decrypt_from_json
);
criterion_main!(benches);
