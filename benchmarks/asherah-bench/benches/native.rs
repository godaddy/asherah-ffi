use asherah::builders;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

/// On Apple Silicon, request P-core scheduling via QoS class.
/// This prevents benchmarks from running on efficiency cores when plugged in.
#[cfg(target_os = "macos")]
fn pin_to_performance_cores() {
    // QOS_CLASS_USER_INTERACTIVE = 0x21
    extern "C" {
        fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    }
    unsafe {
        pthread_set_qos_class_self_np(0x21, 0);
    }
}

#[cfg(not(target_os = "macos"))]
fn pin_to_performance_cores() {}

fn bench_mode() -> String {
    std::env::var("BENCH_MODE")
        .ok()
        .unwrap_or_else(|| "memory".to_string())
        .to_lowercase()
}

fn uses_partition_rotation() -> bool {
    matches!(bench_mode().as_str(), "warm" | "cold")
}

fn bench_encrypt(c: &mut Criterion) {
    pin_to_performance_cores();
    let factory = builders::factory_from_env().expect("factory setup");
    let cold = uses_partition_rotation();

    let mut rng = StdRng::seed_from_u64(12345);
    let sizes = [64, 1024, 8192];

    // Warmup: populate SK cache
    {
        let session = factory.get_session("bench-warmup");
        let _ = session.encrypt(&[0u8; 64]).expect("warmup encrypt");
        session.close().ok();
    }

    let mut group = c.benchmark_group("native_encrypt");
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        if cold {
            // Cold: pre-encrypt on pool of partitions so IKs exist in metastore,
            // then benchmark with IK cache=1 so every access is a cache miss
            // measuring load_latest cost, not IK creation cost.
            // Sessions are cached in a HashMap to match what FFI bindings do
            // (their stateless APIs keep sessions alive internally).
            let mode = bench_mode();
            let pool_size = 2048_usize;
            let partitions: Vec<String> = (0..pool_size)
                .map(|i| format!("bench-{mode}-{size}-{i}"))
                .collect();
            let mut sessions: HashMap<&str, _> = HashMap::new();
            for p in &partitions {
                let session = factory.get_session(p);
                let _ = session.encrypt(&data).expect("pre-encrypt");
                sessions.insert(p.as_str(), session);
            }

            // Warmup: 1000 iterations to stabilize MySQL connection pool,
            // branch predictor, etc. — matches FFI binding benchmarks.
            for w in 0..1000 {
                let session = &sessions[partitions[w % pool_size].as_str()];
                let _ = black_box(session.encrypt(&data).expect("warmup"));
            }

            let ctr = AtomicUsize::new(0);
            group.bench_function(BenchmarkId::new("rust_native", size), |b| {
                b.iter(|| {
                    let i = ctr.fetch_add(1, Ordering::Relaxed) % pool_size;
                    let session = &sessions[partitions[i].as_str()];
                    black_box(session.encrypt(black_box(&data)).expect("encrypt"))
                })
            });
        } else {
            let session = factory.get_session("bench-partition");
            // Verify round-trip
            let drr = session.encrypt(&data).expect("verify encrypt");
            let decrypted = session.decrypt(drr).expect("verify decrypt");
            assert_eq!(decrypted, data, "round-trip verification failed for {size}B");

            group.bench_function(BenchmarkId::new("rust_native", size), |b| {
                b.iter(|| black_box(session.encrypt(black_box(&data)).expect("encrypt")))
            });
            session.close().ok();
        }
    }
    group.finish();
    factory.close().ok();
}

fn bench_decrypt(c: &mut Criterion) {
    let factory = builders::factory_from_env().expect("factory setup");
    let cold = uses_partition_rotation();

    let mut rng = StdRng::seed_from_u64(67890);
    let sizes = [64, 1024, 8192];

    let mut group = c.benchmark_group("native_decrypt");
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        if cold {
            // Cold: pre-encrypt on many partitions, rotate to force IK miss.
            // Sessions cached in a HashMap to match FFI binding behavior.
            let mode = bench_mode();
            let pool_size = 2048_usize;
            let mut partitions = Vec::with_capacity(pool_size);
            let mut ciphertexts = Vec::with_capacity(pool_size);
            let mut sessions: HashMap<String, _> = HashMap::new();
            for i in 0..pool_size {
                let partition = format!("bench-{mode}-{size}-{i}");
                let session = factory.get_session(&partition);
                let drr = session.encrypt(&data).expect("pre-encrypt");
                ciphertexts.push(drr);
                sessions.insert(partition.clone(), session);
                partitions.push(partition);
            }
            // Warmup: 1000 iterations to stabilize MySQL connection pool,
            // branch predictor, and SK cache — matches FFI binding benchmarks.
            for w in 0..1000 {
                let i = w % pool_size;
                let session = &sessions[&partitions[i]];
                let _ = black_box(session.decrypt(ciphertexts[i].clone()).expect("warmup"));
            }

            let ctr = AtomicUsize::new(0);
            group.bench_function(BenchmarkId::new("rust_native", size), |b| {
                b.iter(|| {
                    let i = ctr.fetch_add(1, Ordering::Relaxed) % pool_size;
                    let session = &sessions[&partitions[i]];
                    black_box(
                        session
                            .decrypt(black_box(ciphertexts[i].clone()))
                            .expect("cold decrypt"),
                    )
                })
            });
        } else {
            let session = factory.get_session("bench-partition");
            let drr = session.encrypt(&data).expect("encrypt for decrypt setup");
            let decrypted = session.decrypt(drr.clone()).expect("verify decrypt");
            assert_eq!(decrypted, data, "decrypt verification failed for {size}B");

            group.bench_function(BenchmarkId::new("rust_native", size), |b| {
                b.iter(|| black_box(session.decrypt(black_box(drr.clone())).expect("decrypt")))
            });
            session.close().ok();
        }
    }
    group.finish();
    factory.close().ok();
}

fn bench_decrypt_from_json(c: &mut Criterion) {
    // Only run in non-cold mode
    if uses_partition_rotation() {
        return;
    }
    let factory = builders::factory_from_env().expect("factory setup");
    let session = factory.get_session("bench-partition");

    let mut rng = StdRng::seed_from_u64(11111);
    let sizes = [64, 1024, 8192];

    let mut group = c.benchmark_group("native_decrypt_from_json");
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        let drr = session.encrypt(&data).expect("encrypt for decrypt setup");
        let json = drr.to_json_fast();

        let drr_parsed: asherah::types::DataRowRecord =
            serde_json::from_str(&json).expect("verify json parse");
        let decrypted = session.decrypt(drr_parsed).expect("verify decrypt from json");
        assert_eq!(
            decrypted, data,
            "JSON decrypt verification failed for {size}B"
        );

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
