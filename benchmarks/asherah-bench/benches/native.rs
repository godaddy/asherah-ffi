use asherah::builders;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::sync::atomic::{AtomicUsize, Ordering};

fn is_cold() -> bool {
    std::env::var("BENCH_MODE").ok().as_deref() == Some("cold")
}

fn bench_encrypt(c: &mut Criterion) {
    let factory = builders::factory_from_env().expect("factory setup");
    let cold = is_cold();

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
            let pool_size = 2048_usize;
            let partitions: Vec<String> = (0..pool_size)
                .map(|i| format!("cold-enc-{size}-{i}"))
                .collect();
            for p in &partitions {
                let session = factory.get_session(p);
                let _ = session.encrypt(&data).expect("pre-encrypt");
                session.close().ok();
            }

            let ctr = AtomicUsize::new(0);
            group.bench_function(BenchmarkId::new("rust_native", size), |b| {
                b.iter(|| {
                    let i = ctr.fetch_add(1, Ordering::Relaxed) % pool_size;
                    let session = factory.get_session(&partitions[i]);
                    let result =
                        black_box(session.encrypt(black_box(&data)).expect("encrypt"));
                    session.close().ok();
                    result
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
    let cold = is_cold();

    let mut rng = StdRng::seed_from_u64(67890);
    let sizes = [64, 1024, 8192];

    let mut group = c.benchmark_group("native_decrypt");
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);

        if cold {
            // Cold: pre-encrypt on many partitions, rotate to force IK miss
            let pool_size = 2048_usize;
            let mut partitions = Vec::with_capacity(pool_size);
            let mut ciphertexts = Vec::with_capacity(pool_size);
            for i in 0..pool_size {
                let partition = format!("cold-dec-{size}-{i}");
                let session = factory.get_session(&partition);
                let drr = session.encrypt(&data).expect("pre-encrypt");
                ciphertexts.push(drr);
                partitions.push(partition);
                session.close().ok();
            }
            // Warm SK cache
            {
                let session = factory.get_session(&partitions[0]);
                let _ = session.decrypt(ciphertexts[0].clone()).expect("warm SK");
                session.close().ok();
            }

            let ctr = AtomicUsize::new(0);
            group.bench_function(BenchmarkId::new("rust_native", size), |b| {
                b.iter(|| {
                    let i = ctr.fetch_add(1, Ordering::Relaxed) % pool_size;
                    let session = factory.get_session(&partitions[i]);
                    let result = black_box(
                        session
                            .decrypt(black_box(ciphertexts[i].clone()))
                            .expect("cold decrypt"),
                    );
                    session.close().ok();
                    result
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
    if is_cold() {
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
