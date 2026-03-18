use asherah::builders;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::sync::atomic::{AtomicUsize, Ordering};

fn is_cold() -> bool {
    std::env::var("BENCH_COLD").ok().as_deref() == Some("1")
}

fn bench_encrypt(c: &mut Criterion) {
    let factory = builders::factory_from_env().expect("factory setup");
    let cold = is_cold();

    let mut rng = StdRng::seed_from_u64(12345);
    let sizes = [64, 1024, 8192];

    if !cold {
        let session = factory.get_session("bench-partition");
        // Warmup
        let warmup = vec![0u8; 64];
        let drr = session.encrypt(&warmup).expect("warmup encrypt");
        let _ = session.decrypt(drr).expect("warmup decrypt");

        let mut group = c.benchmark_group("native_encrypt");
        for size in sizes {
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);
            let drr = session.encrypt(&data).expect("verify encrypt");
            let decrypted = session.decrypt(drr).expect("verify decrypt");
            assert_eq!(decrypted, data, "round-trip verification failed for {size}B");

            group.bench_function(BenchmarkId::new("rust_native", size), |b| {
                b.iter(|| black_box(session.encrypt(black_box(&data)).expect("encrypt")))
            });
        }
        group.finish();
        session.close().ok();
    } else {
        // Cold: unique partition per iteration → IK cache miss every time
        let session = factory.get_session("cold-warmup");
        let warmup = vec![0u8; 64];
        let _ = session.encrypt(&warmup).expect("warmup"); // warm SK cache
        session.close().ok();

        let mut group = c.benchmark_group("native_encrypt");
        for size in sizes {
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);
            let ctr = AtomicUsize::new(0);
            group.bench_function(BenchmarkId::new("rust_native", size), |b| {
                b.iter(|| {
                    let i = ctr.fetch_add(1, Ordering::Relaxed);
                    let partition = format!("cold-enc-{size}-{i}");
                    let session = factory.get_session(&partition);
                    let result = black_box(session.encrypt(black_box(&data)).expect("encrypt"));
                    session.close().ok();
                    result
                })
            });
        }
        group.finish();
    }

    factory.close().ok();
}

fn bench_decrypt(c: &mut Criterion) {
    let factory = builders::factory_from_env().expect("factory setup");
    let cold = is_cold();

    let mut rng = StdRng::seed_from_u64(67890);
    let sizes = [64, 1024, 8192];

    if !cold {
        let session = factory.get_session("bench-partition");
        let mut group = c.benchmark_group("native_decrypt");
        for size in sizes {
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);
            let drr = session.encrypt(&data).expect("encrypt for decrypt setup");
            let decrypted = session.decrypt(drr.clone()).expect("verify decrypt");
            assert_eq!(decrypted, data, "decrypt verification failed for {size}B");

            group.bench_function(BenchmarkId::new("rust_native", size), |b| {
                b.iter(|| black_box(session.decrypt(black_box(drr.clone())).expect("decrypt")))
            });
        }
        group.finish();
        session.close().ok();
    } else {
        // Cold: alternate 2 partitions with IK cache size 1 → cache miss every iteration
        let session0 = factory.get_session("cold-0");
        let session1 = factory.get_session("cold-1");

        let mut group = c.benchmark_group("native_decrypt");
        for size in sizes {
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);
            let drr0 = session0.encrypt(&data).expect("encrypt cold-0");
            let drr1 = session1.encrypt(&data).expect("encrypt cold-1");
            // Warm SK cache
            let _ = session0.decrypt(drr0.clone()).expect("warm SK");

            let ctr = AtomicUsize::new(0);
            group.bench_function(BenchmarkId::new("rust_native", size), |b| {
                b.iter(|| {
                    let i = ctr.fetch_add(1, Ordering::Relaxed) % 2;
                    let drr = if i == 0 { drr0.clone() } else { drr1.clone() };
                    let session = if i == 0 { &session0 } else { &session1 };
                    black_box(session.decrypt(black_box(drr)).expect("cold decrypt"))
                })
            });
        }
        group.finish();
        session0.close().ok();
        session1.close().ok();
    }

    factory.close().ok();
}

fn bench_decrypt_from_json(c: &mut Criterion) {
    // Only run in hot mode — cold JSON decrypt is same cost as cold decrypt
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
