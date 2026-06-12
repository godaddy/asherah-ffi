use asherah::aead;
use asherah::traits::AEAD as _;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, RngCore, SeedableRng};

/// On Apple Silicon, request P-core scheduling via QoS class.
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

fn bench_prepare_key(c: &mut Criterion) {
    pin_to_performance_cores();
    let backend = aead::backend_name();
    let key = [0x42_u8; 32];

    let mut group = c.benchmark_group("crypto_prepare_key");
    group.bench_function(BenchmarkId::new(backend, 32), |b| {
        b.iter(|| black_box(aead::prepare_key(black_box(&key)).expect("prepare key")))
    });
    group.finish();
}

fn bench_prepared_key_encrypt(c: &mut Criterion) {
    pin_to_performance_cores();
    let backend = aead::backend_name();
    let key = [0x42_u8; 32];
    let prepared = aead::prepare_key(&key).expect("prepare key");
    let mut rng = StdRng::seed_from_u64(0xA5A5);
    let sizes = [32_usize, 64, 1024, 8192];

    let mut group = c.benchmark_group("crypto_prepared_encrypt");
    for size in sizes {
        let mut data = vec![0_u8; size];
        rng.fill_bytes(&mut data);
        group.bench_function(BenchmarkId::new(backend, size), |b| {
            b.iter(|| {
                black_box(
                    aead::encrypt_with_prepared_key(black_box(&data), black_box(&prepared))
                        .expect("encrypt"),
                )
            })
        });
    }
    group.finish();
}

fn bench_prepared_key_decrypt(c: &mut Criterion) {
    pin_to_performance_cores();
    let backend = aead::backend_name();
    let key = [0x42_u8; 32];
    let prepared = aead::prepare_key(&key).expect("prepare key");
    let mut rng = StdRng::seed_from_u64(0x5A5A);
    let sizes = [32_usize, 64, 1024, 8192];

    let mut group = c.benchmark_group("crypto_prepared_decrypt");
    for size in sizes {
        let mut data = vec![0_u8; size];
        rng.fill_bytes(&mut data);
        let ciphertext = aead::encrypt_with_prepared_key(&data, &prepared).expect("encrypt setup");
        group.bench_function(BenchmarkId::new(backend, size), |b| {
            b.iter(|| {
                black_box(
                    aead::decrypt_with_prepared_key(black_box(&ciphertext), black_box(&prepared))
                        .expect("decrypt"),
                )
            })
        });
    }
    group.finish();
}

fn bench_aead_trait_encrypt(c: &mut Criterion) {
    pin_to_performance_cores();
    let backend = aead::backend_name();
    let aead = aead::AES256GCM::new();
    let key = [0x42_u8; 32];
    let mut rng = StdRng::seed_from_u64(0x0BAD_5EED);
    let sizes = [32_usize, 64, 1024, 8192];

    let mut group = c.benchmark_group("crypto_trait_encrypt");
    for size in sizes {
        let mut data = vec![0_u8; size];
        rng.fill_bytes(&mut data);
        group.bench_function(BenchmarkId::new(backend, size), |b| {
            b.iter(|| {
                black_box(
                    aead.encrypt(black_box(&data), black_box(&key))
                        .expect("encrypt"),
                )
            })
        });
    }
    group.finish();
}

fn bench_fast_random(c: &mut Criterion) {
    pin_to_performance_cores();
    let backend = aead::backend_name();
    let sizes = [12_usize, 32, 64];

    let mut group = c.benchmark_group("crypto_fast_random");
    for size in sizes {
        group.bench_function(BenchmarkId::new(backend, size), |b| {
            b.iter(|| {
                let mut out = vec![0_u8; size];
                aead::fast_random_bytes(black_box(&mut out)).expect("fast random");
                black_box(out)
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_prepare_key,
    bench_prepared_key_encrypt,
    bench_prepared_key_decrypt,
    bench_aead_trait_encrypt,
    bench_fast_random
);
criterion_main!(benches);
