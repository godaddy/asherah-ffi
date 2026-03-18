//! Benchmarks against a real MySQL metastore via testcontainers.
//!
//! Run with:
//!   cargo bench --manifest-path benchmarks/asherah-bench/Cargo.toml \
//!     --features mysql --bench mysql_metastore
//!
//! Requires Docker.

use std::sync::Arc;

use asherah::aead::AES256GCM;
use asherah::api::{new_session_factory_with_options, FactoryOption};
use asherah::config::Config;
use asherah::kms::StaticKMS;
use asherah::metastore_mysql::MySqlMetastore;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mysql::prelude::Queryable;
use once_cell::sync::Lazy;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

type Factory = asherah::session::PublicFactory<AES256GCM, StaticKMS<AES256GCM>, MySqlMetastore>;

struct MysqlEnv {
    _container: ContainerAsync<GenericImage>,
    url: String,
}

static MYSQL: Lazy<MysqlEnv> = Lazy::new(|| {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let container = GenericImage::new("mysql", "8.1")
            .with_exposed_port(testcontainers::core::IntoContainerPort::tcp(3306))
            .with_wait_for(testcontainers::core::WaitFor::message_on_stderr("port: 3306"))
            .with_env_var("MYSQL_DATABASE", "test")
            .with_env_var("MYSQL_ALLOW_EMPTY_PASSWORD", "yes")
            .with_startup_timeout(std::time::Duration::from_secs(120))
            .start()
            .await
            .expect("start MySQL container");

        let port = container
            .get_host_port_ipv4(3306)
            .await
            .expect("get MySQL port");
        let url = format!("mysql://root@127.0.0.1:{port}/test");

        // Wait for MySQL to be ready and create table
        for attempt in 0..30 {
            match mysql::Pool::new(mysql::Opts::try_from(url.as_str()).unwrap()) {
                Ok(pool) => match pool.get_conn() {
                    Ok(mut conn) => {
                        conn.query_drop(
                            r#"CREATE TABLE IF NOT EXISTS encryption_key (
                                id VARCHAR(255) NOT NULL,
                                created TIMESTAMP NOT NULL,
                                key_record JSON NOT NULL,
                                PRIMARY KEY(id, created)
                            ) ENGINE=InnoDB"#,
                        )
                        .expect("create table");
                        eprintln!("MySQL ready on port {port} (attempt {attempt})");
                        return MysqlEnv {
                            _container: container,
                            url,
                        };
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_secs(1)),
                },
                Err(_) => std::thread::sleep(std::time::Duration::from_secs(1)),
            }
        }
        panic!("MySQL not ready after 30 retries");
    })
});

fn make_factory(url: &str) -> Factory {
    let master_key = vec![0x22u8; 32];
    let crypto = Arc::new(AES256GCM::new());
    let metastore = Arc::new(MySqlMetastore::connect(url).expect("mysql connect"));
    let kms = Arc::new(StaticKMS::new(crypto.clone(), master_key).expect("kms"));
    let cfg = Config::new("bench-svc", "bench-prod");
    new_session_factory_with_options(cfg, metastore, kms, crypto, &[FactoryOption::Metrics(false)])
}

/// Hot cache: same factory, same session — measures steady-state with MySQL.
fn bench_mysql_hot(c: &mut Criterion) {
    let env = &*MYSQL;
    let factory = make_factory(&env.url);
    let session = factory.get_session("mysql-bench");

    let mut rng = StdRng::seed_from_u64(12345);
    let sizes = [64, 1024, 8192];

    // Warm up: first encrypt/decrypt populates cache + creates keys in MySQL
    let warmup_data = vec![0u8; 64];
    let warmup_drr = session.encrypt(&warmup_data).expect("warmup encrypt");
    let _ = session.decrypt(warmup_drr).expect("warmup decrypt");

    let mut group = c.benchmark_group("mysql_hot_encrypt");
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        group.bench_function(BenchmarkId::new("mysql", size), |b| {
            b.iter(|| black_box(session.encrypt(black_box(&data)).expect("encrypt")))
        });
    }
    group.finish();

    let mut group = c.benchmark_group("mysql_hot_decrypt");
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        let drr = session.encrypt(&data).expect("encrypt for decrypt");
        // Warm decrypt cache
        let _ = session.decrypt(drr.clone()).expect("warm");
        group.bench_function(BenchmarkId::new("mysql", size), |b| {
            b.iter(|| black_box(session.decrypt(black_box(drr.clone())).expect("decrypt")))
        });
    }
    group.finish();

    session.close().ok();
    factory.close().ok();
}

/// Cold cache: factory A encrypts, factory B decrypts with empty cache.
/// Each iteration creates a fresh factory B → guaranteed MySQL round-trips.
fn bench_mysql_cold(c: &mut Criterion) {
    let env = &*MYSQL;

    // Factory A: encryptor
    let factory_a = make_factory(&env.url);
    let session_a = factory_a.get_session("mysql-bench");

    let mut rng = StdRng::seed_from_u64(67890);
    let sizes = [64, 1024, 8192];

    // Pre-encrypt
    let mut test_data = Vec::new();
    for size in sizes {
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        let drr = session_a.encrypt(&data).expect("encrypt");

        // Verify cross-factory works
        let fb = make_factory(&env.url);
        let sb = fb.get_session("mysql-bench");
        let pt = sb.decrypt(drr.clone()).expect("cross-factory decrypt");
        assert_eq!(pt, data, "verification failed for {size}B");
        sb.close().ok();
        fb.close().ok();

        test_data.push((size, data, drr));
    }

    let mut group = c.benchmark_group("mysql_cold_decrypt");
    for (size, _data, drr) in &test_data {
        group.bench_function(BenchmarkId::new("mysql", *size), |b| {
            b.iter(|| {
                let fb = make_factory(&env.url);
                let sb = fb.get_session("mysql-bench");
                let result = black_box(sb.decrypt(black_box(drr.clone())).expect("cold decrypt"));
                sb.close().ok();
                fb.close().ok();
                result
            })
        });
    }
    group.finish();

    session_a.close().ok();
    factory_a.close().ok();
}

/// Warm SK, cold IK: same long-lived factory (SK cached), but each iteration
/// decrypts data from a partition it hasn't seen → 1 MySQL round-trip for IK.
/// This is the realistic production case: factory lives for the process lifetime,
/// SK is loaded once, but new partitions arrive continuously.
fn bench_mysql_warm_sk(c: &mut Criterion) {
    let env = &*MYSQL;

    // Long-lived factory with tiny IK cache (1 entry) so every new partition
    // is a guaranteed IK miss, but the SK stays cached at factory level.
    let master_key = vec![0x22u8; 32];
    let crypto = Arc::new(AES256GCM::new());
    let metastore = Arc::new(MySqlMetastore::connect(&env.url).expect("mysql connect"));
    let kms = Arc::new(StaticKMS::new(crypto.clone(), master_key).expect("kms"));
    let mut cfg = Config::new("bench-svc", "bench-prod");
    cfg.policy.intermediate_key_cache_max_size = 1;
    let factory = new_session_factory_with_options(cfg, metastore, kms, crypto, &[FactoryOption::Metrics(false)]);

    // Pre-encrypt data on many distinct partitions so each decrypt is a new IK
    let mut rng = StdRng::seed_from_u64(99999);
    let sizes = [64, 1024, 8192];

    let mut test_data: Vec<(usize, Vec<(String, asherah::types::DataRowRecord)>)> = Vec::new();
    for size in sizes {
        let mut entries = Vec::new();
        // Create enough distinct partitions to exceed any iteration count
        for i in 0..10000 {
            let partition = format!("warm-sk-{size}-{i}");
            let session = factory.get_session(&partition);
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);
            let drr = session.encrypt(&data).expect("encrypt");
            entries.push((partition, drr));
            session.close().ok();
        }
        test_data.push((size, entries));
    }

    // Warm the SK cache with one decrypt (so only IK misses remain)
    {
        let (_, ref entries) = test_data[0];
        let session = factory.get_session(&entries[0].0);
        let _ = session.decrypt(entries[0].1.clone()).expect("warm SK");
        session.close().ok();
    }

    let mut group = c.benchmark_group("mysql_warm_sk_decrypt");
    for (size, entries) in &test_data {
        let counter = std::sync::atomic::AtomicUsize::new(1); // start at 1, 0 used for warmup
        group.bench_function(BenchmarkId::new("mysql", *size), |b| {
            b.iter_custom(|iters| {
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    // Each iteration uses a different partition, guaranteeing
                    // an IK cache miss (cache max=1, always evicted by prior).
                    let idx = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % entries.len();
                    let (ref partition, ref drr) = entries[idx];
                    let session = factory.get_session(partition);
                    black_box(session.decrypt(black_box(drr.clone())).expect("warm-sk decrypt"));
                    session.close().ok();
                }
                start.elapsed()
            })
        });
    }
    group.finish();

    factory.close().ok();
}

/// Simulates pre-fix behavior: SK cache disabled (NeverCache), so every decrypt
/// loads BOTH IK and SK from MySQL. This is what every request looked like before
/// the shared SK cache fix.
fn bench_mysql_no_sk_cache(c: &mut Criterion) {
    let env = &*MYSQL;

    let master_key = vec![0x22u8; 32];
    let crypto = Arc::new(AES256GCM::new());
    let metastore = Arc::new(MySqlMetastore::connect(&env.url).expect("mysql connect"));
    let kms = Arc::new(StaticKMS::new(crypto.clone(), master_key).expect("kms"));
    let mut cfg = Config::new("bench-svc", "bench-prod");
    // Simulate old behavior: per-session SK cache = NeverCache
    cfg.policy.cache_system_keys = false;
    cfg.policy.intermediate_key_cache_max_size = 1;
    let factory = new_session_factory_with_options(
        cfg,
        metastore,
        kms,
        crypto,
        &[FactoryOption::Metrics(false)],
    );

    let mut rng = StdRng::seed_from_u64(77777);
    let sizes = [64, 1024, 8192];

    let mut test_data: Vec<(usize, Vec<(String, asherah::types::DataRowRecord)>)> = Vec::new();
    for size in sizes {
        let mut entries = Vec::new();
        for i in 0..10000 {
            let partition = format!("no-sk-{size}-{i}");
            let session = factory.get_session(&partition);
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);
            let drr = session.encrypt(&data).expect("encrypt");
            entries.push((partition, drr));
            session.close().ok();
        }
        test_data.push((size, entries));
    }

    let mut group = c.benchmark_group("mysql_no_sk_cache_decrypt");
    for (size, entries) in &test_data {
        let counter = std::sync::atomic::AtomicUsize::new(0);
        group.bench_function(BenchmarkId::new("mysql", *size), |b| {
            b.iter_custom(|iters| {
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let idx =
                        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % entries.len();
                    let (ref partition, ref drr) = entries[idx];
                    let session = factory.get_session(partition);
                    black_box(
                        session
                            .decrypt(black_box(drr.clone()))
                            .expect("no-sk decrypt"),
                    );
                    session.close().ok();
                }
                start.elapsed()
            })
        });
    }
    group.finish();

    factory.close().ok();
}

criterion_group!(
    benches,
    bench_mysql_hot,
    bench_mysql_cold,
    bench_mysql_warm_sk,
    bench_mysql_no_sk_cache
);
criterion_main!(benches);
