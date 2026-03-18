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

criterion_group!(benches, bench_mysql_hot, bench_mysql_cold);
criterion_main!(benches);
