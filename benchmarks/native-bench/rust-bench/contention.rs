use std::hint::black_box;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use asherah::aead::AES256GCM;
use asherah::api::{new_session_factory_with_options, FactoryOption};
use asherah::config::Config;
use asherah::kms::StaticKMS;
use asherah::metastore::InMemoryMetastore;

fn main() -> anyhow::Result<()> {
    let thread_counts = [1, 2, 4, 8];
    let iterations_per_thread = 5000;
    let payload_size = 64;

    println!("=== Cache Contention Benchmark ===\n");
    println!(
        "{:>8} {:>12} {:>14} {:>14} {:>14}",
        "threads", "total_ops", "wall_ms", "ops/sec", "µs/op"
    );
    println!("{}", "-".repeat(66));

    for &num_threads in &thread_counts {
        // Fresh factory per run to reset caches
        let master_key = vec![0x22u8; 32];
        let crypto = Arc::new(AES256GCM::new());
        let metastore = Arc::new(InMemoryMetastore::new());
        let kms = Arc::new(StaticKMS::new(crypto.clone(), master_key)?);

        let mut cfg = Config::new("bench-svc", "bench-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 100;
        cfg.policy.cache_system_keys = true;
        cfg.policy.system_key_cache_max_size = 100;
        cfg.policy.cache_sessions = true;
        cfg.policy.session_cache_max_size = 100;
        cfg.policy.session_cache_ttl_s = 3600;

        let factory = Arc::new(new_session_factory_with_options(
            cfg,
            metastore,
            kms,
            crypto,
            &[FactoryOption::Metrics(false)],
        ));

        // Warmup
        {
            let session = factory.get_session("warmup");
            let mut buf = vec![0u8; payload_size];
            rand::fill(&mut buf[..]);
            for _ in 0..200 {
                let drr = session.encrypt(black_box(&buf))?;
                black_box(session.decrypt(drr)?);
            }
        }

        // --- Benchmark: shared partition (max cache contention) ---
        let mut payload = vec![0u8; payload_size];
        rand::fill(&mut payload[..]);
        let payload = Arc::new(payload);

        let start = Instant::now();
        let handles: Vec<_> = (0..num_threads)
            .map(|_| {
                let f = factory.clone();
                let p = payload.clone();
                thread::spawn(move || {
                    let session = f.get_session("shared-partition");
                    for _ in 0..iterations_per_thread {
                        let drr = session.encrypt(black_box(&p)).unwrap();
                        black_box(session.decrypt(drr).unwrap());
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        let wall = start.elapsed();

        let total_ops = num_threads * iterations_per_thread * 2; // encrypt + decrypt
        let ops_sec = total_ops as f64 / wall.as_secs_f64();
        let us_per_op = wall.as_micros() as f64 / total_ops as f64;

        println!(
            "{:>8} {:>12} {:>13.1} {:>13.0} {:>13.2}",
            num_threads,
            total_ops,
            wall.as_millis(),
            ops_sec,
            us_per_op,
        );

        factory.close()?;
    }

    println!("\n--- Distinct partitions (reduced contention) ---\n");
    println!(
        "{:>8} {:>12} {:>14} {:>14} {:>14}",
        "threads", "total_ops", "wall_ms", "ops/sec", "µs/op"
    );
    println!("{}", "-".repeat(66));

    for &num_threads in &thread_counts {
        let master_key = vec![0x22u8; 32];
        let crypto = Arc::new(AES256GCM::new());
        let metastore = Arc::new(InMemoryMetastore::new());
        let kms = Arc::new(StaticKMS::new(crypto.clone(), master_key)?);

        let mut cfg = Config::new("bench-svc", "bench-prod");
        cfg.policy.cache_intermediate_keys = true;
        cfg.policy.intermediate_key_cache_max_size = 100;
        cfg.policy.cache_system_keys = true;
        cfg.policy.system_key_cache_max_size = 100;
        cfg.policy.cache_sessions = true;
        cfg.policy.session_cache_max_size = 100;
        cfg.policy.session_cache_ttl_s = 3600;

        let factory = Arc::new(new_session_factory_with_options(
            cfg,
            metastore,
            kms,
            crypto,
            &[FactoryOption::Metrics(false)],
        ));

        let mut payload = vec![0u8; payload_size];
        rand::fill(&mut payload[..]);
        let payload = Arc::new(payload);

        let start = Instant::now();
        let handles: Vec<_> = (0..num_threads)
            .map(|t| {
                let f = factory.clone();
                let p = payload.clone();
                thread::spawn(move || {
                    let partition = format!("partition-{t}");
                    let session = f.get_session(&partition);
                    for _ in 0..iterations_per_thread {
                        let drr = session.encrypt(black_box(&p)).unwrap();
                        black_box(session.decrypt(drr).unwrap());
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        let wall = start.elapsed();

        let total_ops = num_threads * iterations_per_thread * 2;
        let ops_sec = total_ops as f64 / wall.as_secs_f64();
        let us_per_op = wall.as_micros() as f64 / total_ops as f64;

        println!(
            "{:>8} {:>12} {:>13.1} {:>13.0} {:>13.2}",
            num_threads,
            total_ops,
            wall.as_millis(),
            ops_sec,
            us_per_op,
        );

        factory.close()?;
    }

    Ok(())
}
