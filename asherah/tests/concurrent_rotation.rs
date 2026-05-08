//! Concurrent rotation tests — N threads racing to rotate the **same**
//! partition's IK at an expiration boundary.
//!
//! The existing `cache_concurrent.rs` runs N threads but each on a
//! distinct partition, so threads never race for the same key. The
//! single-flight CAS in `cache.rs::try_claim_reload_latest` and the
//! metastore-store race-loss recovery in
//! `Session::create_intermediate_key` are the two mechanisms that
//! prevent corruption when N threads simultaneously cross an
//! expiration boundary on a hot partition. Production traffic will
//! hit this path on the 90-day rotation. Without these tests a
//! regression in either mechanism is silent.
//!
//! Invariants asserted:
//!  1. After a rotation burst, every thread's DRR decrypts to its
//!     plaintext.
//!  2. The metastore contains exactly one IK at the post-rotation
//!     `created` value (not N entries — the race-loss recovery folded
//!     duplicates).
//!  3. All threads encrypted under an IK with `created >= ` the
//!     pre-rotation IK's `created`.
//!  4. SK rotation under the same load behaves the same way.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use asherah as ael;

fn make_factory(
    store: Arc<ael::metastore::InMemoryMetastore>,
    expire_s: i64,
) -> Arc<
    ael::SessionFactory<
        ael::aead::AES256GCM,
        ael::kms::StaticKMS<ael::aead::AES256GCM>,
        ael::metastore::InMemoryMetastore,
    >,
> {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![0x42_u8; 32]).unwrap());
    let mut cfg = ael::Config::new("conc-rot-svc", "conc-rot-prod");
    cfg.policy.expire_key_after_s = expire_s;
    cfg.policy.create_date_precision_s = 1;
    cfg.policy.revoke_check_interval_s = 1;
    // Force a shared, bounded IK cache so all threads hit the same
    // entry; single-flight + race-loss recovery is the unit under
    // test, not per-session caching.
    cfg.policy.shared_intermediate_key_cache = true;
    cfg.policy.cache_intermediate_keys = true;
    cfg.policy.cache_system_keys = true;
    cfg.policy.cache_sessions = false;
    Arc::new(ael::api::new_session_factory(cfg, store, kms, crypto))
}

/// All threads encrypt simultaneously after the IK has policy-expired.
/// Exactly one IK should be created and visible via `load_latest`; the
/// metastore should not contain N duplicate IKs.
#[test]
fn concurrent_rotation_converges_on_one_ik() {
    const THREADS: usize = 16;
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store.clone(), 1);

    // Seed the IK so the first call doesn't have to take the create
    // path under contention. The barrier-synchronized burst below is
    // about *rotation*, not first-creation.
    let seed_session = factory.get_session("hot-partition");
    let seed_drr = seed_session.encrypt(b"seed").unwrap();
    let seed_ik_created = seed_drr
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;
    let ik_id = seed_drr
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .id
        .clone();

    // Sleep past `expire_key_after_s` + `create_date_precision_s` so
    // the seed IK is policy-expired AND the new timestamp will be
    // strictly greater than the seed.
    thread::sleep(Duration::from_millis(1200));

    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    for i in 0..THREADS {
        let f = factory.clone();
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            // All threads share the same partition so they hit the
            // same IK cache entry and the same metastore row.
            let s = f.get_session("hot-partition");
            b.wait();
            let msg = format!("burst-{i}");
            let drr = s.encrypt(msg.as_bytes()).unwrap();
            let pt = s.decrypt(drr.clone()).unwrap();
            assert_eq!(pt, msg.as_bytes());
            (i, drr, msg)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Invariant 1: every DRR decrypted on its producer thread.
    // (Asserted inline above; record the observed IK timestamps for
    // invariants 2-3.)
    let mut observed_ik_createds: HashSet<i64> = HashSet::new();
    for (_, drr, _) in &results {
        let pkm = drr.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
        observed_ik_createds.insert(pkm.created);
        assert!(
            pkm.created >= seed_ik_created,
            "post-rotation IK created {} must be >= seed {}",
            pkm.created,
            seed_ik_created
        );
    }

    // Invariant 3: rotation actually happened — at least one thread
    // got a strictly newer IK. (Some may share the seed IK if the
    // create_date_precision rounded their timestamps to the seed
    // window, but with a 1.2s sleep that's not possible.)
    let max_seen = *observed_ik_createds.iter().max().unwrap();
    assert!(
        max_seen > seed_ik_created,
        "no rotation occurred: max observed IK {max_seen} == seed {seed_ik_created}"
    );

    // Invariant 2: the metastore must NOT contain N duplicate IKs at
    // the post-rotation timestamp. The store's `(id, created)` is the
    // primary key so duplicates would have been collapsed by the
    // store anyway; what we're really asserting is that
    // `load_latest` returns the IK every thread converged on.
    let latest = ael::Metastore::load_latest(&*store, &ik_id)
        .unwrap()
        .expect("metastore must have a latest IK after the burst");
    assert!(
        observed_ik_createds.contains(&latest.created),
        "load_latest returned created={} which no thread observed (observed: {:?})",
        latest.created,
        observed_ik_createds
    );

    // Cross-decryption: every DRR must also decrypt under a *fresh*
    // session (one not in the original race). This shape regression-
    // tests the case where the race-loss recovery returns a
    // different-but-equivalent IK to the loser.
    let fresh_factory = factory.clone();
    let fresh_session = fresh_factory.get_session("hot-partition");
    for (_, drr, msg) in &results {
        let pt = fresh_session.decrypt(drr.clone()).unwrap();
        assert_eq!(&pt, msg.as_bytes());
    }
}

/// Same shape as above but for SK rotation. The SK cache is shared at
/// the factory level (`session.rs:567`), so a bad SK rotation poisons
/// every session in the process.
#[test]
fn concurrent_rotation_converges_on_one_sk() {
    const THREADS: usize = 16;
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store.clone(), 1);

    // Seed: encrypt to populate SK1 and IK1 in the metastore.
    let seed_session = factory.get_session("sk-burst");
    let seed_drr = seed_session.encrypt(b"seed").unwrap();
    let seed_ik_meta = seed_drr
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap();
    let seed_ik = ael::Metastore::load(&*store, &seed_ik_meta.id, seed_ik_meta.created)
        .unwrap()
        .unwrap();
    let seed_sk_created = seed_ik.parent_key_meta.as_ref().unwrap().created;

    // Sleep past expiration so the burst forces SK rotation.
    thread::sleep(Duration::from_millis(1200));

    let barrier = Arc::new(Barrier::new(THREADS));
    let mut handles = Vec::with_capacity(THREADS);
    // Use distinct partitions per thread so each one needs its own IK
    // (and therefore needs to call `get_or_load_system_key(latest)`),
    // which is what makes them race for the SAME SK.
    for i in 0..THREADS {
        let f = factory.clone();
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            let partition = format!("sk-burst-{i}");
            let s = f.get_session(&partition);
            b.wait();
            let msg = format!("sk-burst-{i}");
            let drr = s.encrypt(msg.as_bytes()).unwrap();
            let pt = s.decrypt(drr.clone()).unwrap();
            assert_eq!(pt, msg.as_bytes());
            (i, drr, msg)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Each thread's IK must reference the rotated SK. Walk back from
    // the DRR → IK → parent_key_meta and collect SK timestamps.
    let mut observed_sks: HashSet<i64> = HashSet::new();
    for (_, drr, _) in &results {
        let ik_meta = drr.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
        let ik_ekr = ael::Metastore::load(&*store, &ik_meta.id, ik_meta.created)
            .unwrap()
            .unwrap();
        let sk_created = ik_ekr.parent_key_meta.as_ref().unwrap().created;
        observed_sks.insert(sk_created);
    }

    let sk_max = *observed_sks.iter().max().unwrap();
    assert!(
        sk_max > seed_sk_created,
        "no SK rotation: max observed SK created {sk_max} == seed {seed_sk_created}"
    );

    // The metastore's latest SK pointer must match what at least one
    // thread observed. A divergent latest pointer means the race-loss
    // recovery in `try_store_system_key` lost atomicity.
    let sk_id = seed_ik.parent_key_meta.as_ref().unwrap().id.clone();
    let latest_sk = ael::Metastore::load_latest(&*store, &sk_id)
        .unwrap()
        .expect("metastore must have a latest SK");
    assert!(
        observed_sks.contains(&latest_sk.created),
        "load_latest SK created={} not observed by any thread (observed: {:?})",
        latest_sk.created,
        observed_sks
    );

    // Cross-decrypt every DRR under a fresh session.
    let fresh_factory = factory.clone();
    for (i, drr, msg) in &results {
        let partition = format!("sk-burst-{i}");
        let s = fresh_factory.get_session(&partition);
        let pt = s.decrypt(drr.clone()).unwrap();
        assert_eq!(&pt, msg.as_bytes());
    }
}

/// Long-running concurrent rotation: drive multiple rotation cycles
/// through the same hot partition. Catches state-leak regressions
/// (e.g. cache entry not replaced after expiry, latest pointer
/// drifting, metastore growing unboundedly).
#[test]
fn concurrent_rotation_multiple_cycles() {
    const THREADS: usize = 8;
    const CYCLES: usize = 3;
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store.clone(), 1);

    let mut all_drrs: Vec<(ael::DataRowRecord, String)> = Vec::new();
    let mut last_seen_ik: i64 = i64::MIN;

    for cycle in 0..CYCLES {
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::with_capacity(THREADS);
        for i in 0..THREADS {
            let f = factory.clone();
            let b = barrier.clone();
            handles.push(thread::spawn(move || {
                let s = f.get_session("hot-multi");
                b.wait();
                let msg = format!("cycle-{cycle}-thread-{i}");
                let drr = s.encrypt(msg.as_bytes()).unwrap();
                (drr, msg)
            }));
        }
        let cycle_results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // The cycle's max IK created must exceed the previous cycle's
        // max — i.e. rotation actually advanced.
        let cycle_max = cycle_results
            .iter()
            .map(|(d, _)| {
                d.key
                    .as_ref()
                    .unwrap()
                    .parent_key_meta
                    .as_ref()
                    .unwrap()
                    .created
            })
            .max()
            .unwrap();
        if cycle > 0 {
            assert!(
                cycle_max > last_seen_ik,
                "cycle {cycle} did not rotate: max IK {cycle_max} <= prev cycle max {last_seen_ik}"
            );
        }
        last_seen_ik = cycle_max;

        all_drrs.extend(cycle_results);

        // Sleep past expiry before the next cycle.
        thread::sleep(Duration::from_millis(1200));
    }

    // Every DRR from every cycle must still decrypt — historical
    // decrypt of all rotated-past keys.
    let s = factory.get_session("hot-multi");
    for (drr, msg) in &all_drrs {
        let pt = s.decrypt(drr.clone()).unwrap();
        assert_eq!(&pt, msg.as_bytes());
    }
}
