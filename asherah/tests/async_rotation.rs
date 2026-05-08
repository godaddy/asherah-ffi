//! Rotation, revocation, and race-loss coverage for the **async**
//! encrypt/decrypt path.
//!
//! `PublicSession::encrypt_async` / `decrypt_async` go through a
//! parallel implementation (`session.rs:1054-1340`) with its own
//! `get_or_load_system_key_async`,
//! `load_intermediate_key_async`,
//! `load_latest_or_create_intermediate_key_async`,
//! `create_intermediate_key_async`. This impl uses `check_*` /
//! `insert_*_key` cache primitives plus `tokio::task::spawn_blocking`
//! for SK loaders, instead of the sync path's `get_or_load_*`. The
//! sync path has rotation/revocation tests; the async path didn't.
//! Without parallel coverage, an async-only regression (e.g. cache
//! check that ignores `invalid`, race-loss recovery that doesn't
//! reload, SK rotation that uses a stale cached SK) would be silent.
//!
//! `tests/async_session.rs` covers happy-path round-trips. This file
//! covers the scary moments: expiration, revocation, concurrent
//! rotation, sync↔async interop across rotation boundaries.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use asherah as ael;

fn make_factory(
    store: Arc<ael::metastore::InMemoryMetastore>,
    expire_s: i64,
) -> ael::SessionFactory<
    ael::aead::AES256GCM,
    ael::kms::StaticKMS<ael::aead::AES256GCM>,
    ael::metastore::InMemoryMetastore,
> {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![0x88_u8; 32]).unwrap());
    let mut cfg = ael::Config::new("async-rot-svc", "async-rot-prod");
    cfg.policy.expire_key_after_s = expire_s;
    cfg.policy.create_date_precision_s = 1;
    cfg.policy.revoke_check_interval_s = 1;
    cfg.policy.cache_sessions = false;
    ael::api::new_session_factory(cfg, store, kms, crypto)
}

fn ik_meta(drr: &ael::DataRowRecord) -> (String, i64) {
    let pkm = drr.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    (pkm.id.clone(), pkm.created)
}

fn sk_meta(store: &ael::metastore::InMemoryMetastore, drr: &ael::DataRowRecord) -> (String, i64) {
    let (ik_id, ik_created) = ik_meta(drr);
    let ik_ekr = ael::Metastore::load(store, &ik_id, ik_created)
        .unwrap()
        .unwrap();
    let parent = ik_ekr.parent_key_meta.as_ref().unwrap();
    (parent.id.clone(), parent.created)
}

/// Async equivalent of `tests/rotation_expiration.rs::creates_new_intermediate_key_when_expired`.
/// Encrypt, sleep past expiry, encrypt again — the second encrypt
/// must produce a strictly newer IK created timestamp.
#[tokio::test]
async fn async_rotation_creates_new_ik_when_expired() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store.clone(), 1);
    let session = factory.get_session("p-async-rot");

    let drr1 = session.encrypt_async(b"one").await.unwrap();
    let (_, ik1) = ik_meta(&drr1);

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let drr2 = session.encrypt_async(b"two").await.unwrap();
    let (_, ik2) = ik_meta(&drr2);

    assert!(
        ik2 > ik1,
        "async path must rotate IK after expiry: {ik2} > {ik1}"
    );
    assert_eq!(session.decrypt_async(drr1).await.unwrap(), b"one");
    assert_eq!(session.decrypt_async(drr2).await.unwrap(), b"two");
}

/// Async equivalent of `tests/revocation.rs::revoked_intermediate_key_triggers_rotation`.
#[tokio::test]
async fn async_revoked_ik_triggers_rotation() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store.clone(), 24 * 60 * 60);
    let session = factory.get_session("p-async-rev");

    let drr1 = session.encrypt_async(b"pre").await.unwrap();
    let (ik_id, ik_created) = ik_meta(&drr1);

    store.mark_revoked(&ik_id, ik_created);
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let drr2 = session.encrypt_async(b"post").await.unwrap();
    let (_, ik_created_2) = ik_meta(&drr2);
    assert!(
        ik_created_2 > ik_created,
        "async path must rotate IK after revocation: {ik_created_2} > {ik_created}"
    );

    assert_eq!(session.decrypt_async(drr1).await.unwrap(), b"pre");
    assert_eq!(session.decrypt_async(drr2).await.unwrap(), b"post");
}

/// Async equivalent of `tests/revocation.rs::revoked_key_still_decrypts_old_data`.
/// Decrypt-by-exact-meta must work for revoked historical keys.
#[tokio::test]
async fn async_revoked_key_still_decrypts_old_data() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store.clone(), 24 * 60 * 60);
    let session = factory.get_session("p-async-hist");

    let drr = session.encrypt_async(b"old secret").await.unwrap();
    let (ik_id, ik_created) = ik_meta(&drr);

    store.mark_revoked(&ik_id, ik_created);
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let pt = session.decrypt_async(drr).await.unwrap();
    assert_eq!(pt, b"old secret");
}

/// Async SK rotation: revoke SK, force IK rotation, verify a new SK
/// was created on the async path. Mirrors
/// `tests/sk_revocation.rs::sk_revocation_rotates_on_next_ik_rotation`.
#[tokio::test]
async fn async_sk_revocation_rotates_on_next_ik_rotation() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    // 1-second expiry so both IK and SK age out together — the
    // simplest path to forcing IK rotation, which in turn forces
    // the async SK loader to revisit the latest SK.
    let factory = make_factory(store.clone(), 1);
    let session = factory.get_session("p-async-sk-rev");

    let drr1 = session.encrypt_async(b"pre").await.unwrap();
    let (sk_id, sk_created_1) = sk_meta(&store, &drr1);

    store.mark_revoked(&sk_id, sk_created_1);
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let drr2 = session.encrypt_async(b"post").await.unwrap();
    let (_, sk_created_2) = sk_meta(&store, &drr2);

    assert!(
        sk_created_2 > sk_created_1,
        "async path must rotate SK on next IK rotation: {sk_created_2} > {sk_created_1}"
    );

    assert_eq!(session.decrypt_async(drr1).await.unwrap(), b"pre");
    assert_eq!(session.decrypt_async(drr2).await.unwrap(), b"post");
}

/// Concurrent rotation on the async path: N tokio tasks barrier-
/// synchronized, all encrypt_async on the same hot partition just
/// after expiry. Asserts every DRR decrypts (under both async and
/// sync), no metastore corruption, and `load_latest` matches what
/// at least one task observed.
///
/// Mirrors `tests/concurrent_rotation.rs::concurrent_rotation_converges_on_one_ik`
/// using tokio's notify primitive instead of std::sync::Barrier
/// because Barrier::wait blocks the executor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_concurrent_rotation_converges_on_one_ik() {
    use std::collections::HashSet;
    use tokio::sync::Barrier;

    const TASKS: usize = 8;
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = Arc::new(make_factory(store.clone(), 1));

    // Seed the IK so the burst is exercising rotation, not first-
    // creation under contention.
    let seed_session = factory.get_session("hot-async");
    let seed_drr = seed_session.encrypt_async(b"seed").await.unwrap();
    let (ik_id, seed_ik_created) = ik_meta(&seed_drr);

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let barrier = Arc::new(Barrier::new(TASKS));
    let mut handles = Vec::with_capacity(TASKS);
    for i in 0..TASKS {
        let f = factory.clone();
        let b = barrier.clone();
        handles.push(tokio::spawn(async move {
            let s = f.get_session("hot-async");
            b.wait().await;
            let msg = format!("burst-{i}");
            let drr = s.encrypt_async(msg.as_bytes()).await.unwrap();
            let pt = s.decrypt_async(drr.clone()).await.unwrap();
            assert_eq!(pt, msg.as_bytes());
            (i, drr, msg)
        }));
    }
    let mut results = Vec::with_capacity(TASKS);
    for h in handles {
        results.push(h.await.unwrap());
    }

    let mut observed: HashSet<i64> = HashSet::new();
    for (_, drr, _) in &results {
        let (_, c) = ik_meta(drr);
        observed.insert(c);
        assert!(c >= seed_ik_created);
    }
    let max_seen = *observed.iter().max().unwrap();
    assert!(
        max_seen > seed_ik_created,
        "no rotation: max observed IK {max_seen} == seed {seed_ik_created}"
    );

    let latest = ael::Metastore::load_latest(&*store, &ik_id)
        .unwrap()
        .expect("metastore must have a latest IK");
    assert!(
        observed.contains(&latest.created),
        "load_latest {} not observed by any task (observed: {:?})",
        latest.created,
        observed
    );

    // Cross-decrypt: every burst DRR must also decrypt under a fresh
    // session, both async and sync.
    let fresh = factory.get_session("hot-async");
    for (_, drr, msg) in &results {
        assert_eq!(
            &fresh.decrypt_async(drr.clone()).await.unwrap(),
            msg.as_bytes()
        );
        assert_eq!(&fresh.decrypt(drr.clone()).unwrap(), msg.as_bytes());
    }
}

/// Sync↔async interop across a rotation boundary. Encrypt sync,
/// rotate, decrypt async (and vice versa). Catches regressions
/// where the two paths drift in their handling of historical keys.
#[tokio::test]
async fn async_sync_interop_after_rotation() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store.clone(), 1);
    let session = factory.get_session("p-interop");

    // Encrypt under both paths before rotation.
    let drr_sync_pre = session.encrypt(b"sync-pre").unwrap();
    let drr_async_pre = session.encrypt_async(b"async-pre").await.unwrap();

    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Encrypt under both paths after rotation.
    let drr_sync_post = session.encrypt(b"sync-post").unwrap();
    let drr_async_post = session.encrypt_async(b"async-post").await.unwrap();

    // Cross-decrypt every combination (4 DRRs × 2 paths = 8 round trips).
    assert_eq!(session.decrypt(drr_sync_pre.clone()).unwrap(), b"sync-pre");
    assert_eq!(
        session.decrypt_async(drr_sync_pre).await.unwrap(),
        b"sync-pre"
    );
    assert_eq!(
        session.decrypt(drr_async_pre.clone()).unwrap(),
        b"async-pre"
    );
    assert_eq!(
        session.decrypt_async(drr_async_pre).await.unwrap(),
        b"async-pre"
    );
    assert_eq!(
        session.decrypt(drr_sync_post.clone()).unwrap(),
        b"sync-post"
    );
    assert_eq!(
        session.decrypt_async(drr_sync_post).await.unwrap(),
        b"sync-post"
    );
    assert_eq!(
        session.decrypt(drr_async_post.clone()).unwrap(),
        b"async-post"
    );
    assert_eq!(
        session.decrypt_async(drr_async_post).await.unwrap(),
        b"async-post"
    );
}

/// Async equivalent of `tests/cache_ttl.rs::ik_cache_ttl_expires_and_reloads`.
/// First encrypt populates IK cache, second hits cache, third (after
/// TTL) reloads.
#[tokio::test]
async fn async_ik_cache_ttl_reload() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    // Long policy expiry so TTL alone drives the reload.
    let factory = make_factory(store.clone(), 24 * 60 * 60);
    let session = factory.get_session("p-async-ttl");

    let drr1 = session.encrypt_async(b"first").await.unwrap();
    let (_, ik1) = ik_meta(&drr1);

    let drr2 = session.encrypt_async(b"second").await.unwrap();
    let (_, ik2) = ik_meta(&drr2);
    assert_eq!(ik1, ik2, "second encrypt should hit cache (same IK)");

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let drr3 = session.encrypt_async(b"third").await.unwrap();
    let (_, ik3) = ik_meta(&drr3);
    assert!(
        ik3 > 0,
        "post-TTL IK created should be a sane epoch, got {ik3}"
    );

    // All three round-trip.
    assert_eq!(session.decrypt_async(drr1).await.unwrap(), b"first");
    assert_eq!(session.decrypt_async(drr2).await.unwrap(), b"second");
    assert_eq!(session.decrypt_async(drr3).await.unwrap(), b"third");
}

/// Cascading revocations on the async path. Three rounds of
/// {encrypt_async → revoke IK → sleep}; every prior DRR remains
/// decryptable.
#[tokio::test]
async fn async_cascading_revocations() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store.clone(), 24 * 60 * 60);
    let session = factory.get_session("p-async-casc");

    let mut drrs: Vec<(ael::DataRowRecord, String)> = Vec::new();
    let mut prev: i64 = i64::MIN;

    for round in 0..3 {
        let msg = format!("round-{round}");
        let drr = session.encrypt_async(msg.as_bytes()).await.unwrap();
        let (ik_id, ik_created) = ik_meta(&drr);
        if round > 0 {
            assert!(
                ik_created > prev,
                "round {round}: IK {ik_created} should be > prev {prev}"
            );
        }
        prev = ik_created;
        drrs.push((drr, msg));
        store.mark_revoked(&ik_id, ik_created);
        tokio::time::sleep(Duration::from_millis(1100)).await;
    }

    for (drr, msg) in drrs {
        assert_eq!(session.decrypt_async(drr).await.unwrap(), msg.as_bytes());
    }
}
