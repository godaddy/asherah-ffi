//! Stale-while-revalidate loader failure tests.
//!
//! `SimpleKeyCache::get_or_load_latest` (cache.rs:575-625) has a
//! documented behavior on the SWR loader-error path:
//!
//!     // Metastore error: loaded_at was already bumped by the CAS,
//!     // so we won't retry until next TTL expiry. This is acceptable
//!     // since the metastore is unreachable anyway.
//!
//! That branch returns the stale key to the caller (line 614). Without
//! a test, two future regressions are silent:
//!  1. Bubbling the loader error to the caller — would convert a
//!     transient metastore blip into hard encrypt failures.
//!  2. Removing the CAS bump and retrying on every call — would turn
//!     a transient metastore failure into N×retry per second.
//!
//! These tests pin the documented behavior in place.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use asherah::cache::{KeyCacher, SimpleKeyCache};
use asherah::internal::CryptoKey;
use asherah::types::KeyMeta;

fn make_key(created: i64) -> Arc<CryptoKey> {
    Arc::new(CryptoKey::new(created, false, vec![0xAA; 32]).unwrap())
}

/// SWR loader failure on the latest path returns the stale key to
/// the caller — the metastore error does not bubble up.
#[test]
fn swr_latest_loader_failure_returns_stale_key() {
    let cache = SimpleKeyCache::new_with_ttl(1);

    // Seed.
    let seeded = cache
        .get_or_load_latest("id", &mut || Ok(make_key(100)))
        .unwrap();
    assert_eq!(seeded.created(), 100);

    // Wait for TTL.
    sleep(Duration::from_millis(1100));

    // Reloader fails — caller must still get the stale key, not an
    // error.
    let stale = cache
        .get_or_load_latest("id", &mut || Err(anyhow::anyhow!("metastore unreachable")))
        .expect("SWR loader-failure must return stale key, not propagate the error");
    assert_eq!(
        stale.created(),
        100,
        "expected the stale (seed) key, got created={}",
        stale.created()
    );
}

/// After a SWR loader failure bumps `loaded_at` via CAS, the next
/// call within the TTL window must NOT call the loader again — the
/// CAS bump is the explicit "don't hammer the metastore" signal.
/// This is the second half of the documented behavior.
#[test]
fn swr_latest_loader_failure_does_not_retry_until_next_ttl() {
    let cache = SimpleKeyCache::new_with_ttl(1);

    cache
        .get_or_load_latest("id", &mut || Ok(make_key(100)))
        .unwrap();

    sleep(Duration::from_millis(1100));

    let calls = AtomicUsize::new(0);
    // First call after expiry: claims the reload, calls loader, fails.
    drop(
        cache
            .get_or_load_latest("id", &mut || {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(anyhow::anyhow!("transient metastore error"))
            })
            .unwrap(),
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "first SWR call must invoke loader"
    );

    // Subsequent calls within the TTL window must NOT call the
    // loader — the CAS bump should have updated loaded_at to "now".
    for _ in 0..5 {
        drop(
            cache
                .get_or_load_latest("id", &mut || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Err(anyhow::anyhow!("should not be called"))
                })
                .unwrap(),
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "post-failure SWR must not re-invoke loader within TTL window"
    );
}

/// After the *next* TTL window passes, SWR must try the loader again.
/// (Without this, a single transient failure would freeze the cache
/// forever.)
#[test]
fn swr_latest_loader_retries_in_next_ttl_window() {
    let cache = SimpleKeyCache::new_with_ttl(1);

    cache
        .get_or_load_latest("id", &mut || Ok(make_key(100)))
        .unwrap();

    sleep(Duration::from_millis(1100));

    // First TTL window: loader fails.
    drop(
        cache
            .get_or_load_latest("id", &mut || Err(anyhow::anyhow!("err1")))
            .unwrap(),
    );

    // Wait past the next TTL window — the CAS bump set loaded_at
    // to now, so we need to wait at least another TTL.
    sleep(Duration::from_millis(1100));

    let calls = AtomicUsize::new(0);
    let result = cache
        .get_or_load_latest("id", &mut || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(make_key(200))
        })
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "after next TTL window, SWR must retry the loader"
    );
    assert_eq!(
        result.created(),
        200,
        "loader must have replaced the stale key"
    );
}

/// Cold-miss loader failure must propagate (no stale key to fall
/// back to). Distinguish from the SWR path.
#[test]
fn cold_miss_loader_failure_propagates() {
    let cache = SimpleKeyCache::new_with_ttl(60);
    let result = cache.get_or_load_latest("id", &mut || Err(anyhow::anyhow!("cold-fail")));
    assert!(
        result.is_err(),
        "cold-miss loader failure must propagate the error"
    );
    assert!(
        result.unwrap_err().to_string().contains("cold-fail"),
        "error message should reflect loader's error"
    );
}

/// On the meta path, SWR doesn't call the loader at all (decrypt path
/// — the key material at `(id, created)` is immutable). A "loader
/// failure" path therefore should never trip a real metastore call;
/// this test guards against a regression that introduces one.
#[test]
fn swr_meta_does_not_invoke_loader_on_stale() {
    let cache = SimpleKeyCache::new_with_ttl(1);
    let meta = KeyMeta {
        id: "k".into(),
        created: 42,
    };

    // Seed.
    cache.get_or_load(&meta, &mut || Ok(make_key(42))).unwrap();

    sleep(Duration::from_millis(1100));

    let calls = AtomicUsize::new(0);
    let key = cache
        .get_or_load(&meta, &mut || {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::anyhow!("must not be called"))
        })
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "SWR meta path must not call the loader for stale-but-cached entries"
    );
    assert_eq!(key.created(), 42);
}

/// Loader failure under concurrent load: with 8 threads racing on a
/// stale entry, only the CAS winner calls the loader. If that loader
/// fails, every other thread still gets the stale key. No thread
/// must surface the loader's error.
#[test]
fn concurrent_swr_loader_failure_isolated_to_one_thread() {
    use std::sync::Barrier;
    let cache = Arc::new(SimpleKeyCache::new_with_ttl(1));
    cache
        .get_or_load_latest("id", &mut || Ok(make_key(100)))
        .unwrap();
    sleep(Duration::from_millis(1100));

    const THREADS: usize = 8;
    let barrier = Arc::new(Barrier::new(THREADS));
    let load_calls = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let c = cache.clone();
        let b = barrier.clone();
        let lc = load_calls.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            c.get_or_load_latest("id", &mut || {
                lc.fetch_add(1, Ordering::SeqCst);
                sleep(Duration::from_millis(20));
                Err(anyhow::anyhow!("transient"))
            })
        }));
    }

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All threads must have received Ok (the stale key) — none should
    // surface the loader's error.
    for r in &results {
        let key = r
            .as_ref()
            .expect("SWR concurrent loader-failure must not surface an error");
        assert_eq!(
            key.created(),
            100,
            "expected stale key (created=100), got created={}",
            key.created()
        );
    }

    // CAS contract: at most a couple of loader calls (one winner +
    // potential CAS race losers retrying). Definitely not THREADS.
    let calls = load_calls.load(Ordering::SeqCst);
    assert!(
        calls <= 2,
        "expected at most 2 loader calls under SWR contention, got {calls}"
    );
}
