#![allow(clippy::unwrap_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use asherah::cache::{CachePolicy, KeyCacher, NeverCache, SimpleKeyCache};
use asherah::internal::CryptoKey;
use asherah::types::KeyMeta;

fn make_key(created: i64, revoked: bool) -> Arc<CryptoKey> {
    Arc::new(CryptoKey::new(created, revoked, vec![0xAB; 32]).unwrap())
}

// ---------------------------------------------------------------------------
// CachePolicy::parse
// ---------------------------------------------------------------------------

#[test]
fn parse_simple() {
    assert_eq!(
        CachePolicy::parse("simple", CachePolicy::Lru),
        CachePolicy::Simple
    );
}

#[test]
fn parse_lru() {
    assert_eq!(
        CachePolicy::parse("lru", CachePolicy::Simple),
        CachePolicy::Lru
    );
}

#[test]
fn parse_lfu() {
    assert_eq!(
        CachePolicy::parse("lfu", CachePolicy::Simple),
        CachePolicy::Lfu
    );
}

#[test]
fn parse_slru() {
    assert_eq!(
        CachePolicy::parse("slru", CachePolicy::Simple),
        CachePolicy::Slru
    );
}

#[test]
fn parse_tinylfu() {
    assert_eq!(
        CachePolicy::parse("tinylfu", CachePolicy::Simple),
        CachePolicy::TinyLfu
    );
}

#[test]
fn parse_case_insensitive() {
    assert_eq!(
        CachePolicy::parse("SIMPLE", CachePolicy::Lru),
        CachePolicy::Simple
    );
    assert_eq!(
        CachePolicy::parse("Lru", CachePolicy::Simple),
        CachePolicy::Lru
    );
    assert_eq!(
        CachePolicy::parse("LFU", CachePolicy::Simple),
        CachePolicy::Lfu
    );
    assert_eq!(
        CachePolicy::parse("SLRU", CachePolicy::Simple),
        CachePolicy::Slru
    );
    assert_eq!(
        CachePolicy::parse("TinyLfu", CachePolicy::Simple),
        CachePolicy::TinyLfu
    );
}

#[test]
fn parse_unknown_returns_default() {
    assert_eq!(
        CachePolicy::parse("unknown", CachePolicy::Lfu),
        CachePolicy::Lfu
    );
    assert_eq!(
        CachePolicy::parse("", CachePolicy::TinyLfu),
        CachePolicy::TinyLfu
    );
    assert_eq!(
        CachePolicy::parse("garbage", CachePolicy::Simple),
        CachePolicy::Simple
    );
}

// ---------------------------------------------------------------------------
// NeverCache
// ---------------------------------------------------------------------------

#[test]
fn never_cache_get_or_load_latest_always_calls_loader() {
    let cache = NeverCache;
    let calls = AtomicUsize::new(0);
    let mut loader = || -> anyhow::Result<Arc<CryptoKey>> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key(100, false))
    };

    for _ in 0..5 {
        cache.get_or_load_latest("key1", &mut loader).unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 5);
}

#[test]
fn never_cache_get_or_load_always_calls_loader() {
    let cache = NeverCache;
    let calls = AtomicUsize::new(0);
    let meta = KeyMeta {
        id: "key1".into(),
        created: 100,
    };
    let mut loader = || -> anyhow::Result<Arc<CryptoKey>> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key(100, false))
    };

    for _ in 0..5 {
        cache.get_or_load(&meta, &mut loader).unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 5);
}

#[test]
fn never_cache_loader_count_matches_call_count() {
    let cache = NeverCache;
    let latest_calls = AtomicUsize::new(0);
    let meta_calls = AtomicUsize::new(0);
    let meta = KeyMeta {
        id: "k".into(),
        created: 1,
    };

    let mut latest_loader = || -> anyhow::Result<Arc<CryptoKey>> {
        latest_calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key(1, false))
    };
    let mut meta_loader = || -> anyhow::Result<Arc<CryptoKey>> {
        meta_calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key(1, false))
    };

    for _ in 0..3 {
        cache.get_or_load_latest("k", &mut latest_loader).unwrap();
    }
    for _ in 0..7 {
        cache.get_or_load(&meta, &mut meta_loader).unwrap();
    }
    assert_eq!(latest_calls.load(Ordering::SeqCst), 3);
    assert_eq!(meta_calls.load(Ordering::SeqCst), 7);
}

// ---------------------------------------------------------------------------
// SimpleKeyCache basic caching
// ---------------------------------------------------------------------------

#[test]
fn simple_cache_get_or_load_latest_caches_result() {
    let cache = SimpleKeyCache::new();
    let calls = AtomicUsize::new(0);
    let mut loader = || -> anyhow::Result<Arc<CryptoKey>> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key(100, false))
    };

    let v1 = cache.get_or_load_latest("id1", &mut loader).unwrap();
    let v2 = cache.get_or_load_latest("id1", &mut loader).unwrap();

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "loader should only be called once"
    );
    assert_eq!(v1.created(), v2.created());
}

#[test]
fn simple_cache_different_ids_call_loader_separately() {
    let cache = SimpleKeyCache::new();
    let calls = AtomicUsize::new(0);
    let mut loader = || -> anyhow::Result<Arc<CryptoKey>> {
        let n = calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key((n as i64 + 1) * 100, false))
    };

    let v1 = cache.get_or_load_latest("a", &mut loader).unwrap();
    let v2 = cache.get_or_load_latest("b", &mut loader).unwrap();
    let v3 = cache.get_or_load_latest("a", &mut loader).unwrap();

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "loader called once per distinct id"
    );
    assert_eq!(v1.created(), v3.created());
    assert_ne!(v1.created(), v2.created());
}

// ---------------------------------------------------------------------------
// SimpleKeyCache TTL=0 (always expired)
// ---------------------------------------------------------------------------

#[test]
fn simple_cache_ttl_zero_always_calls_loader() {
    let cache = SimpleKeyCache::new_with_ttl(0);
    let calls = AtomicUsize::new(0);
    let mut loader = || -> anyhow::Result<Arc<CryptoKey>> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key(100, false))
    };

    for _ in 0..5 {
        cache.get_or_load_latest("id1", &mut loader).unwrap();
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        5,
        "every call should go through loader with ttl=0"
    );
}

// ---------------------------------------------------------------------------
// SimpleKeyCache get_or_load by KeyMeta
// ---------------------------------------------------------------------------

#[test]
fn simple_cache_get_or_load_by_meta_caches_per_unique_meta() {
    let cache = SimpleKeyCache::new();
    let calls = AtomicUsize::new(0);
    let meta1 = KeyMeta {
        id: "key1".into(),
        created: 100,
    };
    let meta2 = KeyMeta {
        id: "key1".into(),
        created: 200,
    };
    let meta3 = KeyMeta {
        id: "key2".into(),
        created: 100,
    };

    let mut loader = || -> anyhow::Result<Arc<CryptoKey>> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key(42, false))
    };

    cache.get_or_load(&meta1, &mut loader).unwrap();
    cache.get_or_load(&meta1, &mut loader).unwrap();
    cache.get_or_load(&meta2, &mut loader).unwrap();
    cache.get_or_load(&meta3, &mut loader).unwrap();
    cache.get_or_load(&meta2, &mut loader).unwrap();

    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "loader should be called once per unique (id, created)"
    );
}

// ---------------------------------------------------------------------------
// LRU eviction
// ---------------------------------------------------------------------------

#[test]
fn lru_eviction_removes_least_recently_used() {
    let cache = SimpleKeyCache::new_with_policy(3600, 2, CachePolicy::Lru, 0);
    let calls = AtomicUsize::new(0);

    let make_loader = |created: i64| {
        let calls_ref = &calls;
        move || -> anyhow::Result<Arc<CryptoKey>> {
            calls_ref.fetch_add(1, Ordering::SeqCst);
            Ok(make_key(created, false))
        }
    };

    // Insert item A (created=1) and B (created=2) -- fills cache to max=2
    cache.get_or_load_latest("a", &mut make_loader(1)).unwrap();
    cache.get_or_load_latest("b", &mut make_loader(2)).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // Insert item C (created=3) -- should evict A (least recently used)
    cache.get_or_load_latest("c", &mut make_loader(3)).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    // Access A again -- should trigger loader since it was evicted
    cache.get_or_load_latest("a", &mut make_loader(10)).unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "A should have been evicted and reloaded"
    );

    // Access B -- should still be cached (it was more recently used than A when C was inserted)
    cache.get_or_load_latest("b", &mut make_loader(20)).unwrap();
    // B might or might not be evicted at this point depending on what was evicted when A was re-added.
    // The key assertion is that inserting C caused an eviction.
}

// ---------------------------------------------------------------------------
// LFU eviction
// ---------------------------------------------------------------------------

#[test]
fn lfu_eviction_removes_least_frequently_used() {
    let cache = SimpleKeyCache::new_with_policy(3600, 2, CachePolicy::Lfu, 0);
    let calls = AtomicUsize::new(0);

    let make_loader = |created: i64| {
        let calls_ref = &calls;
        move || -> anyhow::Result<Arc<CryptoKey>> {
            calls_ref.fetch_add(1, Ordering::SeqCst);
            Ok(make_key(created, false))
        }
    };

    // Insert A and B
    cache.get_or_load_latest("a", &mut make_loader(1)).unwrap();
    cache.get_or_load_latest("b", &mut make_loader(2)).unwrap();

    // Access A multiple times to increase its frequency
    cache.get_or_load_latest("a", &mut make_loader(1)).unwrap();
    cache.get_or_load_latest("a", &mut make_loader(1)).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2, "only 2 initial loads");

    // Insert C -- should evict B (least frequently used)
    cache.get_or_load_latest("c", &mut make_loader(3)).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    // A should still be cached
    cache.get_or_load_latest("a", &mut make_loader(10)).unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "A should still be cached (high freq)"
    );

    // B should have been evicted
    cache.get_or_load_latest("b", &mut make_loader(20)).unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "B should have been evicted (low freq)"
    );
}

// ---------------------------------------------------------------------------
// SLRU eviction
// ---------------------------------------------------------------------------

#[test]
fn slru_eviction_evicts_probationary_first() {
    let cache = SimpleKeyCache::new_with_policy(3600, 2, CachePolicy::Slru, 0);
    let calls = AtomicUsize::new(0);

    let make_loader = |created: i64| {
        let calls_ref = &calls;
        move || -> anyhow::Result<Arc<CryptoKey>> {
            calls_ref.fetch_add(1, Ordering::SeqCst);
            Ok(make_key(created, false))
        }
    };

    // Insert A and B -- both start as probationary
    cache.get_or_load_latest("a", &mut make_loader(1)).unwrap();
    cache.get_or_load_latest("b", &mut make_loader(2)).unwrap();

    // Access A again -- promotes A to protected
    cache.get_or_load_latest("a", &mut make_loader(1)).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // Insert C -- should evict B (probationary) not A (protected)
    cache.get_or_load_latest("c", &mut make_loader(3)).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    // A should still be cached (was protected)
    cache.get_or_load_latest("a", &mut make_loader(10)).unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "A should still be cached (protected)"
    );

    // B was evicted (was probationary)
    cache.get_or_load_latest("b", &mut make_loader(20)).unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "B should have been evicted (probationary)"
    );
}

// ---------------------------------------------------------------------------
// TinyLFU eviction
// ---------------------------------------------------------------------------

#[test]
fn tinylfu_eviction_removes_least_frequent_with_decay() {
    let cache = SimpleKeyCache::new_with_policy(3600, 2, CachePolicy::TinyLfu, 0);
    let calls = AtomicUsize::new(0);

    let make_loader = |created: i64| {
        let calls_ref = &calls;
        move || -> anyhow::Result<Arc<CryptoKey>> {
            calls_ref.fetch_add(1, Ordering::SeqCst);
            Ok(make_key(created, false))
        }
    };

    // Insert A and B
    cache.get_or_load_latest("a", &mut make_loader(1)).unwrap();
    cache.get_or_load_latest("b", &mut make_loader(2)).unwrap();

    // Access A to boost frequency
    cache.get_or_load_latest("a", &mut make_loader(1)).unwrap();
    cache.get_or_load_latest("a", &mut make_loader(1)).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // Insert C -- should evict B (lower frequency)
    cache.get_or_load_latest("c", &mut make_loader(3)).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    // A should still be cached
    cache.get_or_load_latest("a", &mut make_loader(10)).unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "A should still be cached (high freq)"
    );

    // B should have been evicted
    cache.get_or_load_latest("b", &mut make_loader(20)).unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "B should have been evicted (low freq)"
    );
}

// ---------------------------------------------------------------------------
// Simple policy does NOT evict
// ---------------------------------------------------------------------------

#[test]
fn simple_policy_does_not_evict() {
    let cache = SimpleKeyCache::new_with_policy(3600, 2, CachePolicy::Simple, 0);
    let calls = AtomicUsize::new(0);

    let make_loader = |created: i64| {
        let calls_ref = &calls;
        move || -> anyhow::Result<Arc<CryptoKey>> {
            calls_ref.fetch_add(1, Ordering::SeqCst);
            Ok(make_key(created, false))
        }
    };

    // Insert A, B, C -- Simple policy skips eviction even beyond max
    cache.get_or_load_latest("a", &mut make_loader(1)).unwrap();
    cache.get_or_load_latest("b", &mut make_loader(2)).unwrap();
    cache.get_or_load_latest("c", &mut make_loader(3)).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    // All three should still be cached (no eviction)
    cache.get_or_load_latest("a", &mut make_loader(10)).unwrap();
    cache.get_or_load_latest("b", &mut make_loader(20)).unwrap();
    cache.get_or_load_latest("c", &mut make_loader(30)).unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "Simple policy should not evict any items"
    );
}

// ---------------------------------------------------------------------------
// Revoked key triggers reload
// ---------------------------------------------------------------------------

#[test]
fn revoked_key_triggers_reload_on_get_or_load_latest() {
    let cache = SimpleKeyCache::new();
    let calls = AtomicUsize::new(0);

    // First load returns a revoked key
    let mut loader_revoked = || -> anyhow::Result<Arc<CryptoKey>> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key(100, true))
    };
    cache
        .get_or_load_latest("id1", &mut loader_revoked)
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Second call with a loader that returns a non-revoked key should call loader
    // because the cached key is revoked (invalid)
    let mut loader_fresh = || -> anyhow::Result<Arc<CryptoKey>> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key(200, false))
    };
    let result = cache.get_or_load_latest("id1", &mut loader_fresh).unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "revoked key should trigger reload"
    );
    assert_eq!(result.created(), 200);
}

// ---------------------------------------------------------------------------
// Expired key by expire_after_s
// ---------------------------------------------------------------------------

#[test]
fn expired_key_by_expire_after_s_triggers_reload() {
    // expire_after_s = 1 second, key created at epoch 0 should be expired by now
    let cache = SimpleKeyCache::new_with_policy(3600, 0, CachePolicy::Simple, 1);
    let calls = AtomicUsize::new(0);

    // Load a key with created=0 (very old -- will be expired per expire_after_s=1)
    let mut loader_old = || -> anyhow::Result<Arc<CryptoKey>> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key(0, false))
    };
    cache.get_or_load_latest("id1", &mut loader_old).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Second call should reload because the key's created timestamp makes it expired
    let mut loader_new = || -> anyhow::Result<Arc<CryptoKey>> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(make_key(i64::MAX / 2, false))
    };
    let result = cache.get_or_load_latest("id1", &mut loader_new).unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "key with old created timestamp should trigger reload when expire_after_s is set"
    );
    assert_eq!(result.created(), i64::MAX / 2);
}

// ---------------------------------------------------------------------------
// close() is a no-op (doesn't panic)
// ---------------------------------------------------------------------------

#[test]
fn close_does_not_panic() {
    let cache = SimpleKeyCache::new();
    let mut loader = || -> anyhow::Result<Arc<CryptoKey>> { Ok(make_key(1, false)) };
    cache.get_or_load_latest("x", &mut loader).unwrap();
    cache.close().unwrap();

    let never = NeverCache;
    never.close().unwrap();
}
