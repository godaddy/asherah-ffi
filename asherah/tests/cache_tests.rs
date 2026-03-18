#![allow(clippy::unwrap_used, clippy::expect_used, let_underscore_drop)]
//! Tests for key cache (SimpleKeyCache, NeverCache) and CachePolicy.

use std::sync::Arc;

use asherah::cache::{CachePolicy, KeyCacher, NeverCache, SimpleKeyCache};
use asherah::internal::CryptoKey;
use asherah::types::KeyMeta;

fn make_key(created: i64) -> Arc<CryptoKey> {
    Arc::new(CryptoKey::new(created, false, vec![0xAA; 32]).unwrap())
}

fn make_revoked_key(created: i64) -> Arc<CryptoKey> {
    Arc::new(CryptoKey::new(created, true, vec![0xBB; 32]).unwrap())
}

// ──────────────────────────── CachePolicy::parse ────────────────────────────

#[test]
fn cache_policy_parse_all_variants() {
    assert_eq!(
        CachePolicy::parse("simple", CachePolicy::Lru),
        CachePolicy::Simple
    );
    assert_eq!(
        CachePolicy::parse("lru", CachePolicy::Simple),
        CachePolicy::Lru
    );
    assert_eq!(
        CachePolicy::parse("lfu", CachePolicy::Simple),
        CachePolicy::Lfu
    );
    assert_eq!(
        CachePolicy::parse("slru", CachePolicy::Simple),
        CachePolicy::Slru
    );
    assert_eq!(
        CachePolicy::parse("tinylfu", CachePolicy::Simple),
        CachePolicy::TinyLfu
    );
}

#[test]
fn cache_policy_parse_case_insensitive() {
    assert_eq!(
        CachePolicy::parse("SIMPLE", CachePolicy::Lru),
        CachePolicy::Simple
    );
    assert_eq!(
        CachePolicy::parse("LRU", CachePolicy::Simple),
        CachePolicy::Lru
    );
    assert_eq!(
        CachePolicy::parse("TinyLFU", CachePolicy::Simple),
        CachePolicy::TinyLfu
    );
}

#[test]
fn cache_policy_parse_unknown_returns_default() {
    assert_eq!(
        CachePolicy::parse("unknown", CachePolicy::Lru),
        CachePolicy::Lru
    );
    assert_eq!(CachePolicy::parse("", CachePolicy::Slru), CachePolicy::Slru);
}

// ──────────────────────────── NeverCache ────────────────────────────

#[test]
fn never_cache_always_calls_loader() {
    let cache = NeverCache;
    let mut count = 0;
    let _ = cache
        .get_or_load_latest("id", &mut || {
            count += 1;
            Ok(make_key(100))
        })
        .unwrap();
    let _ = cache
        .get_or_load_latest("id", &mut || {
            count += 1;
            Ok(make_key(100))
        })
        .unwrap();
    assert_eq!(count, 2, "NeverCache should call loader every time");
}

#[test]
fn never_cache_get_or_load() {
    let cache = NeverCache;
    let meta = KeyMeta {
        id: "k".into(),
        created: 1,
    };
    let mut count = 0;
    let _ = cache
        .get_or_load(&meta, &mut || {
            count += 1;
            Ok(make_key(1))
        })
        .unwrap();
    let _ = cache
        .get_or_load(&meta, &mut || {
            count += 1;
            Ok(make_key(1))
        })
        .unwrap();
    assert_eq!(count, 2);
}

#[test]
fn never_cache_close() {
    let cache = NeverCache;
    cache.close().unwrap();
}

// ──────────────────────────── SimpleKeyCache - basic caching ────────────────────────────

#[test]
fn simple_cache_caches_on_second_call() {
    let cache = SimpleKeyCache::new();
    let mut count = 0;
    let k1 = cache
        .get_or_load_latest("id", &mut || {
            count += 1;
            Ok(make_key(100))
        })
        .unwrap();
    let k2 = cache
        .get_or_load_latest("id", &mut || {
            count += 1;
            Ok(make_key(200)) // different created, but should never be called
        })
        .unwrap();
    assert_eq!(count, 1, "second call should hit cache");
    assert_eq!(k1.created(), k2.created());
}

#[test]
fn simple_cache_meta_caching() {
    let cache = SimpleKeyCache::new();
    let meta = KeyMeta {
        id: "k".into(),
        created: 42,
    };
    let mut count = 0;
    let _ = cache
        .get_or_load(&meta, &mut || {
            count += 1;
            Ok(make_key(42))
        })
        .unwrap();
    let _ = cache
        .get_or_load(&meta, &mut || {
            count += 1;
            Ok(make_key(42))
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn simple_cache_different_ids_are_separate() {
    let cache = SimpleKeyCache::new();
    let _ = cache
        .get_or_load_latest("id1", &mut || Ok(make_key(1)))
        .unwrap();
    let _ = cache
        .get_or_load_latest("id2", &mut || Ok(make_key(2)))
        .unwrap();
    let k1 = cache
        .get_or_load_latest("id1", &mut || Ok(make_key(999)))
        .unwrap();
    let k2 = cache
        .get_or_load_latest("id2", &mut || Ok(make_key(999)))
        .unwrap();
    assert_eq!(k1.created(), 1);
    assert_eq!(k2.created(), 2);
}

// ──────────────────────────── TTL=0 bypass ────────────────────────────

#[test]
fn cache_ttl_zero_always_reloads() {
    let cache = SimpleKeyCache::new_with_ttl(0);
    let mut count = 0;
    let _ = cache
        .get_or_load_latest("id", &mut || {
            count += 1;
            Ok(make_key(count as i64))
        })
        .unwrap();
    let _ = cache
        .get_or_load_latest("id", &mut || {
            count += 1;
            Ok(make_key(count as i64))
        })
        .unwrap();
    assert_eq!(count, 2, "TTL=0 should always expire");
}

// ──────────────────────────── LRU eviction ────────────────────────────

#[test]
fn lru_eviction_with_max_1() {
    let cache = SimpleKeyCache::new_with_policy(3600, 1, CachePolicy::Lru, 0);
    // Insert first key
    let _ = cache
        .get_or_load_latest("a", &mut || Ok(make_key(1)))
        .unwrap();
    // Insert second key — should evict first
    let _ = cache
        .get_or_load_latest("b", &mut || Ok(make_key(2)))
        .unwrap();
    // First key should be evicted
    let mut count = 0;
    let k = cache
        .get_or_load_latest("a", &mut || {
            count += 1;
            Ok(make_key(3))
        })
        .unwrap();
    assert_eq!(count, 1, "evicted key should require reload");
    assert_eq!(k.created(), 3);
}

// ──────────────────────────── LFU eviction ────────────────────────────

#[test]
fn lfu_eviction_evicts_least_frequent() {
    let cache = SimpleKeyCache::new_with_policy(3600, 2, CachePolicy::Lfu, 0);
    // Insert "a" and access it twice
    let _ = cache
        .get_or_load_latest("a", &mut || Ok(make_key(1)))
        .unwrap();
    let _ = cache
        .get_or_load_latest("a", &mut || Ok(make_key(1)))
        .unwrap();
    // Insert "b" accessed only once
    let _ = cache
        .get_or_load_latest("b", &mut || Ok(make_key(2)))
        .unwrap();
    // Insert "c" — should evict "b" (least frequent)
    let _ = cache
        .get_or_load_latest("c", &mut || Ok(make_key(3)))
        .unwrap();
    // "a" should still be cached
    let mut a_reloaded = false;
    let _ = cache
        .get_or_load_latest("a", &mut || {
            a_reloaded = true;
            Ok(make_key(99))
        })
        .unwrap();
    assert!(!a_reloaded, "frequently accessed key should not be evicted");
}

// ──────────────────────────── SLRU eviction ────────────────────────────

#[test]
fn slru_promotes_on_second_access() {
    let cache = SimpleKeyCache::new_with_policy(3600, 3, CachePolicy::Slru, 0);
    // Insert three keys
    let _ = cache
        .get_or_load_latest("a", &mut || Ok(make_key(1)))
        .unwrap();
    let _ = cache
        .get_or_load_latest("b", &mut || Ok(make_key(2)))
        .unwrap();
    let _ = cache
        .get_or_load_latest("c", &mut || Ok(make_key(3)))
        .unwrap();
    // Access "a" again to promote to protected
    let _ = cache
        .get_or_load_latest("a", &mut || Ok(make_key(99)))
        .unwrap();
    // Insert "d" — should evict from probationary (not "a")
    let _ = cache
        .get_or_load_latest("d", &mut || Ok(make_key(4)))
        .unwrap();
    // "a" should still be cached
    let mut a_reloaded = false;
    let _ = cache
        .get_or_load_latest("a", &mut || {
            a_reloaded = true;
            Ok(make_key(99))
        })
        .unwrap();
    assert!(!a_reloaded, "protected key should not be evicted");
}

// ──────────────────────────── TinyLFU decay ────────────────────────────

#[test]
fn tinylfu_basic_eviction() {
    let cache = SimpleKeyCache::new_with_policy(3600, 2, CachePolicy::TinyLfu, 0);
    let _ = cache
        .get_or_load_latest("a", &mut || Ok(make_key(1)))
        .unwrap();
    let _ = cache
        .get_or_load_latest("b", &mut || Ok(make_key(2)))
        .unwrap();
    // Evict one
    let _ = cache
        .get_or_load_latest("c", &mut || Ok(make_key(3)))
        .unwrap();
    // At least "c" and one of "a"/"b" should be present
    let mut c_reloaded = false;
    let _ = cache
        .get_or_load_latest("c", &mut || {
            c_reloaded = true;
            Ok(make_key(99))
        })
        .unwrap();
    assert!(!c_reloaded, "most recent insert should be cached");
}

// ──────────────────────────── Simple policy never evicts ────────────────────────────

#[test]
fn simple_policy_never_evicts() {
    let cache = SimpleKeyCache::new_with_policy(3600, 1, CachePolicy::Simple, 0);
    // Insert multiple keys — Simple policy doesn't evict
    let _ = cache
        .get_or_load_latest("a", &mut || Ok(make_key(1)))
        .unwrap();
    let _ = cache
        .get_or_load_latest("b", &mut || Ok(make_key(2)))
        .unwrap();
    let _ = cache
        .get_or_load_latest("c", &mut || Ok(make_key(3)))
        .unwrap();
    // All should still be cached
    let mut reloads = 0;
    let _ = cache
        .get_or_load_latest("a", &mut || {
            reloads += 1;
            Ok(make_key(99))
        })
        .unwrap();
    let _ = cache
        .get_or_load_latest("b", &mut || {
            reloads += 1;
            Ok(make_key(99))
        })
        .unwrap();
    let _ = cache
        .get_or_load_latest("c", &mut || {
            reloads += 1;
            Ok(make_key(99))
        })
        .unwrap();
    assert_eq!(reloads, 0, "simple policy should not evict");
}

// ──────────────────────────── Revoked key handling ────────────────────────────

#[test]
fn cache_invalidates_revoked_keys_for_latest() {
    let cache = SimpleKeyCache::new_with_policy(3600, 0, CachePolicy::Simple, 3600);
    // Insert a revoked key
    let _ = cache
        .get_or_load_latest("id", &mut || Ok(make_revoked_key(100)))
        .unwrap();
    // Should reload because key is revoked (invalid)
    let mut reloaded = false;
    let k = cache
        .get_or_load_latest("id", &mut || {
            reloaded = true;
            Ok(make_key(200))
        })
        .unwrap();
    assert!(reloaded, "revoked key should trigger reload for latest");
    assert_eq!(k.created(), 200);
}

// ──────────────────────────── Loader error propagation ────────────────────────────

#[test]
fn cache_propagates_loader_error() {
    let cache = SimpleKeyCache::new();
    let result = cache.get_or_load_latest("id", &mut || Err(anyhow::anyhow!("loader failed")));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("loader failed"));
}

// ──────────────────────────── Default constructor ────────────────────────────

#[test]
fn simple_cache_default() {
    let cache = SimpleKeyCache::default();
    let _ = cache
        .get_or_load_latest("id", &mut || Ok(make_key(1)))
        .unwrap();
    let mut reloaded = false;
    let _ = cache
        .get_or_load_latest("id", &mut || {
            reloaded = true;
            Ok(make_key(2))
        })
        .unwrap();
    assert!(!reloaded);
}

// ──────────────────────────── SLRU rebalance edge cases ────────────────────────────

#[test]
fn slru_max_size_1() {
    // max=1, protected_cap = max(1, 1/2) = max(1, 0) = 1
    let cache = SimpleKeyCache::new_with_policy(3600, 1, CachePolicy::Slru, 0);
    let _ = cache
        .get_or_load_latest("a", &mut || Ok(make_key(1)))
        .unwrap();
    // Access again to promote to protected
    let _ = cache
        .get_or_load_latest("a", &mut || Ok(make_key(99)))
        .unwrap();
    // Insert "b" — "b" enters as probationary and is immediately evicted
    // because SLRU evicts from probationary first, and "a" is protected
    let _ = cache
        .get_or_load_latest("b", &mut || Ok(make_key(2)))
        .unwrap();
    // "a" should still be cached (protected segment survives eviction)
    let mut a_reloaded = false;
    let _ = cache
        .get_or_load_latest("a", &mut || {
            a_reloaded = true;
            Ok(make_key(3))
        })
        .unwrap();
    assert!(
        !a_reloaded,
        "protected key in SLRU max=1 should survive eviction"
    );
    // "b" should have been evicted (it was probationary)
    let mut b_reloaded = false;
    let _ = cache
        .get_or_load_latest("b", &mut || {
            b_reloaded = true;
            Ok(make_key(4))
        })
        .unwrap();
    assert!(
        b_reloaded,
        "probationary key should be evicted in SLRU max=1"
    );
}

#[test]
fn slru_max_size_2() {
    // max=2, protected_cap = max(1, 2/2) = 1
    let cache = SimpleKeyCache::new_with_policy(3600, 2, CachePolicy::Slru, 0);
    let _ = cache
        .get_or_load_latest("a", &mut || Ok(make_key(1)))
        .unwrap();
    let _ = cache
        .get_or_load_latest("b", &mut || Ok(make_key(2)))
        .unwrap();
    // Access both to promote to protected
    let _ = cache
        .get_or_load_latest("a", &mut || Ok(make_key(99)))
        .unwrap();
    let _ = cache
        .get_or_load_latest("b", &mut || Ok(make_key(99)))
        .unwrap();
    // Now both are protected, but protected_cap=1, so rebalance should demote one
    // Insert "c" — triggers eviction
    let _ = cache
        .get_or_load_latest("c", &mut || Ok(make_key(3)))
        .unwrap();
    // At least "c" should be present, and the most recently accessed of a/b
    let mut c_reloaded = false;
    let _ = cache
        .get_or_load_latest("c", &mut || {
            c_reloaded = true;
            Ok(make_key(99))
        })
        .unwrap();
    assert!(!c_reloaded, "latest insert should be cached");
}

// ──────────────────────────── Revoked-but-not-expired via get_or_load ────────────────────────────

#[test]
fn cache_meta_revoked_but_not_expired_returns_cached() {
    // The get_meta_if_fresh function forces expired=false for revoked keys,
    // meaning get_or_load returns the cached revoked key without reloading.
    let cache = SimpleKeyCache::new_with_policy(3600, 0, CachePolicy::Simple, 3600);
    let meta = KeyMeta {
        id: "k".into(),
        created: 1,
    };

    // Load a revoked key into cache
    let _ = cache
        .get_or_load(&meta, &mut || Ok(make_revoked_key(1)))
        .unwrap();

    // Second load should return cached (revoked) key without calling loader
    let mut reloaded = false;
    let k = cache
        .get_or_load(&meta, &mut || {
            reloaded = true;
            Ok(make_key(1))
        })
        .unwrap();
    assert!(
        !reloaded,
        "revoked key via get_or_load should be returned from cache (not reloaded)"
    );
    assert!(k.revoked(), "returned key should still be revoked");
}

#[test]
fn cache_latest_revoked_key_triggers_reload() {
    // Contrasts with get_meta_if_fresh: get_latest_if_fresh returns invalid=true for revoked
    let cache = SimpleKeyCache::new_with_policy(3600, 0, CachePolicy::Simple, 3600);
    let _ = cache
        .get_or_load_latest("k", &mut || Ok(make_revoked_key(100)))
        .unwrap();
    let mut reloaded = false;
    let k = cache
        .get_or_load_latest("k", &mut || {
            reloaded = true;
            Ok(make_key(200))
        })
        .unwrap();
    assert!(reloaded, "revoked key should trigger reload for latest");
    assert!(!k.revoked());
    assert_eq!(k.created(), 200);
}

// ──────────────────────────── Stale-while-revalidate ────────────────────────────

#[test]
fn stale_while_revalidate_returns_stale_key_for_non_reloader() {
    // TTL=0 means every entry is immediately stale, but TTL=0 also means
    // try_claim_reload's CAS always succeeds (the entry is always stale).
    // Use a 1-second TTL instead and manually expire.
    let cache = SimpleKeyCache::new_with_ttl(1);

    // Seed the cache
    let _ = cache
        .get_or_load_latest("id", &mut || Ok(make_key(100)))
        .unwrap();

    // Wait for TTL to expire
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // First call after expiry: reloader claims the reload and calls loader
    let mut count = 0;
    let k = cache
        .get_or_load_latest("id", &mut || {
            count += 1;
            Ok(make_key(200))
        })
        .unwrap();
    assert_eq!(count, 1, "reloader should call loader once");
    // Reloader returns the loaded key
    assert_eq!(k.created(), 200);

    // Second call: entry is now fresh (reloader inserted new key), so no reload
    let mut count2 = 0;
    let k2 = cache
        .get_or_load_latest("id", &mut || {
            count2 += 1;
            Ok(make_key(300))
        })
        .unwrap();
    assert_eq!(count2, 0, "second call should hit cache (entry is fresh)");
    assert_eq!(k2.created(), 200, "should return the reloaded key");
}

#[test]
fn stale_while_revalidate_meta_returns_stale_key_without_loading() {
    let cache = SimpleKeyCache::new_with_ttl(1);
    let meta = KeyMeta {
        id: "k".into(),
        created: 42,
    };

    // Seed
    let _ = cache.get_or_load(&meta, &mut || Ok(make_key(42))).unwrap();

    // Wait for TTL
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // First call after expiry: returns stale key, no loader call (decrypt path
    // skips the metastore entirely — key material is unchanged).
    let mut count = 0;
    let k = cache
        .get_or_load(&meta, &mut || {
            count += 1;
            Ok(make_key(42))
        })
        .unwrap();
    assert_eq!(count, 0, "decrypt path should not call loader on stale hit");
    assert_eq!(k.created(), 42);

    // Second call: loaded_at was bumped by CAS, entry is fresh
    let mut count2 = 0;
    let _ = cache
        .get_or_load(&meta, &mut || {
            count2 += 1;
            Ok(make_key(42))
        })
        .unwrap();
    assert_eq!(count2, 0, "second call should hit cache");
}

#[test]
fn stale_while_revalidate_concurrent_only_one_reloader() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    let cache = Arc::new(SimpleKeyCache::new_with_ttl(1));

    // Seed
    cache
        .get_or_load_latest("id", &mut || Ok(make_key(100)))
        .unwrap();

    // Wait for expiry
    std::thread::sleep(std::time::Duration::from_millis(1100));

    let load_count = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(std::sync::Barrier::new(10));

    let mut handles = vec![];
    for _ in 0..10 {
        let c = cache.clone();
        let lc = load_count.clone();
        let b = barrier.clone();
        handles.push(std::thread::spawn(move || {
            b.wait(); // All threads start at the same time
            let _ = c
                .get_or_load_latest("id", &mut || {
                    lc.fetch_add(1, Ordering::SeqCst);
                    // Simulate slow metastore query
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    Ok(make_key(200))
                })
                .unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let total_loads = load_count.load(Ordering::SeqCst);
    assert!(
        total_loads <= 2,
        "expected at most 2 loader calls (1 reloader + possible CAS race), got {total_loads}"
    );
}
