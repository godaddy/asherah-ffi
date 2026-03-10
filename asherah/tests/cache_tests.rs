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
