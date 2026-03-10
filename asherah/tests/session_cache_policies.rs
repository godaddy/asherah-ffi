#![allow(clippy::unwrap_used, let_underscore_drop)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use asherah::aead::AES256GCM;
use asherah::cache::CachePolicy;
use asherah::kms::StaticKMS;
use asherah::metastore::InMemoryMetastore;
use asherah::session::PublicFactory;
use asherah::session_cache::SessionCache;
use asherah::Config;

type TestCache = SessionCache<AES256GCM, StaticKMS<AES256GCM>, InMemoryMetastore>;

fn make_factory() -> PublicFactory<AES256GCM, StaticKMS<AES256GCM>, InMemoryMetastore> {
    let crypto = Arc::new(AES256GCM::new());
    let kms = Arc::new(StaticKMS::new(crypto.clone(), vec![6_u8; 32]).unwrap());
    let store = Arc::new(InMemoryMetastore::new());
    let cfg = Config::new("svc", "prod");
    PublicFactory::new(cfg, store, kms, crypto)
}

fn make_cache(max: usize, ttl_s: i64, policy: CachePolicy) -> TestCache {
    SessionCache::new(max, ttl_s, policy)
}

#[test]
fn basic_caching_returns_same_session() {
    let factory = make_factory();
    let cache = make_cache(10, 60, CachePolicy::Lru);
    let create_count = AtomicUsize::new(0);

    let s1 = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });
    let s2 = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });

    assert_eq!(create_count.load(Ordering::SeqCst), 1);
    assert!(Arc::ptr_eq(&s1, &s2));
}

#[test]
fn different_ids_get_different_sessions() {
    let factory = make_factory();
    let cache = make_cache(10, 60, CachePolicy::Lru);
    let create_count = AtomicUsize::new(0);

    let s1 = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });
    let s2 = cache.get_or_create("p2", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p2")
    });

    assert_eq!(create_count.load(Ordering::SeqCst), 2);
    assert!(!Arc::ptr_eq(&s1, &s2));
}

#[test]
fn ttl_expiry_creates_new_session() {
    let factory = make_factory();
    let cache = make_cache(10, 1, CachePolicy::Lru);
    let create_count = AtomicUsize::new(0);

    let s1 = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });
    assert_eq!(create_count.load(Ordering::SeqCst), 1);

    sleep(Duration::from_millis(1100));

    let s2 = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });
    assert_eq!(create_count.load(Ordering::SeqCst), 2);
    assert!(!Arc::ptr_eq(&s1, &s2));
}

#[test]
fn ttl_zero_always_creates() {
    let factory = make_factory();
    let cache = make_cache(10, 0, CachePolicy::Lru);
    let create_count = AtomicUsize::new(0);

    let s1 = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });
    let s2 = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });
    let s3 = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });

    assert_eq!(create_count.load(Ordering::SeqCst), 3);
    assert!(!Arc::ptr_eq(&s1, &s2));
    assert!(!Arc::ptr_eq(&s2, &s3));
}

#[test]
fn lru_eviction() {
    let factory = make_factory();
    let cache = make_cache(2, 60, CachePolicy::Lru);

    let s1 = cache.get_or_create("p1", || factory.get_session("p1"));
    let _s2 = cache.get_or_create("p2", || factory.get_session("p2"));

    // Access p1 again to make p2 the least recently used
    let _ = cache.get_or_create("p1", || factory.get_session("p1"));

    // Insert p3, should evict p2 (least recently used)
    let _s3 = cache.get_or_create("p3", || factory.get_session("p3"));

    // p1 should still be cached
    let create_count = AtomicUsize::new(0);
    let s1_again = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });
    assert_eq!(create_count.load(Ordering::SeqCst), 0);
    assert!(Arc::ptr_eq(&s1, &s1_again));

    // p2 should have been evicted
    let s2_again = cache.get_or_create("p2", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p2")
    });
    assert_eq!(create_count.load(Ordering::SeqCst), 1);
    // s2_again is a new session, not the old one
    drop(s2_again);
}

#[test]
fn lfu_eviction() {
    let factory = make_factory();
    let cache = make_cache(2, 60, CachePolicy::Lfu);

    let s1 = cache.get_or_create("p1", || factory.get_session("p1"));
    let _s2 = cache.get_or_create("p2", || factory.get_session("p2"));

    // Access p1 multiple times to increase its frequency
    let _ = cache.get_or_create("p1", || factory.get_session("p1"));
    let _ = cache.get_or_create("p1", || factory.get_session("p1"));

    // Insert p3, should evict p2 (least frequently used)
    let _s3 = cache.get_or_create("p3", || factory.get_session("p3"));

    // p1 should still be cached (higher frequency)
    let create_count = AtomicUsize::new(0);
    let s1_again = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });
    assert_eq!(create_count.load(Ordering::SeqCst), 0);
    assert!(Arc::ptr_eq(&s1, &s1_again));

    // p2 should have been evicted
    let s2_again = cache.get_or_create("p2", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p2")
    });
    assert_eq!(create_count.load(Ordering::SeqCst), 1);
    drop(s2_again);
}

#[test]
fn slru_eviction_prefers_probationary() {
    let factory = make_factory();
    let cache = make_cache(2, 60, CachePolicy::Slru);

    let s1 = cache.get_or_create("p1", || factory.get_session("p1"));

    // Access p1 again to promote it to protected segment
    let _ = cache.get_or_create("p1", || factory.get_session("p1"));

    let _s2 = cache.get_or_create("p2", || factory.get_session("p2"));

    // Insert p3, should evict p2 (probationary) rather than p1 (protected)
    let _s3 = cache.get_or_create("p3", || factory.get_session("p3"));

    // p1 should still be cached (protected)
    let create_count = AtomicUsize::new(0);
    let s1_again = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });
    assert_eq!(create_count.load(Ordering::SeqCst), 0);
    assert!(Arc::ptr_eq(&s1, &s1_again));

    // p2 should have been evicted
    let s2_again = cache.get_or_create("p2", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p2")
    });
    assert_eq!(create_count.load(Ordering::SeqCst), 1);
    drop(s2_again);
}

#[test]
fn tinylfu_eviction() {
    let factory = make_factory();
    let cache = make_cache(2, 60, CachePolicy::TinyLfu);

    let s1 = cache.get_or_create("p1", || factory.get_session("p1"));
    let _s2 = cache.get_or_create("p2", || factory.get_session("p2"));

    // Access p1 to increase its frequency
    let _ = cache.get_or_create("p1", || factory.get_session("p1"));

    // Insert p3, should evict the least frequent (p2)
    let _s3 = cache.get_or_create("p3", || factory.get_session("p3"));

    // p1 should still be cached
    let create_count = AtomicUsize::new(0);
    let s1_again = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });
    assert_eq!(create_count.load(Ordering::SeqCst), 0);
    assert!(Arc::ptr_eq(&s1, &s1_again));

    // p2 should have been evicted
    let s2_again = cache.get_or_create("p2", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p2")
    });
    assert_eq!(create_count.load(Ordering::SeqCst), 1);
    drop(s2_again);
}

#[test]
fn simple_policy_never_evicts() {
    let factory = make_factory();
    let cache = make_cache(2, 60, CachePolicy::Simple);

    let s1 = cache.get_or_create("p1", || factory.get_session("p1"));
    let s2 = cache.get_or_create("p2", || factory.get_session("p2"));
    let _s3 = cache.get_or_create("p3", || factory.get_session("p3"));

    // All three should still be cached because Simple never evicts
    let create_count = AtomicUsize::new(0);
    let s1_again = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });
    let s2_again = cache.get_or_create("p2", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p2")
    });

    assert_eq!(create_count.load(Ordering::SeqCst), 0);
    assert!(Arc::ptr_eq(&s1, &s1_again));
    assert!(Arc::ptr_eq(&s2, &s2_again));
}

#[test]
fn close_clears_cache() {
    let factory = make_factory();
    let cache = make_cache(10, 60, CachePolicy::Lru);

    let s1 = cache.get_or_create("p1", || factory.get_session("p1"));

    cache.close();

    let create_count = AtomicUsize::new(0);
    let s2 = cache.get_or_create("p1", || {
        create_count.fetch_add(1, Ordering::SeqCst);
        factory.get_session("p1")
    });

    assert_eq!(create_count.load(Ordering::SeqCst), 1);
    assert!(!Arc::ptr_eq(&s1, &s2));
}
