#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::thread;

use asherah as ael;

fn make_factory(
    ik_policy: &str,
    ik_max: usize,
    sk_policy: &str,
    sk_max: usize,
    session_cache: bool,
    session_max: usize,
) -> Arc<
    ael::SessionFactory<
        ael::aead::AES256GCM,
        ael::kms::StaticKMS<ael::aead::AES256GCM>,
        ael::metastore::InMemoryMetastore,
    >,
> {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![1_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let mut cfg = ael::Config::new("conc-svc", "conc-prod");
    cfg.policy.cache_intermediate_keys = true;
    cfg.policy.intermediate_key_cache_max_size = ik_max;
    cfg.policy.intermediate_key_cache_eviction_policy = ik_policy.into();
    cfg.policy.cache_system_keys = true;
    cfg.policy.system_key_cache_max_size = sk_max;
    cfg.policy.system_key_cache_eviction_policy = sk_policy.into();
    cfg.policy.cache_sessions = session_cache;
    cfg.policy.session_cache_max_size = session_max;
    cfg.policy.session_cache_ttl_s = 3600;
    Arc::new(ael::api::new_session_factory(cfg, store, kms, crypto))
}

#[test]
fn concurrent_ik_cache_eviction_lru() {
    let factory = make_factory("lru", 2, "lru", 2, false, 0);
    let mut handles = vec![];
    for i in 0..50 {
        let f = factory.clone();
        handles.push(thread::spawn(move || {
            let partition = format!("part-lru-{i}");
            let s = f.get_session(&partition);
            let msg = format!("lru-msg-{i}");
            let drr = s.encrypt(msg.as_bytes()).unwrap();
            let pt = s.decrypt(drr).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn concurrent_session_cache_eviction_slru() {
    let factory = make_factory("lru", 2, "lru", 2, true, 3);
    let mut handles = vec![];
    for i in 0..50 {
        let f = factory.clone();
        handles.push(thread::spawn(move || {
            let partition = format!("part-slru-{i}");
            let s = f.get_session(&partition);
            let msg = format!("slru-msg-{i}");
            let drr = s.encrypt(msg.as_bytes()).unwrap();
            let pt = s.decrypt(drr).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn concurrent_ik_cache_eviction_lfu() {
    let factory = make_factory("lfu", 2, "lfu", 2, false, 0);
    let mut handles = vec![];
    for i in 0..50 {
        let f = factory.clone();
        handles.push(thread::spawn(move || {
            let partition = format!("part-lfu-{i}");
            let s = f.get_session(&partition);
            let msg = format!("lfu-msg-{i}");
            let drr = s.encrypt(msg.as_bytes()).unwrap();
            let pt = s.decrypt(drr).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn concurrent_ik_cache_eviction_tinylfu() {
    let factory = make_factory("tinylfu", 2, "tinylfu", 2, false, 0);
    let mut handles = vec![];
    for i in 0..50 {
        let f = factory.clone();
        handles.push(thread::spawn(move || {
            let partition = format!("part-tlfu-{i}");
            let s = f.get_session(&partition);
            let msg = format!("tinylfu-msg-{i}");
            let drr = s.encrypt(msg.as_bytes()).unwrap();
            let pt = s.decrypt(drr).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn concurrent_mixed_encrypt_decrypt_with_small_cache() {
    let factory = make_factory("lru", 2, "lru", 2, false, 0);

    // Phase 1: encrypt 50 messages from different partitions, collect DRRs
    let mut pre_drrs = Vec::new();
    for i in 0..50 {
        let partition = format!("part-mixed-{i}");
        let s = factory.get_session(&partition);
        let msg = format!("pre-msg-{i}");
        let drr = s.encrypt(msg.as_bytes()).unwrap();
        pre_drrs.push((partition, msg, drr));
    }

    // Phase 2: spawn 50 threads. Even threads encrypt new data, odd threads decrypt pre-existing data.
    let shared_drrs: Arc<Vec<_>> = Arc::new(pre_drrs);
    let mut handles = vec![];
    for i in 0..50 {
        let f = factory.clone();
        let drrs = shared_drrs.clone();
        handles.push(thread::spawn(move || {
            if i % 2 == 0 {
                // Encrypt new data
                let partition = format!("part-mixed-new-{i}");
                let s = f.get_session(&partition);
                let msg = format!("new-msg-{i}");
                let drr = s.encrypt(msg.as_bytes()).unwrap();
                let pt = s.decrypt(drr).unwrap();
                assert_eq!(pt, msg.as_bytes());
            } else {
                // Decrypt pre-existing data
                let (ref partition, ref msg, ref drr) = drrs[i];
                let s = f.get_session(partition);
                let pt = s.decrypt(drr.clone()).unwrap();
                assert_eq!(pt, msg.as_bytes());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
