#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use asherah as ael;

#[test]
fn ik_cache_ttl_expires_and_reloads() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![6_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let mut cfg = ael::Config::new("svc", "prod");
    cfg.policy.shared_intermediate_key_cache = false;
    cfg.policy.cache_intermediate_keys = true;
    cfg.policy.revoke_check_interval_s = 1; // TTL
    let factory = ael::api::new_session_factory(cfg, store, kms, crypto);
    let sess = factory.get_session("p1");

    // First encrypt loads and caches IK
    let d1 = sess.encrypt(b"hello").unwrap();
    let ik1 = d1.key.unwrap().parent_key_meta.unwrap().created;

    // Immediately encrypt again - should hit cache (IK unchanged)
    let d2 = sess.encrypt(b"world").unwrap();
    let ik2 = d2.key.unwrap().parent_key_meta.unwrap().created;
    assert_eq!(ik1, ik2);

    // After TTL, encrypt again - IK may rotate due to expiration policy defaults; at least force reload
    sleep(Duration::from_millis(1100));
    let d3 = sess.encrypt(b"again").unwrap();
    let ik3 = d3.key.unwrap().parent_key_meta.unwrap().created;
    // The previous `assert!(ik3 >= ik2)` was a no-op: `created` is a
    // monotonic-clock-derived second count, so the comparison is true
    // by construction. Replace with the actual invariant — after a TTL
    // expiry the IK metadata's parent_key_meta should still parse to a
    // sane epoch (positive within the last hour) and the encrypt
    // succeeded, returning bytes that didn't blow up the call. The
    // rotation-rather-than-reuse path is exercised by
    // `tests/revocation.rs`. T-finding "assert!(ik3 >= ik2) is a no-op"
    // in `docs/review-2026-05-05-findings.md`.
    assert!(
        ik3 > 0,
        "IK metadata.created should be a non-zero epoch; got {ik3}"
    );
    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    assert!(
        ik3 <= now_s,
        "IK metadata.created should not be in the future; got {ik3} > now {now_s}"
    );
    assert!(
        now_s - ik3 < 3600,
        "IK metadata.created should be within the last hour for a fresh test; got delta {}",
        now_s - ik3
    );
}
