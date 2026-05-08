//! System-key revocation tests.
//!
//! `tests/revocation.rs` covers IK revocation. `tests/error_injection.rs`
//! has a single SK-rotation test that combines revocation + 1-second
//! policy expiry. These tests cover SK revocation as an independent
//! axis and lock down a non-obvious design property: **SK revocation
//! by itself does not rotate the SK; it only takes effect at the
//! next IK rotation**, because `PublicSession::encrypt` only consults
//! the latest SK when it creates a new IK.
//!
//! Scenarios:
//!  - SK revocation while the IK is still valid: no rotation, by
//!    design (locked down so a regression that adds SK polling on
//!    every encrypt is caught).
//!  - SK revocation + IK rotation: SK rotates, pre-rotation DRRs
//!    still decrypt.
//!  - Cross-factory: revocation visible via metastore alone.
//!  - Cascading SK revocations across multiple cycles.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use asherah as ael;

/// Build a factory whose IKs and SKs both age out after `expire_s`.
/// `revoke_check_interval_s = 1` so cache TTLs don't dominate.
fn make_factory_with_expire(
    store: Arc<ael::metastore::InMemoryMetastore>,
    expire_s: i64,
) -> ael::SessionFactory<
    ael::aead::AES256GCM,
    ael::kms::StaticKMS<ael::aead::AES256GCM>,
    ael::metastore::InMemoryMetastore,
> {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![0x33_u8; 32]).unwrap());
    let mut cfg = ael::Config::new("sk-rev-svc", "sk-rev-prod");
    cfg.policy.expire_key_after_s = expire_s;
    cfg.policy.create_date_precision_s = 1;
    cfg.policy.revoke_check_interval_s = 1;
    cfg.policy.cache_sessions = false;
    ael::api::new_session_factory(cfg, store, kms, crypto)
}

fn extract_sk_meta(
    store: &ael::metastore::InMemoryMetastore,
    drr: &ael::DataRowRecord,
) -> (String, i64) {
    let ik_meta = drr.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    let ik_ekr = ael::Metastore::load(store, &ik_meta.id, ik_meta.created)
        .unwrap()
        .unwrap();
    let sk_meta = ik_ekr.parent_key_meta.as_ref().unwrap().clone();
    (sk_meta.id, sk_meta.created)
}

/// Pin down design: revoking the SK while the IK remains valid does
/// NOT rotate either key. Encrypt only consults the latest SK when
/// creating a new IK; with the IK still valid, the encrypt path
/// reuses IK1 → SK1 (revoked or not) without ever asking the
/// metastore for the latest SK.
///
/// If a future change starts polling the latest SK on every encrypt,
/// this test catches it (the assertion flips and we know to revisit
/// the operational story).
#[test]
fn sk_revocation_alone_does_not_rotate_while_ik_valid() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    // 24-hour expiry: IK never ages out during the test.
    let factory = make_factory_with_expire(store.clone(), 24 * 60 * 60);
    let session = factory.get_session("p1");

    let drr1 = session.encrypt(b"pre-revoke").unwrap();
    let (sk_id, sk_created_1) = extract_sk_meta(&store, &drr1);

    store.mark_revoked(&sk_id, sk_created_1);
    sleep(Duration::from_millis(1100));

    let drr2 = session.encrypt(b"post-revoke").unwrap();
    let (_, sk_created_2) = extract_sk_meta(&store, &drr2);

    assert_eq!(
        sk_created_2, sk_created_1,
        "design: SK revocation alone does not rotate while IK is still valid \
         (encrypt only consults latest SK on IK rotation). \
         If this assertion flips, the operational rotation story has changed."
    );
    // Both DRRs still decrypt.
    assert_eq!(session.decrypt(drr1).unwrap(), b"pre-revoke");
    assert_eq!(session.decrypt(drr2).unwrap(), b"post-revoke");
}

/// SK revocation + IK rotation: when the IK ages out (or is itself
/// revoked) the encrypt path creates a new IK, which forces a fresh
/// `load_latest` of the SK; the loader sees the revoked SK and
/// rotates it. This is the path operators rely on for SK rotation
/// to actually take effect.
#[test]
fn sk_revocation_rotates_on_next_ik_rotation() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    // 1-second expiry so both IK and SK age out together.
    let factory = make_factory_with_expire(store.clone(), 1);
    let session = factory.get_session("p1");

    let drr1 = session.encrypt(b"pre").unwrap();
    let (sk_id, sk_created_1) = extract_sk_meta(&store, &drr1);

    // Revoke SK1; sleep past expiration so the IK also rotates.
    store.mark_revoked(&sk_id, sk_created_1);
    sleep(Duration::from_millis(1200));

    let drr2 = session.encrypt(b"post").unwrap();
    let (_, sk_created_2) = extract_sk_meta(&store, &drr2);

    assert!(
        sk_created_2 > sk_created_1,
        "SK rotation: SK2 created {sk_created_2} must exceed SK1 created {sk_created_1}"
    );

    // Pre-rotation DRR still decrypts (SK1 loaded by exact (id,
    // created); revocation doesn't gate decrypt).
    assert_eq!(session.decrypt(drr1).unwrap(), b"pre");
    assert_eq!(session.decrypt(drr2).unwrap(), b"post");
}

/// Historical DRRs created before SK revocation must decrypt
/// indefinitely. Decrypt loads SKs by exact `(id, created)`, which
/// does not consult revocation.
#[test]
fn historical_drrs_decrypt_after_sk_revocation() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory_with_expire(store.clone(), 1);
    let session = factory.get_session("p1");

    let mut drrs: Vec<ael::DataRowRecord> = Vec::new();
    for i in 0..5 {
        let msg = format!("hist-{i}");
        drrs.push(session.encrypt(msg.as_bytes()).unwrap());
    }
    let (sk_id, sk_created_1) = extract_sk_meta(&store, &drrs[0]);

    store.mark_revoked(&sk_id, sk_created_1);
    sleep(Duration::from_millis(1200));

    // Force IK + SK rotation.
    let drr_after = session.encrypt(b"after").unwrap();
    let (_, sk_created_2) = extract_sk_meta(&store, &drr_after);
    assert!(sk_created_2 > sk_created_1);

    // Every historical DRR must still decrypt.
    for (i, drr) in drrs.into_iter().enumerate() {
        let expected = format!("hist-{i}");
        let pt = session.decrypt(drr).unwrap();
        assert_eq!(pt, expected.as_bytes());
    }
    assert_eq!(session.decrypt(drr_after).unwrap(), b"after");
}

/// A *second* factory pointed at the same metastore must observe the
/// revocation through the metastore alone — no in-process state
/// shared between factories. Catches regressions where revocation
/// state lives in factory-level memory.
#[test]
fn cross_factory_sk_revocation_propagates() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let f1 = make_factory_with_expire(store.clone(), 1);
    let s1 = f1.get_session("p-cross");

    let drr1 = s1.encrypt(b"f1-pre").unwrap();
    let (sk_id, sk_created_1) = extract_sk_meta(&store, &drr1);

    store.mark_revoked(&sk_id, sk_created_1);
    sleep(Duration::from_millis(1200));

    // Brand new factory — no SK cache state from f1.
    let f2 = make_factory_with_expire(store.clone(), 1);
    let s2 = f2.get_session("p-cross");
    let drr2 = s2.encrypt(b"f2-post").unwrap();
    let (_, sk_created_2) = extract_sk_meta(&store, &drr2);

    assert!(
        sk_created_2 > sk_created_1,
        "second factory must observe revocation via metastore: SK2 {sk_created_2} > SK1 {sk_created_1}"
    );

    assert_eq!(s1.decrypt(drr1.clone()).unwrap(), b"f1-pre");
    assert_eq!(s2.decrypt(drr1).unwrap(), b"f1-pre");
    assert_eq!(s1.decrypt(drr2.clone()).unwrap(), b"f2-post");
    assert_eq!(s2.decrypt(drr2).unwrap(), b"f2-post");
}

/// Cascading SK revocations across multiple cycles. Each round:
/// encrypt → mark SK revoked → wait past expiry → encrypt under
/// a fresh SK. Verify every prior DRR remains decryptable.
#[test]
fn cascading_sk_revocations() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory_with_expire(store.clone(), 1);
    let session = factory.get_session("p-casc");

    let mut drrs: Vec<(ael::DataRowRecord, String)> = Vec::new();
    let mut prev_sk_created = i64::MIN;

    for round in 0..3 {
        let msg = format!("round-{round}");
        let drr = session.encrypt(msg.as_bytes()).unwrap();
        let (sk_id, sk_created) = extract_sk_meta(&store, &drr);

        if round > 0 {
            assert!(
                sk_created > prev_sk_created,
                "round {round}: SK {sk_created} should be > prev {prev_sk_created}"
            );
        }
        prev_sk_created = sk_created;

        drrs.push((drr, msg));
        store.mark_revoked(&sk_id, sk_created);
        sleep(Duration::from_millis(1200));
    }

    for (drr, msg) in drrs {
        let pt = session.decrypt(drr).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }
}

/// IK and SK both revoked while caches still warm: after TTL elapses,
/// the encrypt path must produce both a new IK and a new SK.
#[test]
fn dual_ik_sk_revocation_full_rotation() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory_with_expire(store.clone(), 24 * 60 * 60);
    let session = factory.get_session("p-dual");

    let drr1 = session.encrypt(b"dual-pre").unwrap();
    let ik_meta = drr1.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    let ik_id = ik_meta.id.clone();
    let ik_created = ik_meta.created;
    let (sk_id, sk_created_1) = extract_sk_meta(&store, &drr1);

    // Revoke both.
    store.mark_revoked(&ik_id, ik_created);
    store.mark_revoked(&sk_id, sk_created_1);

    // Wait past `revoke_check_interval_s` so the IK cache re-evaluates,
    // sees the revoked IK, and triggers create_intermediate_key, which
    // in turn requests the latest SK and triggers SK rotation.
    sleep(Duration::from_millis(1200));

    let drr2 = session.encrypt(b"dual-post").unwrap();
    let new_ik_meta = drr2.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    let (_, sk_created_2) = extract_sk_meta(&store, &drr2);

    assert!(
        new_ik_meta.created > ik_created,
        "IK rotated: new {} > old {}",
        new_ik_meta.created,
        ik_created
    );
    assert!(
        sk_created_2 > sk_created_1,
        "SK rotated: new {sk_created_2} > old {sk_created_1}"
    );

    assert_eq!(session.decrypt(drr1).unwrap(), b"dual-pre");
    assert_eq!(session.decrypt(drr2).unwrap(), b"dual-post");
}
