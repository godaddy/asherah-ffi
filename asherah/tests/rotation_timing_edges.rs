//! Edge cases at the intersection of `create_date_precision_s`,
//! `expire_key_after_s`, and the IK→SK parent invariant when both
//! tiers expire simultaneously.
//!
//! Two clusters of tests:
//!
//! ## Time-precision boundary
//!
//! `Session::new_key_timestamp` (`session.rs:96-101`) rounds new-key
//! created timestamps down to `create_date_precision_s`-aligned
//! buckets. The interaction with `expire_key_after_s` and the
//! metastore's `(id, created)` primary key produces several edge
//! cases that weren't asserted anywhere:
//!
//! - Two encrypts in the same precision window must share the same
//!   IK (precision rounding wins; metastore store returns Ok(false)
//!   on duplicate, race-loss recovery converges).
//! - When `precision_s > expire_s`, every encrypt sees a policy-
//!   expired IK but the new-key timestamp would land in the same
//!   precision bucket — the system must converge, not hot-loop.
//! - `precision_s=0` and `precision_s<0` skip the rounding entirely
//!   (`session.rs:97-99`).
//!
//! ## Simultaneous SK+IK expiration
//!
//! `tests/error_injection.rs::decrypt_succeeds_after_system_key_rotation`
//! checks that a post-rotation DRR exists and the old DRR decrypts.
//! It does **not** assert the structural invariant that the new IK's
//! `parent_key_meta` points at the **new** SK (not the old one), nor
//! that the new IK is actually decryptable under the new SK at
//! encrypt time. Those are security-critical properties: an IK born
//! pointing at a stale SK would decrypt under the wrong key on
//! every subsequent operation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use asherah as ael;

fn make_factory(
    store: Arc<ael::metastore::InMemoryMetastore>,
    precision_s: i64,
    expire_s: i64,
) -> ael::SessionFactory<
    ael::aead::AES256GCM,
    ael::kms::StaticKMS<ael::aead::AES256GCM>,
    ael::metastore::InMemoryMetastore,
> {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![0x99_u8; 32]).unwrap());
    let mut cfg = ael::Config::new("rot-edge-svc", "rot-edge-prod");
    cfg.policy.create_date_precision_s = precision_s;
    cfg.policy.expire_key_after_s = expire_s;
    cfg.policy.revoke_check_interval_s = 1;
    cfg.policy.cache_sessions = false;
    ael::api::new_session_factory(cfg, store, kms, crypto)
}

fn ik_meta(drr: &ael::DataRowRecord) -> (String, i64) {
    let pkm = drr.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    (pkm.id.clone(), pkm.created)
}

fn sk_meta(store: &ael::metastore::InMemoryMetastore, drr: &ael::DataRowRecord) -> (String, i64) {
    let (id, created) = ik_meta(drr);
    let ekr = ael::Metastore::load(store, &id, created).unwrap().unwrap();
    let p = ekr.parent_key_meta.as_ref().unwrap();
    (p.id.clone(), p.created)
}

// ──────────────────────── Precision boundary ────────────────────────

/// Two encrypts inside one 60-second precision window must share
/// the same IK. The new-key timestamp rounds down to the window
/// start; both encrypts compute the same `(id, created)` and the
/// metastore's "INSERT IGNORE / ON CONFLICT DO NOTHING" path
/// converges them.
#[test]
fn precision_window_groups_encrypts_into_one_ik() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store, 60, 24 * 60 * 60);
    let session = factory.get_session("p-window");

    let drr1 = session.encrypt(b"a").unwrap();
    let drr2 = session.encrypt(b"b").unwrap();
    let drr3 = session.encrypt(b"c").unwrap();

    let (_, c1) = ik_meta(&drr1);
    let (_, c2) = ik_meta(&drr2);
    let (_, c3) = ik_meta(&drr3);
    assert_eq!(c1, c2, "encrypts within one precision window share IK");
    assert_eq!(c2, c3);

    assert_eq!(session.decrypt(drr1).unwrap(), b"a");
    assert_eq!(session.decrypt(drr2).unwrap(), b"b");
    assert_eq!(session.decrypt(drr3).unwrap(), b"c");
}

/// `expire_s < precision_s` used to be a soft footgun: the second
/// encrypt inside the precision window would see an expired IK but
/// collide with the same rounded `(id, created)`.
///
/// The factory now clamps `create_date_precision_s` to
/// `expire_key_after_s`, so this pathological config converges by
/// rotating into a new one-second bucket after expiry instead of
/// failing closed.
#[test]
fn expire_smaller_than_precision_is_clamped_and_rotates() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store, 60, 1);
    let session = factory.get_session("p-pathological");

    // First encrypt populates SK + IK and round-trips.
    let drr1 = session.encrypt(b"x").unwrap();
    let (_, c1) = ik_meta(&drr1);
    assert_eq!(session.decrypt(drr1).unwrap(), b"x");

    // Sleep past expire_s. The originally requested precision was 60s, but
    // policy minimum enforcement clamps it to expire_s=1s, so this crosses
    // the effective precision window too.
    sleep(Duration::from_millis(1100));

    let drr2 = session.encrypt(b"y").unwrap();
    let (_, c2) = ik_meta(&drr2);
    assert!(
        c2 > c1,
        "clamped precision should allow rotation after expiry: {c2} > {c1}"
    );
    assert_eq!(session.decrypt(drr2).unwrap(), b"y");
}

/// `precision_s=0` skips the rounding entirely; encrypts get
/// distinct created timestamps when separated by ≥1 second.
/// Tests the early-return at `session.rs:97-99`.
#[test]
fn precision_zero_uses_now_directly() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    // Long expire so policy doesn't drive rotation; only the
    // metastore's primary-key uniqueness gates new IKs.
    let factory = make_factory(store.clone(), 0, 24 * 60 * 60);
    let session = factory.get_session("p-prec-zero");

    let drr1 = session.encrypt(b"a").unwrap();
    let (_, c1) = ik_meta(&drr1);

    // Two encrypts in immediate succession may still get the same
    // second-resolution timestamp; round-trip is what matters.
    let drr2 = session.encrypt(b"b").unwrap();
    let (_, c2) = ik_meta(&drr2);
    assert!(
        c2 >= c1,
        "with precision=0, IK created should be monotonically non-decreasing"
    );

    assert_eq!(session.decrypt(drr1).unwrap(), b"a");
    assert_eq!(session.decrypt(drr2).unwrap(), b"b");
}

/// `precision_s < 0` takes the same early-return as zero;
/// behavior is identical.
#[test]
fn precision_negative_uses_now_directly() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store, -42, 24 * 60 * 60);
    let session = factory.get_session("p-prec-neg");

    let drr = session.encrypt(b"hello").unwrap();
    let (_, c) = ik_meta(&drr);
    assert!(c > 0, "negative precision must still produce a sane epoch");
    assert_eq!(session.decrypt(drr).unwrap(), b"hello");
}

/// Two encrypts straddling a precision-window boundary must produce
/// **different** IKs. With `precision_s=1, expire_s=1`, sleeping
/// 1.2s puts the second encrypt in a new bucket and past the
/// expire threshold simultaneously.
#[test]
fn precision_window_crossed_rotates() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store, 1, 1);
    let session = factory.get_session("p-window-cross");

    let drr1 = session.encrypt(b"before").unwrap();
    let (_, c1) = ik_meta(&drr1);

    sleep(Duration::from_millis(1200));

    let drr2 = session.encrypt(b"after").unwrap();
    let (_, c2) = ik_meta(&drr2);

    assert!(
        c2 > c1,
        "crossing both precision and expire boundaries must rotate: {c2} > {c1}"
    );
    assert_eq!(session.decrypt(drr1).unwrap(), b"before");
    assert_eq!(session.decrypt(drr2).unwrap(), b"after");
}

// ─────────────── Simultaneous SK+IK expiration order-of-ops ───────────────

/// When SK1 and IK1 both policy-expire and the next encrypt fires:
/// 1. A new SK2 must be created.
/// 2. The new IK2 must be encrypted under SK2, not SK1.
/// 3. IK2's `parent_key_meta` must point at SK2.
/// 4. Decrypting IK2 from the metastore must succeed using SK2 only
///    (we test this by erasing the SK cache via fresh factory and
///    confirming the decrypt path picks up SK2 by exact meta).
#[test]
fn simultaneous_sk_ik_expire_new_ik_under_new_sk() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store.clone(), 1, 1);
    let session = factory.get_session("p-simul");

    // Establish SK1 + IK1.
    let drr1 = session.encrypt(b"pre").unwrap();
    let (_, ik_created_1) = ik_meta(&drr1);
    let (sk_id, sk_created_1) = sk_meta(&store, &drr1);

    // Sleep past expire for both SK and IK (they share expire_s=1).
    sleep(Duration::from_millis(1200));

    // Trigger rotation. The order-of-ops invariant: a new SK2 is
    // created first, then IK2 is encrypted under SK2.
    let drr2 = session.encrypt(b"post").unwrap();
    let (ik2_id, ik_created_2) = ik_meta(&drr2);
    let (_, sk_created_2) = sk_meta(&store, &drr2);

    // Both tiers must have rotated.
    assert!(
        ik_created_2 > ik_created_1,
        "IK rotated: {ik_created_2} > {ik_created_1}"
    );
    assert!(
        sk_created_2 > sk_created_1,
        "SK rotated: {sk_created_2} > {sk_created_1}"
    );

    // Structural invariant: IK2's parent_key_meta points at SK2,
    // not SK1. If the engine encrypted IK2 under SK1 but stored the
    // record with parent=SK1, the IK row would still decrypt — but
    // any future "SK rotation must propagate" assumption breaks.
    let ik2_ekr = ael::Metastore::load(&*store, &ik2_id, ik_created_2)
        .unwrap()
        .unwrap();
    let parent = ik2_ekr.parent_key_meta.as_ref().unwrap();
    assert_eq!(parent.id, sk_id);
    assert_eq!(
        parent.created, sk_created_2,
        "IK2 must reference the NEW SK, not the old one (parent.created={} != sk_created_2={})",
        parent.created, sk_created_2
    );

    // Confirm IK2 decrypts under SK2 even with a cold SK cache.
    let factory2 = make_factory(store, 1, 1);
    let session2 = factory2.get_session("p-simul");
    assert_eq!(session2.decrypt(drr2).unwrap(), b"post");

    // And the original DRR1 still decrypts — it loads SK1 by exact
    // meta, bypassing revocation/expiration checks on the latest path.
    assert_eq!(session.decrypt(drr1).unwrap(), b"pre");
}

/// After SK rotation, decrypting an old DRR must use the OLD SK
/// loaded by exact meta. Pin down that the decrypt path doesn't
/// accidentally use the latest SK pointer (which would attempt to
/// decrypt the old IK under the new SK and fail with a misleading
/// AEAD error).
#[test]
fn old_drr_decrypts_via_exact_sk_meta_after_rotation() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = make_factory(store.clone(), 1, 1);
    let session = factory.get_session("p-old-drr");

    let drr_old = session.encrypt(b"ancient secret").unwrap();
    let (_, sk_created_old) = sk_meta(&store, &drr_old);

    sleep(Duration::from_millis(1200));

    // Force rotation by encrypting again.
    let drr_new = session.encrypt(b"new secret").unwrap();
    let (_, sk_created_new) = sk_meta(&store, &drr_new);
    assert!(sk_created_new > sk_created_old);

    // Drop session and factory to clear the SK cache, then decrypt
    // the old DRR through a fresh factory. This exercises the cold-
    // load path: load IK1 by exact (id, created), get its
    // parent_key_meta, then load_system_key by exact SK1 meta
    // (NOT load_latest, which would return SK2 and fail).
    drop(session);
    drop(factory);
    let factory2 = make_factory(store, 1, 1);
    let session2 = factory2.get_session("p-old-drr");
    let pt = session2
        .decrypt(drr_old)
        .expect("old DRR must decrypt via exact SK meta");
    assert_eq!(pt, b"ancient secret");
}
