use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use asherah as ael;

#[test]
fn creates_new_intermediate_key_when_expired() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![5u8; 32]));
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let mut cfg = ael::Config::new("svc", "prod");
    // expire keys quickly
    cfg.policy.expire_key_after_s = 1;
    cfg.policy.create_date_precision_s = 1;
    cfg.policy.revoke_check_interval_s = 1; // ensure IK cache re-checks
    let factory =
        ael::api::new_session_factory(cfg.clone(), store.clone(), kms.clone(), crypto.clone());
    let sess = factory.get_session("p1");

    // First encryption generates IK
    let drr1 = sess.encrypt(b"one").unwrap();
    let ik_created_1 = drr1
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;

    // wait for expiration
    sleep(Duration::from_millis(1200));

    // Next encryption should rotate IK
    let drr2 = sess.encrypt(b"two").unwrap();
    let ik_created_2 = drr2
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;

    assert!(ik_created_2 >= ik_created_1);
    assert!(
        ik_created_2 > ik_created_1,
        "expected rotated IK after expiration"
    );
}
