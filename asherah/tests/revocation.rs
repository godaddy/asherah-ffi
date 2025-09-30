use asherah as ael;
use std::sync::Arc;

#[test]
fn revoked_intermediate_key_triggers_rotation() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![8u8; 32]));
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let mut cfg = ael::Config::new("svc", "prod");
    cfg.policy.revoke_check_interval_s = 1; // ensure cache re-evaluates
    cfg.policy.create_date_precision_s = 1;
    let factory = ael::api::new_session_factory(cfg, store.clone(), kms, crypto);
    let sess = factory.get_session("p1");
    // First encrypt to create IK
    let d1 = sess.encrypt(b"one").unwrap();
    let ik_id = d1
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .id
        .clone();
    let ik_created = d1
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;
    // Mark revoked in metastore
    store.mark_revoked(&ik_id, ik_created);
    // Wait past cache TTL so IK cache re-evaluates and does not serve revoked IK
    std::thread::sleep(std::time::Duration::from_millis(1100));
    // Next encrypt should load/create a non-revoked IK
    let d2 = sess.encrypt(b"two").unwrap();
    let ik2 = d2.key.unwrap().parent_key_meta.unwrap().created;
    assert!(ik2 >= ik_created);
    assert!(ik2 > ik_created, "expected new IK after revocation");
}
