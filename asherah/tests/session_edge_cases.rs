#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for session encrypt/decrypt edge cases, error paths, and security invariants.

use std::sync::Arc;

use asherah as ael;
use asherah::types::{DataRowRecord, EnvelopeKeyRecord, KeyMeta};

fn make_factory() -> ael::SessionFactory<
    ael::aead::AES256GCM,
    ael::kms::StaticKMS<ael::aead::AES256GCM>,
    ael::metastore::InMemoryMetastore,
> {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![1_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    ael::api::new_session_factory(ael::Config::new("svc", "prod"), store, kms, crypto)
}

// ──────────────────────────── Empty partition ────────────────────────────

#[test]
fn encrypt_with_empty_partition_fails() {
    let factory = make_factory();
    let session = factory.get_session("");
    let result = session.encrypt(b"data");
    assert!(result.is_err(), "empty partition should fail");
    assert!(
        result.unwrap_err().to_string().contains("empty"),
        "error should mention empty partition"
    );
}

#[test]
fn decrypt_with_empty_partition_fails() {
    let factory = make_factory();
    let good_session = factory.get_session("valid");
    let drr = good_session.encrypt(b"data").unwrap();

    let bad_session = factory.get_session("");
    let result = bad_session.decrypt(drr);
    assert!(result.is_err(), "decrypt with empty partition should fail");
}

// ──────────────────────────── Missing key / parent key ────────────────────────────

#[test]
fn decrypt_missing_key_object_fails() {
    let factory = make_factory();
    let session = factory.get_session("p1");

    let drr = DataRowRecord {
        key: None,
        data: vec![1, 2, 3],
    };
    let result = session.decrypt(drr);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("missing key"));
}

#[test]
fn decrypt_missing_parent_key_meta_fails() {
    let factory = make_factory();
    let session = factory.get_session("p1");

    let drr = DataRowRecord {
        key: Some(EnvelopeKeyRecord {
            id: String::new(),
            created: 100,
            encrypted_key: vec![1, 2, 3],
            revoked: None,
            parent_key_meta: None,
        }),
        data: vec![1, 2, 3],
    };
    let result = session.decrypt(drr);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("missing parent key"));
}

// ──────────────────────────── Invalid IK ID ────────────────────────────

#[test]
fn decrypt_with_wrong_partition_ik_id_fails() {
    let factory = make_factory();
    let session = factory.get_session("p1");

    let drr = DataRowRecord {
        key: Some(EnvelopeKeyRecord {
            id: String::new(),
            created: 100,
            encrypted_key: vec![1, 2, 3],
            revoked: None,
            parent_key_meta: Some(KeyMeta {
                id: "_IK_wrong_partition_svc_prod".into(),
                created: 50,
            }),
        }),
        data: vec![1, 2, 3],
    };
    let result = session.decrypt(drr);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid IK id"));
}

// ──────────────────────────── Tampered DRR ────────────────────────────

#[test]
fn decrypt_tampered_data_fails() {
    let factory = make_factory();
    let session = factory.get_session("p1");

    let mut drr = session.encrypt(b"sensitive").unwrap();
    drr.data[0] ^= 0xFF;
    assert!(session.decrypt(drr).is_err());
}

#[test]
fn decrypt_tampered_encrypted_key_fails() {
    let factory = make_factory();
    let session = factory.get_session("p1");

    let mut drr = session.encrypt(b"sensitive").unwrap();
    if let Some(key) = drr.key.as_mut() {
        key.encrypted_key[0] ^= 0xFF;
    }
    assert!(session.decrypt(drr).is_err());
}

#[test]
fn decrypt_truncated_data_fails() {
    let factory = make_factory();
    let session = factory.get_session("p1");

    let mut drr = session.encrypt(b"sensitive").unwrap();
    drr.data.truncate(5);
    assert!(session.decrypt(drr).is_err());
}

// ──────────────────────────── Empty plaintext ────────────────────────────

#[test]
fn encrypt_decrypt_empty_data() {
    let factory = make_factory();
    let session = factory.get_session("p1");

    let drr = session.encrypt(b"").unwrap();
    let result = session.decrypt(drr).unwrap();
    assert_eq!(result, b"");
}

// ──────────────────────────── Large payload ────────────────────────────

#[test]
fn encrypt_decrypt_large_payload() {
    let factory = make_factory();
    let session = factory.get_session("p1");

    let data = vec![0xAA_u8; 1024 * 1024]; // 1 MB
    let drr = session.encrypt(&data).unwrap();
    let result = session.decrypt(drr).unwrap();
    assert_eq!(result, data);
}

// ──────────────────────────── Multiple partitions ────────────────────────────

#[test]
fn different_partitions_use_different_intermediate_keys() {
    let factory = make_factory();
    let s1 = factory.get_session("user-1");
    let s2 = factory.get_session("user-2");

    let drr1 = s1.encrypt(b"for user 1").unwrap();
    let drr2 = s2.encrypt(b"for user 2").unwrap();

    // Each DRR should reference its own IK
    let ik1 = drr1.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    let ik2 = drr2.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    assert_ne!(
        ik1.id, ik2.id,
        "different partitions should use different IK IDs"
    );

    // Each session can decrypt its own data
    assert_eq!(s1.decrypt(drr1).unwrap(), b"for user 1");
    assert_eq!(s2.decrypt(drr2).unwrap(), b"for user 2");
}

#[test]
fn cross_partition_decrypt_fails() {
    let factory = make_factory();
    let s1 = factory.get_session("user-1");
    let s2 = factory.get_session("user-2");

    let drr = s1.encrypt(b"for user 1 only").unwrap();
    let result = s2.decrypt(drr);
    assert!(result.is_err(), "cross-partition decrypt should fail");
}

// ──────────────────────────── Same plaintext, different ciphertext ────────────────────────────

#[test]
fn encrypt_same_data_produces_different_ciphertext() {
    let factory = make_factory();
    let session = factory.get_session("p1");

    let drr1 = session.encrypt(b"same data").unwrap();
    let drr2 = session.encrypt(b"same data").unwrap();

    // Data should differ (random DRK nonce)
    assert_ne!(drr1.data, drr2.data);
}

// ──────────────────────────── DRR JSON roundtrip ────────────────────────────

#[test]
fn drr_serialization_roundtrip() {
    let factory = make_factory();
    let session = factory.get_session("p1");

    let drr = session.encrypt(b"json roundtrip test").unwrap();
    let json = serde_json::to_string(&drr).unwrap();
    let drr2: DataRowRecord = serde_json::from_str(&json).unwrap();
    let result = session.decrypt(drr2).unwrap();
    assert_eq!(result, b"json roundtrip test");
}

// ──────────────────────────── Store/Load via InMemoryStore ────────────────────────────

#[test]
fn store_load_roundtrip() {
    let factory = make_factory();
    let session = factory.get_session("p1");
    let store = ael::store::InMemoryStore::new();

    let key = session.store(b"stored payload", &store).unwrap();
    let result = session.load(&key, &store).unwrap();
    assert_eq!(result, b"stored payload");
}

#[test]
fn load_nonexistent_key_fails() {
    let factory = make_factory();
    let session = factory.get_session("p1");
    let store = ael::store::InMemoryStore::new();

    let key = serde_json::json!({"Created": 999, "Len": 42});
    let result = session.load(&key, &store);
    assert!(result.is_err());
}

// ──────────────────────────── Factory close ────────────────────────────

#[test]
fn factory_close_is_idempotent() {
    let factory = make_factory();
    factory.close().unwrap();
    factory.close().unwrap();
}

// ──────────────────────────── Metrics disabled ────────────────────────────

#[test]
fn encrypt_decrypt_with_metrics_disabled() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![2_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory = ael::api::new_session_factory_with_options(
        ael::Config::new("svc", "prod"),
        store,
        kms,
        crypto,
        &[ael::FactoryOption::Metrics(false)],
    );
    let session = factory.get_session("p1");

    let drr = session.encrypt(b"no metrics").unwrap();
    let result = session.decrypt(drr).unwrap();
    assert_eq!(result, b"no metrics");
}

// ──────────────────────────── NoCache policy ────────────────────────────

#[test]
fn encrypt_decrypt_with_no_cache() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![3_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg =
        ael::Config::new("svc", "prod").with_policy_options(&[ael::policy::PolicyOption::NoCache]);
    let factory = ael::api::new_session_factory(cfg, store, kms, crypto);
    let session = factory.get_session("p1");

    let drr = session.encrypt(b"uncached").unwrap();
    let result = session.decrypt(drr).unwrap();
    assert_eq!(result, b"uncached");
}

// ──────────────────────────── Gap 11: is_valid_intermediate_key_id edge cases ────────────────────────────

#[test]
fn is_valid_ik_id_suffix_with_special_chars() {
    use ael::partition::DefaultPartition;
    use ael::Partition;

    let p = DefaultPartition::new_suffixed("u".into(), "s".into(), "p".into(), "us-east-1".into());
    // Suffix containing special chars like dots and colons
    let weird = DefaultPartition::new_suffixed("u".into(), "s".into(), "p".into(), "a.b:c".into());

    // Exact match with the configured suffix
    assert!(p.is_valid_intermediate_key_id("_IK_u_s_p_us-east-1"));
    // Prefix match with a different suffix
    assert!(p.is_valid_intermediate_key_id("_IK_u_s_p_eu-west-1"));
    // Prefix match with special chars in the suffix
    assert!(weird.is_valid_intermediate_key_id("_IK_u_s_p_a.b:c"));
    assert!(weird.is_valid_intermediate_key_id("_IK_u_s_p_other"));
    // Non-matching prefix should fail
    assert!(!p.is_valid_intermediate_key_id("_IK_x_s_p_us-east-1"));
    assert!(!weird.is_valid_intermediate_key_id("_IK_x_s_p_a.b:c"));
}

#[test]
fn is_valid_ik_id_empty_suffix() {
    use ael::partition::DefaultPartition;
    use ael::Partition;

    // Empty string suffix — still Some(""), so prefix matching applies
    let p = DefaultPartition::new_suffixed("u".into(), "s".into(), "p".into(), "".into());
    // Exact match: _IK_u_s_p_ (with trailing underscore from empty suffix)
    assert!(p.is_valid_intermediate_key_id("_IK_u_s_p_"));
    // Prefix match: starts with _IK_u_s_p
    assert!(p.is_valid_intermediate_key_id("_IK_u_s_p_anything"));
    // The base without suffix also prefix-matches
    assert!(p.is_valid_intermediate_key_id("_IK_u_s_p"));
    // Wrong id does not match
    assert!(!p.is_valid_intermediate_key_id("_IK_x_s_p_"));
}

#[test]
fn is_valid_ik_id_no_suffix_rejects_extra() {
    use ael::partition::DefaultPartition;
    use ael::Partition;

    // Without suffix, only exact match allowed
    let p = DefaultPartition::new("u".into(), "s".into(), "p".into());
    assert!(p.is_valid_intermediate_key_id("_IK_u_s_p"));
    assert!(!p.is_valid_intermediate_key_id("_IK_u_s_p_extra"));
    assert!(!p.is_valid_intermediate_key_id("_IK_u_s_p_"));
    assert!(!p.is_valid_intermediate_key_id("_IK_u_s_"));
    assert!(!p.is_valid_intermediate_key_id(""));
}
