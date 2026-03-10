#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use asherah as ael;

fn make_factory() -> ael::SessionFactory<
    ael::aead::AES256GCM,
    ael::kms::StaticKMS<ael::aead::AES256GCM>,
    ael::metastore::InMemoryMetastore,
> {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![2_u8; 32]).unwrap());
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("stress-svc", "stress-prod");
    ael::api::new_session_factory(cfg, store, kms, crypto)
}

#[test]
fn encrypt_decrypt_10mb_payload() {
    let factory = make_factory();
    let s = factory.get_session("p-10mb");
    let data: Vec<u8> = (0..10_000_000).map(|i| (i % 251) as u8).collect();
    let drr = s.encrypt(&data).unwrap();
    let pt = s.decrypt(drr).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn encrypt_decrypt_50mb_payload() {
    let factory = make_factory();
    let s = factory.get_session("p-50mb");
    let data: Vec<u8> = (0..50_000_000).map(|i| (i % 239) as u8).collect();
    let drr = s.encrypt(&data).unwrap();
    let pt = s.decrypt(drr).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn encrypt_decrypt_empty_payload() {
    let factory = make_factory();
    let s = factory.get_session("p-empty");
    let data: Vec<u8> = vec![];
    let drr = s.encrypt(&data).unwrap();
    let pt = s.decrypt(drr).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn encrypt_decrypt_1_byte_payload() {
    let factory = make_factory();
    let s = factory.get_session("p-1byte");
    let data = vec![0x42_u8];
    let drr = s.encrypt(&data).unwrap();
    let pt = s.decrypt(drr).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn encrypt_decrypt_payload_sizes() {
    let factory = make_factory();
    let sizes = [1, 100, 1000, 10_000, 100_000, 1_000_000, 5_000_000];
    for &size in &sizes {
        let partition = format!("p-size-{size}");
        let s = factory.get_session(&partition);
        let data: Vec<u8> = (0..size).map(|i| (i % 199) as u8).collect();
        let drr = s.encrypt(&data).unwrap();
        let pt = s.decrypt(drr).unwrap();
        assert_eq!(pt.len(), size, "payload size mismatch for {size}");
        assert_eq!(pt, data, "payload content mismatch for {size}");
    }
}

#[test]
fn many_sequential_encryptions() {
    let factory = make_factory();
    let s = factory.get_session("p-seq");
    let mut drrs = Vec::with_capacity(1000);
    let mut messages = Vec::with_capacity(1000);
    for i in 0..1000 {
        let msg = format!("seq-message-{i}");
        let drr = s.encrypt(msg.as_bytes()).unwrap();
        drrs.push(drr);
        messages.push(msg);
    }
    for (i, drr) in drrs.into_iter().enumerate() {
        let pt = s.decrypt(drr).unwrap();
        assert_eq!(pt, messages[i].as_bytes(), "mismatch at index {i}");
    }
}

#[test]
fn many_partitions() {
    let factory = make_factory();
    let mut records = Vec::with_capacity(100);

    // Encrypt one message per partition
    for i in 0..100 {
        let partition = format!("p-multi-{i}");
        let s = factory.get_session(&partition);
        let msg = format!("partition-msg-{i}");
        let drr = s.encrypt(msg.as_bytes()).unwrap();
        records.push((partition, msg, drr));
    }

    // Decrypt all and verify
    for (partition, msg, drr) in &records {
        let s = factory.get_session(partition);
        let pt = s.decrypt(drr.clone()).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }

    // Cross-partition decryption should fail: try decrypting partition 0's data with partition 1's session
    let (_, _, ref drr_0) = records[0];
    let s_other = factory.get_session(&records[1].0);
    let result = s_other.decrypt(drr_0.clone());
    assert!(result.is_err(), "cross-partition decrypt should fail");
}
