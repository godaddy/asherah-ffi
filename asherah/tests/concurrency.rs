use std::sync::Arc;
use std::thread;

use asherah as ael;

#[test]
fn concurrent_encrypt_decrypt_roundtrip() {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![9u8; 32]));
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let factory =
        ael::api::new_session_factory(ael::Config::new("svc", "prod"), store, kms, crypto);
    let s = Arc::new(factory.get_session("p-concurrent"));

    let mut handles = vec![];
    for i in 0..16 {
        let s2 = s.clone();
        handles.push(thread::spawn(move || {
            let msg = format!("hello-{i}");
            let drr = s2.encrypt(msg.as_bytes()).unwrap();
            let out = s2.decrypt(drr).unwrap();
            assert_eq!(out, msg.as_bytes());
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
