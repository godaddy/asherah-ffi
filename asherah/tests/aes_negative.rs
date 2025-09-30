#![allow(clippy::unwrap_used, clippy::expect_used)]
use asherah as ael;
use asherah::AEAD;
use rand::RngCore;

#[test]
fn decrypt_fails_on_tamper() {
    let c = ael::aead::AES256GCM::new();
    let mut key = vec![0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let pt = b"attack at dawn".to_vec();
    let mut ct = c.encrypt(&pt, &key).unwrap();
    // flip last byte
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    assert!(c.decrypt(&ct, &key).is_err());
}

#[test]
fn decrypt_rejects_short_ciphertext() {
    let c = ael::aead::AES256GCM::new();
    let key = vec![0_u8; 32];
    let short = vec![0_u8; ael::aead::AES256GCM::NONCE_SIZE + ael::aead::AES256GCM::TAG_SIZE - 1];
    assert!(c.decrypt(&short, &key).is_err());
}
