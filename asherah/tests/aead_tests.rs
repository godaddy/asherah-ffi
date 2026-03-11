#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for AES-256-GCM AEAD implementation edge cases.

use asherah::aead::AES256GCM;
use asherah::traits::AEAD;

// ──────────────────────────── Roundtrip ────────────────────────────

#[test]
fn encrypt_decrypt_roundtrip() {
    let aead = AES256GCM::new();
    let key = [0xAA_u8; 32];
    let plaintext = b"hello world";
    let ct = aead.encrypt(plaintext, &key).unwrap();
    let pt = aead.decrypt(&ct, &key).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn encrypt_decrypt_empty_plaintext() {
    let aead = AES256GCM::new();
    let key = [0xBB_u8; 32];
    let ct = aead.encrypt(b"", &key).unwrap();
    let pt = aead.decrypt(&ct, &key).unwrap();
    assert_eq!(pt, b"");
}

// ──────────────────────────── Key size validation ────────────────────────────

#[test]
fn encrypt_wrong_key_size_too_short() {
    let aead = AES256GCM::new();
    let key = [0xAA_u8; 16]; // 16 bytes, not 32
    let result = aead.encrypt(b"data", &key);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid key size"));
}

#[test]
fn encrypt_wrong_key_size_too_long() {
    let aead = AES256GCM::new();
    let key = [0xAA_u8; 64]; // 64 bytes, not 32
    let result = aead.encrypt(b"data", &key);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid key size"));
}

#[test]
fn encrypt_empty_key() {
    let aead = AES256GCM::new();
    let result = aead.encrypt(b"data", &[]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid key size"));
}

#[test]
fn decrypt_wrong_key_size() {
    let aead = AES256GCM::new();
    let key = [0xAA_u8; 16];
    let ct = vec![0_u8; 28]; // minimum size
    let result = aead.decrypt(&ct, &key);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid key size"));
}

// ──────────────────────────── Ciphertext too short ────────────────────────────

#[test]
fn decrypt_ciphertext_too_short() {
    let aead = AES256GCM::new();
    let key = [0xAA_u8; 32];
    // NONCE_SIZE + TAG_SIZE = 12 + 16 = 28, so 27 bytes is too short
    let ct = vec![0_u8; 27];
    let result = aead.decrypt(&ct, &key);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("ciphertext too short"),);
}

#[test]
fn decrypt_empty_ciphertext() {
    let aead = AES256GCM::new();
    let key = [0xAA_u8; 32];
    let result = aead.decrypt(&[], &key);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("ciphertext too short"),);
}

#[test]
fn decrypt_ciphertext_exactly_minimum_size() {
    let aead = AES256GCM::new();
    let key = [0xAA_u8; 32];
    // Exactly 28 bytes (NONCE_SIZE + TAG_SIZE) - this is the minimum but will fail
    // because the tag won't verify. The point is it shouldn't error on "too short".
    let ct = vec![0_u8; 28];
    let result = aead.decrypt(&ct, &key);
    assert!(result.is_err());
    // Should fail with decrypt error, NOT "ciphertext too short"
    assert!(result.unwrap_err().to_string().contains("decrypt error"));
}

// ──────────────────────────── Tampered ciphertext ────────────────────────────

#[test]
fn decrypt_tampered_ciphertext_fails() {
    let aead = AES256GCM::new();
    let key = [0xAA_u8; 32];
    let mut ct = aead.encrypt(b"sensitive", &key).unwrap();
    ct[0] ^= 0xFF; // flip first byte
    let result = aead.decrypt(&ct, &key);
    assert!(result.is_err());
}

#[test]
fn decrypt_tampered_nonce_fails() {
    let aead = AES256GCM::new();
    let key = [0xAA_u8; 32];
    let mut ct = aead.encrypt(b"sensitive", &key).unwrap();
    // nonce is the last 12 bytes
    let nonce_start = ct.len() - AES256GCM::NONCE_SIZE;
    ct[nonce_start] ^= 0xFF;
    let result = aead.decrypt(&ct, &key);
    assert!(result.is_err());
}

#[test]
fn decrypt_wrong_key_fails() {
    let aead = AES256GCM::new();
    let key1 = [0xAA_u8; 32];
    let key2 = [0xBB_u8; 32];
    let ct = aead.encrypt(b"secret", &key1).unwrap();
    let result = aead.decrypt(&ct, &key2);
    assert!(result.is_err());
}

// ──────────────────────────── Same plaintext, different ciphertext ────────────────────────────

#[test]
fn encrypt_same_plaintext_produces_different_ciphertext() {
    let aead = AES256GCM::new();
    let key = [0xAA_u8; 32];
    let ct1 = aead.encrypt(b"hello", &key).unwrap();
    let ct2 = aead.encrypt(b"hello", &key).unwrap();
    assert_ne!(ct1, ct2, "nonce should differ each time");
}

// ──────────────────────────── Ciphertext structure ────────────────────────────

#[test]
fn ciphertext_has_correct_overhead() {
    let aead = AES256GCM::new();
    let key = [0xAA_u8; 32];
    let pt = b"test data";
    let ct = aead.encrypt(pt, &key).unwrap();
    // ciphertext = plaintext + TAG_SIZE (16) + NONCE_SIZE (12)
    assert_eq!(
        ct.len(),
        pt.len() + AES256GCM::TAG_SIZE + AES256GCM::NONCE_SIZE
    );
}

// ──────────────────────────── Constants ────────────────────────────

#[test]
fn nonce_and_tag_sizes() {
    let aead = AES256GCM::new();
    assert_eq!(aead.nonce_size(), 12);
    assert_eq!(aead.tag_size(), 16);
    assert_eq!(AES256GCM::NONCE_SIZE, 12);
    assert_eq!(AES256GCM::TAG_SIZE, 16);
    assert_eq!(AES256GCM::BLOCK_SIZE, 16);
}

// ──────────────────────────── Default trait ────────────────────────────

#[test]
#[allow(clippy::default_constructed_unit_structs)]
fn aes256gcm_default() {
    let aead = AES256GCM::default();
    let key = [0xCC_u8; 32];
    let ct = aead.encrypt(b"default", &key).unwrap();
    let pt = aead.decrypt(&ct, &key).unwrap();
    assert_eq!(pt, b"default");
}

// ──────────────────────────── xsalsa_key_from_bytes ────────────────────────────

#[test]
fn xsalsa_key_deterministic() {
    let k1 = asherah::aead::xsalsa_key_from_bytes(b"input");
    let k2 = asherah::aead::xsalsa_key_from_bytes(b"input");
    assert_eq!(k1, k2);
}

#[test]
fn xsalsa_key_different_inputs_differ() {
    let k1 = asherah::aead::xsalsa_key_from_bytes(b"input1");
    let k2 = asherah::aead::xsalsa_key_from_bytes(b"input2");
    assert_ne!(k1, k2);
}

#[test]
fn xsalsa_key_empty_input() {
    let k = asherah::aead::xsalsa_key_from_bytes(b"");
    assert_eq!(k.len(), 32);
}

#[test]
fn xsalsa_key_large_input() {
    let input = vec![0xAB_u8; 10_000];
    let k = asherah::aead::xsalsa_key_from_bytes(&input);
    assert_eq!(k.len(), 32);
}
