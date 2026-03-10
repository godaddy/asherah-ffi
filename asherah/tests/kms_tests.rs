#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for StaticKMS and MultiKms.

use std::sync::Arc;

use asherah::aead::AES256GCM;
use asherah::kms::StaticKMS;
use asherah::kms_multi::MultiKms;
use asherah::traits::KeyManagementService;

// ──────────────────────────── StaticKMS ────────────────────────────

#[test]
fn static_kms_roundtrip() {
    let crypto = Arc::new(AES256GCM::new());
    let kms = StaticKMS::new(crypto, vec![0xAA_u8; 32]).unwrap();
    let key = b"my secret key bytes 32 bytes!!!!";
    let encrypted = kms.encrypt_key(&(), key).unwrap();
    let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();
    assert_eq!(decrypted, key);
}

#[test]
fn static_kms_invalid_key_size_too_short() {
    let crypto = Arc::new(AES256GCM::new());
    let result = StaticKMS::new(crypto, vec![0xAA_u8; 16]);
    let err = result.err().expect("should be Err");
    assert!(err.to_string().contains("invalid key size"));
}

#[test]
fn static_kms_invalid_key_size_too_long() {
    let crypto = Arc::new(AES256GCM::new());
    let result = StaticKMS::new(crypto, vec![0xAA_u8; 64]);
    assert!(result.is_err());
}

#[test]
fn static_kms_invalid_key_size_empty() {
    let crypto = Arc::new(AES256GCM::new());
    let result = StaticKMS::new(crypto, vec![]);
    assert!(result.is_err());
}

#[test]
fn static_kms_decrypt_garbage_fails() {
    let crypto = Arc::new(AES256GCM::new());
    let kms = StaticKMS::new(crypto, vec![0xBB_u8; 32]).unwrap();
    let result = kms.decrypt_key(&(), &[0xFF; 100]);
    assert!(result.is_err());
}

#[test]
fn static_kms_decrypt_empty_fails() {
    let crypto = Arc::new(AES256GCM::new());
    let kms = StaticKMS::new(crypto, vec![0xCC_u8; 32]).unwrap();
    let result = kms.decrypt_key(&(), &[]);
    assert!(result.is_err());
}

#[test]
fn static_kms_different_keys_cannot_decrypt() {
    let crypto = Arc::new(AES256GCM::new());
    let kms1 = StaticKMS::new(crypto.clone(), vec![0xAA_u8; 32]).unwrap();
    let kms2 = StaticKMS::new(crypto, vec![0xBB_u8; 32]).unwrap();
    let encrypted = kms1
        .encrypt_key(&(), b"secret data 1234567890123456")
        .unwrap();
    let result = kms2.decrypt_key(&(), &encrypted);
    assert!(result.is_err());
}

#[test]
fn static_kms_encrypt_empty_payload() {
    let crypto = Arc::new(AES256GCM::new());
    let kms = StaticKMS::new(crypto, vec![0xDD_u8; 32]).unwrap();
    let encrypted = kms.encrypt_key(&(), b"").unwrap();
    let decrypted = kms.decrypt_key(&(), &encrypted).unwrap();
    assert_eq!(decrypted, b"");
}

// ──────────────────────────── MultiKms ────────────────────────────

#[test]
fn multi_kms_empty_backends_fails() {
    let result = MultiKms::new(0, vec![]);
    let err = result.err().expect("should be Err");
    assert!(err.to_string().contains("no KMS backends"));
}

#[test]
fn multi_kms_preferred_out_of_bounds_clamps_to_zero() {
    let crypto = Arc::new(AES256GCM::new());
    let kms: Arc<dyn KeyManagementService> =
        Arc::new(StaticKMS::new(crypto, vec![0xEE_u8; 32]).unwrap());
    let multi = MultiKms::new(999, vec![kms]).unwrap();
    // Should still work (clamps to 0)
    let encrypted = multi.encrypt_key(&(), b"test12345678901234567890").unwrap();
    let decrypted = multi.decrypt_key(&(), &encrypted).unwrap();
    assert_eq!(decrypted, b"test12345678901234567890");
}

#[test]
fn multi_kms_fallback_decrypt() {
    let crypto = Arc::new(AES256GCM::new());
    let kms1: Arc<dyn KeyManagementService> =
        Arc::new(StaticKMS::new(crypto.clone(), vec![0x11_u8; 32]).unwrap());
    let kms2: Arc<dyn KeyManagementService> =
        Arc::new(StaticKMS::new(crypto, vec![0x22_u8; 32]).unwrap());

    // Encrypt with preferred=0 (kms1)
    let multi1 = MultiKms::new(0, vec![kms1.clone(), kms2.clone()]).unwrap();
    let encrypted = multi1
        .encrypt_key(&(), b"fallback test 1234567890")
        .unwrap();

    // Decrypt with preferred=1 (kms2) - kms2 should fail, fallback to kms1
    let multi2 = MultiKms::new(1, vec![kms1, kms2]).unwrap();
    let decrypted = multi2.decrypt_key(&(), &encrypted).unwrap();
    assert_eq!(decrypted, b"fallback test 1234567890");
}

#[test]
fn multi_kms_all_fail_returns_error() {
    let crypto = Arc::new(AES256GCM::new());
    let kms1: Arc<dyn KeyManagementService> =
        Arc::new(StaticKMS::new(crypto.clone(), vec![0x33_u8; 32]).unwrap());
    let kms2: Arc<dyn KeyManagementService> =
        Arc::new(StaticKMS::new(crypto, vec![0x44_u8; 32]).unwrap());

    let multi = MultiKms::new(0, vec![kms1, kms2]).unwrap();
    // Garbage blob that neither can decrypt
    let result = multi.decrypt_key(&(), &[0xFF; 100]);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("all KMS backends failed"));
}
