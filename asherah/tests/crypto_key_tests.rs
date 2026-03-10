#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for internal crypto_key module: CryptoKey, generate_key, is_key_expired.

use asherah::internal::{crypto_key, CryptoKey};

// ──────────────────────────── CryptoKey basic ────────────────────────────

#[test]
fn crypto_key_new_and_accessors() {
    let key = CryptoKey::new(1234, false, vec![0xAA; 32]).unwrap();
    assert_eq!(key.created(), 1234);
    assert!(!key.revoked());
}

#[test]
fn crypto_key_revoked() {
    let key = CryptoKey::new(100, true, vec![0xBB; 32]).unwrap();
    assert!(key.revoked());
}

#[test]
fn crypto_key_with_key_func() {
    let key = CryptoKey::new(0, false, vec![0xCC; 32]).unwrap();
    let result = key
        .with_key_func(|bytes| {
            assert_eq!(bytes.len(), 32);
            assert!(bytes.iter().all(|b| *b == 0xCC));
            42
        })
        .unwrap();
    assert_eq!(result, 42);
}

#[test]
fn crypto_key_with_key_func_preserves_data() {
    let input = vec![
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let key = CryptoKey::new(0, false, input.clone()).unwrap();
    key.with_key_func(|bytes| {
        assert_eq!(bytes, &input);
    })
    .unwrap();
}

#[test]
fn crypto_key_various_sizes() {
    // 1 byte
    let key = CryptoKey::new(0, false, vec![0xFF]).unwrap();
    key.with_key_func(|b| assert_eq!(b.len(), 1)).unwrap();

    // 64 bytes
    let key = CryptoKey::new(0, false, vec![0xDD; 64]).unwrap();
    key.with_key_func(|b| assert_eq!(b.len(), 64)).unwrap();
}

// ──────────────────────────── generate_key ────────────────────────────

#[test]
fn generate_key_is_32_bytes() {
    let key = crypto_key::generate_key(1000).unwrap();
    assert_eq!(key.created(), 1000);
    assert!(!key.revoked());
    key.with_key_func(|bytes| {
        assert_eq!(bytes.len(), 32);
    })
    .unwrap();
}

#[test]
fn generate_key_produces_different_keys() {
    let key1 = crypto_key::generate_key(1000).unwrap();
    let key2 = crypto_key::generate_key(1000).unwrap();
    let mut bytes1 = Vec::new();
    let mut bytes2 = Vec::new();
    key1.with_key_func(|b| bytes1 = b.to_vec()).unwrap();
    key2.with_key_func(|b| bytes2 = b.to_vec()).unwrap();
    assert_ne!(bytes1, bytes2, "random keys should differ");
}

#[test]
fn generate_key_not_all_zeros() {
    let key = crypto_key::generate_key(0).unwrap();
    let mut is_zero = true;
    key.with_key_func(|bytes| {
        is_zero = bytes.iter().all(|b| *b == 0);
    })
    .unwrap();
    assert!(!is_zero, "generated key should not be all zeros");
}

// ──────────────────────────── is_key_expired ────────────────────────────

#[test]
fn key_not_expired() {
    // created=100, expire_after=1000, now=200 → not expired (elapsed=100 < 1000)
    assert!(!crypto_key::is_key_expired(100, 1000, 200));
}

#[test]
fn key_exactly_expired() {
    // created=100, expire_after=100, now=200 → expired (elapsed=100 >= 100)
    assert!(crypto_key::is_key_expired(100, 100, 200));
}

#[test]
fn key_past_expired() {
    // created=100, expire_after=50, now=200 → expired (elapsed=100 >= 50)
    assert!(crypto_key::is_key_expired(100, 50, 200));
}

#[test]
fn key_just_created() {
    // created=now → not expired (elapsed=0 < anything > 0)
    assert!(!crypto_key::is_key_expired(100, 1, 100));
}

#[test]
fn key_clock_skew_backward() {
    // now < created → now_s - created_s is negative, which wraps for i64
    // Result: negative difference is less than expire_after, so not expired
    assert!(!crypto_key::is_key_expired(200, 100, 100));
}

#[test]
fn key_expire_after_zero() {
    // expire_after=0 → any non-negative elapsed >= 0 → always expired
    assert!(crypto_key::is_key_expired(100, 0, 100));
    assert!(crypto_key::is_key_expired(100, 0, 200));
}

#[test]
fn key_expire_after_negative() {
    // expire_after=-1 → elapsed (0 or positive) >= -1 → always expired
    assert!(crypto_key::is_key_expired(100, -1, 100));
}

#[test]
fn key_expire_very_large() {
    // expire_after = i64::MAX → never expires for reasonable timestamps
    assert!(!crypto_key::is_key_expired(0, i64::MAX, 1_000_000));
}
