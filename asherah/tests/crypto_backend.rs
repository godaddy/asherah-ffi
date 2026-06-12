#![allow(clippy::expect_used)]

use asherah::aead;
use asherah::traits::AEAD as _;
use std::mem::size_of;

fn decode_hex(input: &str) -> Vec<u8> {
    assert!(
        input.len().is_multiple_of(2),
        "hex input length must be even"
    );
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let high = (bytes[i] as char).to_digit(16).expect("valid hex");
        let low = (bytes[i + 1] as char).to_digit(16).expect("valid hex");
        out.push(((high << 4) | low) as u8);
    }
    out
}

#[test]
fn selected_backend_matches_feature() {
    #[cfg(feature = "crypto-hardware-rust")]
    assert_eq!(aead::backend_name(), "hardware-rust-crypto");

    #[cfg(all(not(feature = "crypto-hardware-rust"), feature = "crypto-ring"))]
    assert_eq!(aead::backend_name(), "ring");
}

#[test]
fn prepared_key_state_is_non_empty() {
    assert!(aead::prepared_key_state_size() >= 32);
}

#[test]
fn prepared_key_state_size_matches_cached_key_value() {
    assert_eq!(
        aead::prepared_key_state_size(),
        size_of::<aead::PreparedAes256GcmKey>()
    );
}

#[test]
fn decrypts_standard_aes_256_gcm_vector_in_asherah_layout() {
    // NIST SP 800-38D AES-256-GCM test vector, encoded as Asherah's
    // ciphertext || tag || nonce layout.
    let key = decode_hex("0000000000000000000000000000000000000000000000000000000000000000");
    let nonce = decode_hex("000000000000000000000000");
    let plaintext = decode_hex("00000000000000000000000000000000");
    let ciphertext = decode_hex("cea7403d4d606b6e074ec5d3baf39d18");
    let tag = decode_hex("d0d1c8a799996bf0265b98b5d48ab919");

    let mut asherah_layout = ciphertext;
    asherah_layout.extend_from_slice(&tag);
    asherah_layout.extend_from_slice(&nonce);

    let prepared = aead::prepare_key(&key).expect("prepare key");
    let decrypted =
        aead::decrypt_with_prepared_key(&asherah_layout, &prepared).expect("decrypt vector");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn aead_encrypt_decrypt_uses_selected_backend() {
    let aead = aead::AES256GCM::new();
    let key = [0x5a_u8; 32];
    let plaintext = b"backend round trip";
    let ciphertext = aead.encrypt(plaintext, &key).expect("encrypt");
    let decrypted = aead.decrypt(&ciphertext, &key).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}
