#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Tests for memguard: Buffer, LockedBuffer, Enclave, Coffer, helper functions.

use asherah::memguard;

// ──────────────────────────── Helper functions ────────────────────────────

#[test]
fn hash_deterministic() {
    let h1 = memguard::hash(b"test input");
    let h2 = memguard::hash(b"test input");
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 32);
}

#[test]
fn hash_different_inputs() {
    let h1 = memguard::hash(b"input A");
    let h2 = memguard::hash(b"input B");
    assert_ne!(h1, h2);
}

#[test]
fn hash_empty() {
    let h = memguard::hash(b"");
    assert_eq!(h.len(), 32);
}

#[test]
fn ct_equal_same() {
    assert!(memguard::ct_equal(b"hello", b"hello"));
}

#[test]
fn ct_equal_different() {
    assert!(!memguard::ct_equal(b"hello", b"world"));
}

#[test]
fn ct_equal_different_lengths() {
    assert!(!memguard::ct_equal(b"ab", b"abc"));
}

#[test]
fn ct_equal_empty() {
    assert!(memguard::ct_equal(b"", b""));
}

#[test]
fn ct_copy_basic() {
    let src = [1_u8, 2, 3, 4, 5];
    let mut dst = [0_u8; 5];
    memguard::ct_copy(&mut dst, &src);
    assert_eq!(dst, src);
}

#[test]
fn ct_copy_dst_larger() {
    let src = [1_u8, 2, 3];
    let mut dst = [0_u8; 5];
    memguard::ct_copy(&mut dst, &src);
    assert_eq!(&dst[..3], &src);
    assert_eq!(&dst[3..], &[0, 0]);
}

#[test]
fn ct_move_wipes_source() {
    let mut src = [1_u8, 2, 3, 4, 5];
    let mut dst = [0_u8; 5];
    memguard::ct_move(&mut dst, &mut src);
    assert_eq!(dst, [1, 2, 3, 4, 5]);
    assert_eq!(src, [0, 0, 0, 0, 0]);
}

#[test]
fn wipe_bytes_zeros() {
    let mut buf = [0xAA_u8; 16];
    memguard::wipe_bytes(&mut buf);
    assert!(buf.iter().all(|b| *b == 0));
}

#[test]
fn scramble_bytes_changes_content() {
    let mut buf = [0_u8; 32];
    memguard::scramble_bytes(&mut buf);
    // Extremely unlikely all 32 bytes are zero after random fill
    assert!(!buf.iter().all(|b| *b == 0), "scramble should randomize");
}

// ──────────────────────────── Buffer ────────────────────────────

#[test]
fn buffer_new_and_size() {
    let buf = memguard::Buffer::new(64).unwrap();
    assert_eq!(buf.size(), 64);
    assert!(buf.alive());
    assert!(buf.mutable());
}

#[test]
fn buffer_new_zero_size_fails() {
    let result = memguard::Buffer::new(0);
    assert!(result.is_err());
}

#[test]
fn buffer_write_and_read() {
    let mut buf = memguard::Buffer::new(4).unwrap();
    buf.bytes().copy_from_slice(&[10, 20, 30, 40]);
    assert_eq!(buf.as_slice(), &[10, 20, 30, 40]);
}

#[test]
fn buffer_freeze_and_melt() {
    let mut buf = memguard::Buffer::new(8).unwrap();
    buf.bytes().copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    buf.freeze().unwrap();
    assert!(!buf.mutable());
    assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    buf.melt().unwrap();
    assert!(buf.mutable());
}

#[test]
fn buffer_scramble() {
    let mut buf = memguard::Buffer::new(32).unwrap();
    // Initialize to zeros
    for b in buf.bytes().iter_mut() {
        *b = 0;
    }
    buf.scramble();
    // Should be randomized
    assert!(!buf.as_slice().iter().all(|b| *b == 0));
}

#[test]
fn buffer_destroy() {
    let mut buf = memguard::Buffer::new(16).unwrap();
    buf.destroy().unwrap();
    assert!(!buf.alive());
    assert_eq!(buf.size(), 0);
}

#[test]
fn buffer_destroy_idempotent() {
    let mut buf = memguard::Buffer::new(8).unwrap();
    buf.destroy().unwrap();
    buf.destroy().unwrap(); // should not panic
}

#[test]
fn buffer_dead_returns_empty() {
    let mut buf = memguard::Buffer::new(8).unwrap();
    buf.destroy().unwrap();
    assert_eq!(buf.bytes().len(), 0);
    assert_eq!(buf.as_slice().len(), 0);
}

// ──────────────────────────── LockedBuffer ────────────────────────────

#[test]
fn locked_buffer_new_and_size() {
    let lb = memguard::LockedBuffer::new(32).unwrap();
    assert_eq!(lb.size(), 32);
    assert!(lb.is_alive());
}

#[test]
fn locked_buffer_from_bytes() {
    let data = vec![1_u8, 2, 3, 4, 5, 6, 7, 8];
    let lb = memguard::LockedBuffer::from_bytes(data.clone()).unwrap();
    assert_eq!(lb.size(), 8);
    assert_eq!(lb.bytes(), data);
}

#[test]
fn locked_buffer_random() {
    let lb = memguard::LockedBuffer::random(32).unwrap();
    assert_eq!(lb.size(), 32);
    // Random should not be all zeros
    assert!(!lb.bytes().iter().all(|b| *b == 0));
}

#[test]
fn locked_buffer_copy() {
    let lb = memguard::LockedBuffer::new(4).unwrap();
    lb.melt().unwrap();
    lb.copy(&[10, 20, 30, 40]);
    assert_eq!(lb.bytes(), vec![10, 20, 30, 40]);
}

#[test]
fn locked_buffer_move_wipes_source() {
    let lb = memguard::LockedBuffer::new(4).unwrap();
    lb.melt().unwrap();
    let mut src = vec![1, 2, 3, 4];
    lb.r#move(&mut src);
    assert_eq!(lb.bytes(), vec![1, 2, 3, 4]);
    assert_eq!(src, vec![0, 0, 0, 0]);
}

#[test]
fn locked_buffer_freeze_melt() {
    let lb = memguard::LockedBuffer::new(8).unwrap();
    lb.melt().unwrap();
    assert!(lb.is_mutable());
    lb.freeze().unwrap();
    assert!(!lb.is_mutable());
}

#[test]
fn locked_buffer_wipe() {
    let lb = memguard::LockedBuffer::from_bytes(vec![0xFF; 8]).unwrap();
    lb.melt().unwrap();
    lb.wipe();
    assert!(lb.bytes().iter().all(|b| *b == 0));
}

#[test]
fn locked_buffer_destroy() {
    let lb = memguard::LockedBuffer::from_bytes(vec![0xAA; 16]).unwrap();
    lb.destroy().unwrap();
    assert!(!lb.is_alive());
}

#[test]
fn locked_buffer_with_bytes() {
    let lb = memguard::LockedBuffer::from_bytes(vec![5, 6, 7, 8]).unwrap();
    let result = lb
        .with_bytes(|b| {
            assert_eq!(b, &[5, 6, 7, 8]);
            42
        })
        .unwrap();
    assert_eq!(result, 42);
}

// ──────────────────────────── Enclave (seal/open) ────────────────────────────

#[test]
fn enclave_seal_and_open_roundtrip() {
    let lb = memguard::LockedBuffer::from_bytes(vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    let enclave = lb.seal().unwrap();
    assert_eq!(enclave.size(), 8);
    assert_eq!(enclave.plaintext_len(), 8);
    let opened = enclave.open().unwrap();
    assert_eq!(opened.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    memguard::pool_release(opened);
}

// ──────────────────────────── Coffer ────────────────────────────

#[test]
fn coffer_view_returns_32_byte_key() {
    let coffer = memguard::Coffer::new().unwrap();
    let key = coffer.view().unwrap();
    assert_eq!(key.size(), 32);
    memguard::pool_release(key);
    coffer.destroy().unwrap();
}

#[test]
fn coffer_view_consistent() {
    let coffer = memguard::Coffer::new().unwrap();
    let k1 = coffer.view().unwrap();
    let k2 = coffer.view().unwrap();
    assert_eq!(k1.as_slice(), k2.as_slice());
    memguard::pool_release(k1);
    memguard::pool_release(k2);
    coffer.destroy().unwrap();
}

// ──────────────────────────── memguard encrypt/decrypt ────────────────────────────

#[test]
fn memguard_encrypt_decrypt_roundtrip() {
    let key = [0xAA_u8; 32];
    let ct = memguard::encrypt(b"hello memguard", &key).unwrap();
    let mut output = vec![0_u8; 14];
    let n = memguard::decrypt(&ct, &key, &mut output).unwrap();
    assert_eq!(n, 14);
    assert_eq!(&output[..n], b"hello memguard");
}

#[test]
fn memguard_encrypt_wrong_key_size() {
    let result = memguard::encrypt(b"data", &[0_u8; 16]);
    assert!(result.is_err());
}

#[test]
fn memguard_decrypt_wrong_key_size() {
    let result = memguard::decrypt(&[0_u8; 100], &[0_u8; 16], &mut [0_u8; 100]);
    assert!(result.is_err());
}

#[test]
fn memguard_decrypt_too_short_ciphertext() {
    let key = [0xBB_u8; 32];
    let result = memguard::decrypt(&[0_u8; 10], &key, &mut [0_u8; 100]);
    assert!(result.is_err());
}

#[test]
fn memguard_decrypt_buffer_too_small() {
    let key = [0xCC_u8; 32];
    let ct = memguard::encrypt(b"some data here!", &key).unwrap();
    let mut output = vec![0_u8; 1]; // too small
    let result = memguard::decrypt(&ct, &key, &mut output);
    assert!(result.is_err());
}

#[test]
fn memguard_decrypt_wrong_key_fails() {
    let key1 = [0xAA_u8; 32];
    let key2 = [0xBB_u8; 32];
    let ct = memguard::encrypt(b"secret", &key1).unwrap();
    let mut output = vec![0_u8; 100];
    let result = memguard::decrypt(&ct, &key2, &mut output);
    assert!(result.is_err());
}

#[test]
fn memguard_overhead_constant() {
    assert_eq!(memguard::OVERHEAD, 28); // 12 nonce + 16 tag
}
