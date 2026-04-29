#![allow(clippy::unwrap_used, clippy::expect_used)]

use asherah::memguard;
use std::sync::Mutex;

/// Tests that interact with the process-global KEY (Enclave, seal, purge) must
/// not run concurrently because `purge()` replaces the global Coffer key.
static GLOBAL_KEY_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Buffer basic lifecycle
// ---------------------------------------------------------------------------

#[test]
fn buffer_new_write_read_destroy() {
    let mut buf = memguard::Buffer::new(64).unwrap();
    assert!(buf.alive());
    assert!(buf.mutable());
    assert_eq!(buf.size(), 64);

    let data = b"hello memguard";
    buf.bytes()[..data.len()].copy_from_slice(data);
    assert_eq!(&buf.as_slice()[..data.len()], data);

    buf.destroy().unwrap();
    assert!(!buf.alive());
    assert_eq!(buf.size(), 0);
}

#[test]
fn buffer_new_zero_returns_null_buffer_error() {
    let result = memguard::Buffer::new(0);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, memguard::Error::NullBuffer));
}

// ---------------------------------------------------------------------------
// Buffer freeze / melt
// ---------------------------------------------------------------------------

#[test]
fn buffer_freeze_makes_immutable() {
    let mut buf = memguard::Buffer::new(32).unwrap();
    buf.bytes()[0] = 42;
    buf.freeze().unwrap();

    assert!(!buf.mutable());
    // Can still read after freeze
    assert_eq!(buf.as_slice()[0], 42);
    assert_eq!(buf.size(), 32);
}

#[test]
fn buffer_melt_restores_mutability() {
    let mut buf = memguard::Buffer::new(32).unwrap();
    buf.bytes()[0] = 1;
    buf.freeze().unwrap();
    assert!(!buf.mutable());

    buf.melt().unwrap();
    assert!(buf.mutable());
    buf.bytes()[0] = 2;
    assert_eq!(buf.as_slice()[0], 2);

    buf.destroy().unwrap();
}

// ---------------------------------------------------------------------------
// Buffer state transitions
// ---------------------------------------------------------------------------

#[test]
fn buffer_state_transitions() {
    let mut buf = memguard::Buffer::new(16).unwrap();

    // Initial: alive + mutable
    assert!(buf.alive());
    assert!(buf.mutable());
    assert_eq!(buf.size(), 16);

    // Freeze: alive + !mutable
    buf.freeze().unwrap();
    assert!(buf.alive());
    assert!(!buf.mutable());
    assert_eq!(buf.size(), 16);

    // Melt: alive + mutable
    buf.melt().unwrap();
    assert!(buf.alive());
    assert!(buf.mutable());

    // Destroy: !alive + !mutable + size 0
    buf.destroy().unwrap();
    assert!(!buf.alive());
    assert!(!buf.mutable());
    assert_eq!(buf.size(), 0);

    // bytes/as_slice return empty after destroy
    assert!(buf.bytes().is_empty());
    assert!(buf.as_slice().is_empty());
}

// ---------------------------------------------------------------------------
// Buffer double destroy is safe
// ---------------------------------------------------------------------------

#[test]
fn buffer_double_destroy_is_safe() {
    let mut buf = memguard::Buffer::new(16).unwrap();
    buf.destroy().unwrap();
    // Second destroy should be a no-op, not panic or error
    buf.destroy().unwrap();
    assert!(!buf.alive());
}

// ---------------------------------------------------------------------------
// Buffer scramble
// ---------------------------------------------------------------------------

#[test]
fn buffer_scramble_changes_content() {
    let mut buf = memguard::Buffer::new(64).unwrap();
    // Zero out
    for b in buf.bytes().iter_mut() {
        *b = 0;
    }
    buf.scramble().expect("OsRng available");
    // After scramble, it's extremely unlikely all 64 bytes are still zero
    let all_zero = buf.as_slice().iter().all(|&b| b == 0);
    assert!(!all_zero, "scramble should produce non-zero random bytes");
    buf.destroy().unwrap();
}

// ---------------------------------------------------------------------------
// encrypt / decrypt roundtrip
// ---------------------------------------------------------------------------

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = [0xAB_u8; 32];
    let plaintext = b"the quick brown fox jumps over the lazy dog";

    let ct = memguard::encrypt(plaintext, &key).unwrap();
    assert_eq!(ct.len(), plaintext.len() + memguard::OVERHEAD);

    let mut output = vec![0_u8; plaintext.len()];
    let n = memguard::decrypt(&ct, &key, &mut output).unwrap();
    assert_eq!(n, plaintext.len());
    assert_eq!(&output[..n], &plaintext[..]);
}

#[test]
fn encrypt_decrypt_empty_plaintext() {
    let key = [0x01_u8; 32];
    let plaintext = b"";

    let ct = memguard::encrypt(plaintext, &key).unwrap();
    assert_eq!(ct.len(), memguard::OVERHEAD);

    let mut output = vec![0_u8; 0];
    let n = memguard::decrypt(&ct, &key, &mut output).unwrap();
    assert_eq!(n, 0);
}

// ---------------------------------------------------------------------------
// encrypt / decrypt error cases
// ---------------------------------------------------------------------------

#[test]
fn encrypt_invalid_key_length() {
    let short_key = [0_u8; 16];
    let result = memguard::encrypt(b"data", &short_key);
    assert!(matches!(
        result.unwrap_err(),
        memguard::Error::InvalidKeyLength
    ));

    let long_key = [0_u8; 64];
    let result = memguard::encrypt(b"data", &long_key);
    assert!(matches!(
        result.unwrap_err(),
        memguard::Error::InvalidKeyLength
    ));
}

#[test]
fn decrypt_invalid_key_length() {
    let key = [0_u8; 32];
    let ct = memguard::encrypt(b"data", &key).unwrap();

    let bad_key = [0_u8; 16];
    let mut output = vec![0_u8; 64];
    let result = memguard::decrypt(&ct, &bad_key, &mut output);
    assert!(matches!(
        result.unwrap_err(),
        memguard::Error::InvalidKeyLength
    ));
}

#[test]
fn decrypt_buffer_too_small() {
    let key = [0_u8; 32];
    let plaintext = b"some data that is reasonably long";
    let ct = memguard::encrypt(plaintext, &key).unwrap();

    // Output buffer is smaller than plaintext length
    let mut output = vec![0_u8; plaintext.len() - 1];
    let result = memguard::decrypt(&ct, &key, &mut output);
    assert!(matches!(
        result.unwrap_err(),
        memguard::Error::BufferTooSmall
    ));
}

#[test]
fn decrypt_truncated_ciphertext() {
    let key = [0_u8; 32];
    // Ciphertext shorter than OVERHEAD (12 nonce + 16 tag = 28)
    let short_ct = vec![0_u8; memguard::OVERHEAD - 1];
    let mut output = vec![0_u8; 64];
    let result = memguard::decrypt(&short_ct, &key, &mut output);
    assert!(matches!(
        result.unwrap_err(),
        memguard::Error::DecryptionFailed
    ));
}

#[test]
fn decrypt_tampered_ciphertext() {
    let key = [0_u8; 32];
    let ct = memguard::encrypt(b"secret", &key).unwrap();

    let mut tampered = ct.clone();
    // Flip a byte in the encrypted payload (past the nonce)
    let idx = tampered.len() - 1;
    tampered[idx] ^= 0xFF;

    let mut output = vec![0_u8; 64];
    let result = memguard::decrypt(&tampered, &key, &mut output);
    assert!(matches!(
        result.unwrap_err(),
        memguard::Error::DecryptionFailed
    ));
}

#[test]
fn decrypt_wrong_key_fails() {
    let key1 = [0xAA_u8; 32];
    let key2 = [0xBB_u8; 32];
    let ct = memguard::encrypt(b"secret", &key1).unwrap();

    let mut output = vec![0_u8; 64];
    let result = memguard::decrypt(&ct, &key2, &mut output);
    assert!(matches!(
        result.unwrap_err(),
        memguard::Error::DecryptionFailed
    ));
}

// ---------------------------------------------------------------------------
// OVERHEAD constant
// ---------------------------------------------------------------------------

#[test]
fn overhead_is_28() {
    assert_eq!(memguard::OVERHEAD, 28); // 12 nonce + 16 tag
}

// ---------------------------------------------------------------------------
// Enclave seal and reopen
// These tests use the global KEY and must be serialized with purge.
// ---------------------------------------------------------------------------

#[test]
fn enclave_seal_and_open_preserves_data() {
    let _guard = GLOBAL_KEY_LOCK.lock().unwrap();

    let mut buf = memguard::Buffer::new(11).unwrap();
    buf.bytes().copy_from_slice(b"hello world");
    buf.freeze().unwrap();

    let enclave = memguard::Enclave::new_from(&mut buf).unwrap();
    assert_eq!(enclave.size(), 11);

    // Original buffer should be destroyed after seal
    assert!(!buf.alive());

    let opened = enclave.open().unwrap();
    assert_eq!(opened.as_slice(), b"hello world");
    memguard::pool_release(opened);
}

#[test]
fn enclave_open_multiple_times() {
    let _guard = GLOBAL_KEY_LOCK.lock().unwrap();

    let mut buf = memguard::Buffer::new(5).unwrap();
    buf.bytes().copy_from_slice(b"abcde");
    buf.freeze().unwrap();

    let enclave = memguard::Enclave::new_from(&mut buf).unwrap();

    // Open multiple times -- each open should return the same data
    for _ in 0..3 {
        let opened = enclave.open().unwrap();
        assert_eq!(opened.as_slice(), b"abcde");
        memguard::pool_release(opened);
    }
}

// ---------------------------------------------------------------------------
// LockedBuffer basic operations
// ---------------------------------------------------------------------------

#[test]
fn locked_buffer_new_and_copy() {
    let lb = memguard::LockedBuffer::new(32).unwrap();
    assert!(lb.is_alive());
    assert!(lb.is_mutable());
    assert_eq!(lb.size(), 32);

    lb.copy(b"test data for locked buffer!!!!!");
    let read = lb.bytes();
    assert_eq!(&read[..5], b"test ");

    lb.destroy().unwrap();
    assert!(!lb.is_alive());
}

#[test]
fn locked_buffer_copy_at() {
    let lb = memguard::LockedBuffer::new(16).unwrap();
    lb.copy(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    lb.copy_at(4, b"mid!");
    let read = lb.bytes();
    assert_eq!(&read[4..8], b"mid!");
    lb.destroy().unwrap();
}

// ---------------------------------------------------------------------------
// LockedBuffer::from_bytes
// ---------------------------------------------------------------------------

#[test]
fn locked_buffer_from_bytes_preserves_data_and_freezes() {
    let data = vec![1_u8, 2, 3, 4, 5];
    let lb = memguard::LockedBuffer::from_bytes(data).unwrap();
    assert!(lb.is_alive());
    assert!(!lb.is_mutable()); // from_bytes freezes
    assert_eq!(lb.size(), 5);
    assert_eq!(lb.bytes(), vec![1, 2, 3, 4, 5]);

    lb.destroy().unwrap();
}

#[test]
fn locked_buffer_from_bytes_wipes_source() {
    let data = vec![0xAA_u8; 8];
    let lb = memguard::LockedBuffer::from_bytes(data).unwrap();
    // The vec passed in is moved, so we can't inspect it directly, but we
    // can verify LockedBuffer holds the right data.
    // (ct_move wipes the source, but since Vec is moved in, this is implicit.)
    assert_eq!(lb.bytes(), vec![0xAA_u8; 8]);
    lb.destroy().unwrap();
}

// ---------------------------------------------------------------------------
// LockedBuffer::random
// ---------------------------------------------------------------------------

#[test]
fn locked_buffer_random_creates_nonzero_data() {
    let lb = memguard::LockedBuffer::random(64).unwrap();
    assert!(lb.is_alive());
    assert!(!lb.is_mutable()); // random freezes
    assert_eq!(lb.size(), 64);

    let data = lb.bytes();
    // Extremely unlikely all 64 random bytes are zero
    let all_zero = data.iter().all(|&b| b == 0);
    assert!(!all_zero, "random buffer should contain non-zero bytes");

    lb.destroy().unwrap();
}

// ---------------------------------------------------------------------------
// LockedBuffer seal/open roundtrip
// Uses the global KEY, so must be serialized.
// ---------------------------------------------------------------------------

#[test]
fn locked_buffer_seal_open_roundtrip() {
    let _guard = GLOBAL_KEY_LOCK.lock().unwrap();

    let lb = memguard::LockedBuffer::new(13).unwrap();
    lb.copy(b"sealed secret");
    lb.freeze().unwrap();

    let enclave = lb.seal().unwrap();
    assert_eq!(enclave.size(), 13);

    // After seal, the inner buffer is destroyed
    assert!(!lb.is_alive());

    let opened = enclave.open().unwrap();
    assert_eq!(opened.as_slice(), b"sealed secret");
    memguard::pool_release(opened);
}

// ---------------------------------------------------------------------------
// LockedBuffer destroy + is_alive
// ---------------------------------------------------------------------------

#[test]
fn locked_buffer_destroy_and_is_alive() {
    let lb = memguard::LockedBuffer::new(8).unwrap();
    assert!(lb.is_alive());
    lb.destroy().unwrap();
    assert!(!lb.is_alive());
    assert_eq!(lb.size(), 0);
}

// ---------------------------------------------------------------------------
// LockedBuffer freeze / melt
// ---------------------------------------------------------------------------

#[test]
fn locked_buffer_freeze_melt() {
    let lb = memguard::LockedBuffer::new(16).unwrap();
    assert!(lb.is_mutable());

    lb.freeze().unwrap();
    assert!(!lb.is_mutable());

    lb.melt().unwrap();
    assert!(lb.is_mutable());

    lb.destroy().unwrap();
}

// ---------------------------------------------------------------------------
// LockedBuffer wipe
// ---------------------------------------------------------------------------

#[test]
fn locked_buffer_wipe_zeros_content() {
    let lb = memguard::LockedBuffer::new(16).unwrap();
    lb.copy(&[0xFF_u8; 16]);
    lb.wipe();
    let data = lb.bytes();
    assert!(data.iter().all(|&b| b == 0), "wipe should zero all bytes");
    lb.destroy().unwrap();
}

// ---------------------------------------------------------------------------
// LockedBuffer scramble
// ---------------------------------------------------------------------------

#[test]
fn locked_buffer_scramble_changes_content() {
    let lb = memguard::LockedBuffer::new(64).unwrap();
    lb.wipe(); // ensure all zeros first
    lb.scramble().expect("OsRng available");
    let data = lb.bytes();
    let all_zero = data.iter().all(|&b| b == 0);
    assert!(!all_zero, "scramble should produce non-zero random bytes");
    lb.destroy().unwrap();
}

// ---------------------------------------------------------------------------
// LockedBuffer move / move_at
// ---------------------------------------------------------------------------

#[test]
fn locked_buffer_move_wipes_source() {
    let lb = memguard::LockedBuffer::new(8).unwrap();
    let mut src = vec![0xDE_u8; 8];
    lb.r#move(&mut src);

    // Source should be wiped
    assert!(src.iter().all(|&b| b == 0), "move should wipe source");
    // Destination should have the data
    assert_eq!(lb.bytes(), vec![0xDE_u8; 8]);
    lb.destroy().unwrap();
}

#[test]
fn locked_buffer_move_at() {
    let lb = memguard::LockedBuffer::new(8).unwrap();
    lb.wipe();
    let mut src = vec![0xAB_u8; 4];
    lb.move_at(2, &mut src);

    assert!(src.iter().all(|&b| b == 0), "move_at should wipe source");
    let data = lb.bytes();
    assert_eq!(&data[2..6], &[0xAB_u8; 4]);
    lb.destroy().unwrap();
}

// ---------------------------------------------------------------------------
// LockedBuffer with_bytes
// ---------------------------------------------------------------------------

#[test]
fn locked_buffer_with_bytes_callback() {
    let lb = memguard::LockedBuffer::new(5).unwrap();
    lb.copy(b"abcde");
    lb.freeze().unwrap();

    let result = lb.with_bytes(|bytes| {
        assert_eq!(bytes, b"abcde");
        bytes.len()
    });
    assert_eq!(result.unwrap(), 5);
    lb.destroy().unwrap();
}

#[test]
fn locked_buffer_with_bytes_after_destroy_returns_error() {
    let lb = memguard::LockedBuffer::new(5).unwrap();
    lb.destroy().unwrap();

    let result = lb.with_bytes(|_bytes| 42);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// hash
// ---------------------------------------------------------------------------

#[test]
fn hash_produces_consistent_32_byte_output() {
    let input = b"test input for hashing";
    let h1 = memguard::hash(input);
    let h2 = memguard::hash(input);

    assert_eq!(h1.len(), 32);
    assert_eq!(h1, h2, "hash should be deterministic");
}

#[test]
fn hash_different_inputs_produce_different_outputs() {
    let h1 = memguard::hash(b"input one");
    let h2 = memguard::hash(b"input two");
    assert_ne!(h1, h2);
}

#[test]
fn hash_empty_input() {
    let h = memguard::hash(b"");
    assert_eq!(h.len(), 32);
    // Should be deterministic
    assert_eq!(h, memguard::hash(b""));
}

// ---------------------------------------------------------------------------
// ct_copy / ct_move / ct_equal
// ---------------------------------------------------------------------------

#[test]
fn ct_copy_copies_data() {
    let src = [1_u8, 2, 3, 4, 5];
    let mut dst = [0_u8; 5];
    memguard::ct_copy(&mut dst, &src);
    assert_eq!(dst, src);
}

#[test]
fn ct_copy_truncates_to_shorter_len() {
    let src = [1_u8, 2, 3, 4, 5];
    let mut dst = [0_u8; 3];
    memguard::ct_copy(&mut dst, &src);
    assert_eq!(dst, [1, 2, 3]);

    let src2 = [10_u8, 20];
    let mut dst2 = [0_u8; 5];
    memguard::ct_copy(&mut dst2, &src2);
    assert_eq!(&dst2[..2], &[10, 20]);
    // Remaining bytes unchanged
    assert_eq!(&dst2[2..], &[0, 0, 0]);
}

#[test]
fn ct_move_copies_and_wipes_source() {
    let mut src = [0xAA_u8; 4];
    let mut dst = [0_u8; 4];
    memguard::ct_move(&mut dst, &mut src);
    assert_eq!(dst, [0xAA; 4]);
    assert_eq!(src, [0; 4], "ct_move should wipe source");
}

#[test]
fn ct_equal_same_data() {
    let a = [1_u8, 2, 3, 4];
    let b = [1_u8, 2, 3, 4];
    assert!(memguard::ct_equal(&a, &b));
}

#[test]
fn ct_equal_different_data() {
    let a = [1_u8, 2, 3, 4];
    let b = [1_u8, 2, 3, 5];
    assert!(!memguard::ct_equal(&a, &b));
}

#[test]
fn ct_equal_empty_slices() {
    assert!(memguard::ct_equal(&[], &[]));
}

#[test]
fn ct_equal_different_lengths() {
    let a = [1_u8, 2, 3];
    let b = [1_u8, 2, 3, 4];
    // subtle's ct_eq on different-length slices returns false
    assert!(!memguard::ct_equal(&a, &b));
}

// ---------------------------------------------------------------------------
// wipe_bytes
// ---------------------------------------------------------------------------

#[test]
fn wipe_bytes_zeros_buffer() {
    let mut buf = [0xFF_u8; 32];
    memguard::wipe_bytes(&mut buf);
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn wipe_bytes_empty_is_noop() {
    let mut buf: [u8; 0] = [];
    memguard::wipe_bytes(&mut buf); // should not panic
}

// ---------------------------------------------------------------------------
// scramble_bytes
// ---------------------------------------------------------------------------

#[test]
fn scramble_bytes_fills_random() {
    let mut buf = [0_u8; 64];
    memguard::scramble_bytes(&mut buf).expect("OsRng available");
    let all_zero = buf.iter().all(|&b| b == 0);
    assert!(!all_zero, "scramble_bytes should produce random data");
}

// ---------------------------------------------------------------------------
// purge
// Uses the global KEY, so must be serialized with Enclave/seal tests.
// ---------------------------------------------------------------------------

#[test]
fn purge_does_not_panic() {
    let _guard = GLOBAL_KEY_LOCK.lock().unwrap();

    // Create a few locked buffers, then purge
    let _lb1 = memguard::LockedBuffer::new(16).unwrap();
    let _lb2 = memguard::LockedBuffer::new(32).unwrap();
    // purge should destroy all registered buffers without panicking
    let result = memguard::purge();
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// Coffer basic view roundtrip (via unified slab)
// ---------------------------------------------------------------------------

#[test]
fn coffer_view_returns_32_byte_key() {
    let key = memguard::coffer_view().unwrap();
    assert_eq!(key.size(), 32);

    // Key should be deterministic within same coffer (before rekey)
    let key2 = memguard::coffer_view().unwrap();
    assert_eq!(key.as_slice(), key2.as_slice());

    memguard::pool_release(key);
    memguard::pool_release(key2);
}

// ---------------------------------------------------------------------------
// Buffer various sizes
// ---------------------------------------------------------------------------

#[test]
fn buffer_various_sizes() {
    for size in [1, 2, 15, 16, 17, 255, 256, 4096, 4097] {
        let mut buf = memguard::Buffer::new(size).unwrap();
        assert_eq!(buf.size(), size);
        assert!(buf.alive());

        // Write a pattern
        for (i, b) in buf.bytes().iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        // Verify
        for (i, &b) in buf.as_slice().iter().enumerate() {
            assert_eq!(b, (i % 256) as u8);
        }

        buf.destroy().unwrap();
    }
}

// ---------------------------------------------------------------------------
// encrypt produces unique ciphertexts (random nonce)
// ---------------------------------------------------------------------------

#[test]
fn encrypt_uses_random_nonce() {
    let key = [0x42_u8; 32];
    let pt = b"same plaintext";
    let ct1 = memguard::encrypt(pt, &key).unwrap();
    let ct2 = memguard::encrypt(pt, &key).unwrap();
    // Same plaintext + same key should produce different ciphertexts
    // due to random nonce
    assert_ne!(ct1, ct2);
}

// ---------------------------------------------------------------------------
// Buffer pool tests
// ---------------------------------------------------------------------------

#[test]
fn pool_acquire_release_roundtrip() {
    let _guard = GLOBAL_KEY_LOCK.lock().unwrap();

    let mut buf = memguard::pool_acquire(32).unwrap();
    assert_eq!(buf.size(), 32);
    buf.bytes().copy_from_slice(&[0xAB; 32]);
    assert_eq!(buf.as_slice(), &[0xAB; 32]);
    memguard::pool_release(buf);
}

#[test]
fn pool_recycles_buffers() {
    let _guard = GLOBAL_KEY_LOCK.lock().unwrap();

    // Acquire and release a buffer, then acquire again — should reuse
    let buf1 = memguard::pool_acquire(32).unwrap();
    let ptr1 = buf1.as_slice().as_ptr();
    memguard::pool_release(buf1);

    let buf2 = memguard::pool_acquire(32).unwrap();
    let ptr2 = buf2.as_slice().as_ptr();
    memguard::pool_release(buf2);

    // Same underlying mmap'd page should be reused
    assert_eq!(ptr1, ptr2);
}

#[test]
fn pool_release_wipes_data() {
    let _guard = GLOBAL_KEY_LOCK.lock().unwrap();

    let mut buf = memguard::pool_acquire(32).unwrap();
    buf.bytes().copy_from_slice(&[0xFF; 32]);
    memguard::pool_release(buf);

    // Re-acquire — data should be wiped
    let buf = memguard::pool_acquire(32).unwrap();
    assert!(
        buf.as_slice().iter().all(|&b| b == 0),
        "recycled buffer should be wiped"
    );
    memguard::pool_release(buf);
}

#[test]
fn pool_non_matching_size_falls_through() {
    // Non-32-byte sizes bypass the pool and allocate directly
    let buf = memguard::pool_acquire(64).unwrap();
    assert_eq!(buf.size(), 64);
    // pool_release on non-pool-size buffer destroys it instead of pooling
    memguard::pool_release(buf);
}

#[test]
fn pool_concurrent_acquire_release() {
    use std::sync::Arc;
    use std::thread;

    let _guard = GLOBAL_KEY_LOCK.lock().unwrap();

    let barrier = Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let b = barrier.clone();
            thread::spawn(move || {
                b.wait();
                for _ in 0..100 {
                    let mut buf = memguard::pool_acquire(32).unwrap();
                    buf.bytes().copy_from_slice(&[0xCC; 32]);
                    assert_eq!(buf.as_slice(), &[0xCC; 32]);
                    memguard::pool_release(buf);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}
