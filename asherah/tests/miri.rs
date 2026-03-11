//! Miri tests for unsafe code in asherah.
//!
//! Miri cannot run OS-level FFI (mmap, mlock, mprotect), so we test the pointer
//! arithmetic patterns from memguard.rs using heap-backed allocations that
//! replicate the same offset calculations and slice creation logic.
//!
//! Run with:
//!   cargo +nightly miri test --test miri
//!
//! Or via the project script:
//!   scripts/miri.sh

#![allow(unsafe_code, clippy::unwrap_used)]

use asherah::memguard::{ct_copy, ct_equal, ct_move, hash, wipe_bytes};

// ============================================================================
// Pure function tests (no FFI)
// ============================================================================

#[test]
fn miri_ct_copy_full() {
    let src = [1_u8, 2, 3, 4];
    let mut dst = [0_u8; 4];
    ct_copy(&mut dst, &src);
    assert_eq!(dst, [1, 2, 3, 4]);
}

#[test]
fn miri_ct_copy_dst_larger() {
    let src = [0xAA_u8, 0xBB];
    let mut dst = [0_u8; 4];
    ct_copy(&mut dst, &src);
    assert_eq!(dst, [0xAA, 0xBB, 0, 0]);
}

#[test]
fn miri_ct_copy_src_larger() {
    let src = [1_u8, 2, 3, 4];
    let mut dst = [0_u8; 2];
    ct_copy(&mut dst, &src);
    assert_eq!(dst, [1, 2]);
}

#[test]
fn miri_ct_copy_empty() {
    let src: [u8; 0] = [];
    let mut dst: [u8; 0] = [];
    ct_copy(&mut dst, &src);
}

#[test]
fn miri_ct_move_wipes_source() {
    let mut src = [0xDE_u8, 0xAD, 0xBE, 0xEF];
    let mut dst = [0_u8; 4];
    ct_move(&mut dst, &mut src);
    assert_eq!(dst, [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(src, [0, 0, 0, 0]);
}

#[test]
fn miri_ct_equal_same() {
    assert!(ct_equal(&[1, 2, 3], &[1, 2, 3]));
}

#[test]
fn miri_ct_equal_different() {
    assert!(!ct_equal(&[1, 2, 3], &[1, 2, 4]));
}

#[test]
fn miri_ct_equal_different_lengths() {
    assert!(!ct_equal(&[1, 2, 3], &[1, 2]));
}

#[test]
fn miri_ct_equal_empty() {
    assert!(ct_equal(&[], &[]));
}

#[test]
fn miri_wipe_bytes_zeros() {
    let mut buf = [0xFF_u8; 64];
    wipe_bytes(&mut buf);
    assert!(buf.iter().all(|&b| b == 0));
}

#[test]
fn miri_wipe_bytes_empty() {
    let mut buf: [u8; 0] = [];
    wipe_bytes(&mut buf);
}

#[test]
fn miri_hash_deterministic() {
    let data = b"test data for hashing";
    let h1 = hash(data);
    let h2 = hash(data);
    assert_eq!(h1, h2);
}

#[test]
fn miri_hash_different_inputs() {
    let h1 = hash(b"input A");
    let h2 = hash(b"input B");
    assert_ne!(h1, h2);
}

#[test]
fn miri_hash_empty() {
    let h = hash(b"");
    assert_eq!(h.len(), 32);
    assert!(h.iter().any(|&b| b != 0));
}

// ============================================================================
// Simulated buffer pointer arithmetic (replicating memguard.rs patterns)
//
// These tests exercise the exact offset calculations used in Buffer::new(),
// SlabPool, and HotKeyCache, but using Vec-backed memory so Miri can verify
// there's no UB in the pointer math.
// ============================================================================

const SLOT_SIZE: usize = 32;

/// Simulates the Buffer::new() layout: [guard_page | canary | data | guard_page]
/// Tests the offset arithmetic used to locate data within the allocation.
#[test]
fn miri_buffer_layout_offsets() {
    let page_size: usize = 4096;
    let data_size: usize = 48; // arbitrary, not page-aligned

    let inner_len = (data_size + (page_size - 1)) & !(page_size - 1); // round up
    assert_eq!(inner_len, page_size); // 48 rounds up to 4096

    let total = 2 * page_size + inner_len;
    let mut mem = vec![0_u8; total];
    let base = mem.as_mut_ptr();

    // These are the exact pointer calculations from Buffer::new()
    let pre_ptr = base;
    let inner_ptr = unsafe { base.add(page_size) };
    let post_ptr = unsafe { inner_ptr.add(inner_len) };
    let data_off = page_size + inner_len - data_size;
    let data_ptr = unsafe { base.add(data_off) };
    let canary_len = inner_len - data_size;

    // Verify all pointers are within bounds
    assert_eq!(unsafe { pre_ptr.offset_from(base) }, 0);
    assert_eq!(unsafe { inner_ptr.offset_from(base) }, page_size as isize);
    assert_eq!(
        unsafe { post_ptr.offset_from(base) },
        (page_size + inner_len) as isize
    );
    assert_eq!(unsafe { data_ptr.offset_from(base) }, data_off as isize);

    // Write canary into the canary region (between inner_ptr and data_ptr)
    if canary_len > 0 {
        let canary = unsafe { std::slice::from_raw_parts_mut(inner_ptr, canary_len) };
        for (i, b) in canary.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }

        // Copy canary pattern into guard pages (like Buffer::new does)
        let pre_s = unsafe { std::slice::from_raw_parts_mut(pre_ptr, page_size) };
        let post_s = unsafe { std::slice::from_raw_parts_mut(post_ptr, page_size) };
        for (idx, slot) in pre_s.iter_mut().enumerate() {
            *slot = canary[idx % canary_len];
        }
        for (idx, slot) in post_s.iter_mut().enumerate() {
            *slot = canary[idx % canary_len];
        }
    }

    // Write to data region
    let data = unsafe { std::slice::from_raw_parts_mut(data_ptr, data_size) };
    for (i, b) in data.iter_mut().enumerate() {
        *b = 0xAA ^ (i as u8);
    }

    // Read back and verify
    let data_read = unsafe { std::slice::from_raw_parts(data_ptr, data_size) };
    for (i, &b) in data_read.iter().enumerate() {
        assert_eq!(b, 0xAA ^ (i as u8));
    }

    // Verify canary integrity (like Buffer::destroy does)
    if canary_len > 0 {
        let can = unsafe { std::slice::from_raw_parts(inner_ptr, canary_len) };
        let pre = unsafe { std::slice::from_raw_parts(pre_ptr, page_size) };
        let post = unsafe { std::slice::from_raw_parts(post_ptr, page_size) };
        for i in 0..page_size {
            let exp = can[i % canary_len];
            assert_eq!(pre[i], exp, "pre-guard canary mismatch at {i}");
            assert_eq!(post[i], exp, "post-guard canary mismatch at {i}");
        }
    }
}

/// Simulates the exact same data_size == inner_len case (page-aligned allocation)
/// where canary_len is 0 and data_ptr == inner_ptr.
#[test]
fn miri_buffer_layout_page_aligned() {
    let page_size: usize = 4096;
    let data_size = page_size; // exactly one page

    let inner_len = (data_size + (page_size - 1)) & !(page_size - 1);
    assert_eq!(inner_len, page_size);

    let total = 2 * page_size + inner_len;
    let mut mem = vec![0_u8; total];
    let base = mem.as_mut_ptr();

    let data_off = page_size + inner_len - data_size;
    let data_ptr = unsafe { base.add(data_off) };
    let inner_ptr = unsafe { base.add(page_size) };
    let canary_len = inner_len - data_size;

    // When data_size == inner_len, data_ptr should equal inner_ptr
    assert_eq!(canary_len, 0);
    assert_eq!(data_ptr, inner_ptr);

    // Write and read the full data region
    let data = unsafe { std::slice::from_raw_parts_mut(data_ptr, data_size) };
    data.fill(0xCC);
    let readback = unsafe { std::slice::from_raw_parts(data_ptr, data_size) };
    assert!(readback.iter().all(|&b| b == 0xCC));
}

/// Simulates slab pool slot pointer arithmetic.
/// A slab page is divided into SLOT_SIZE chunks; tests that slot access
/// doesn't overlap or go out of bounds.
#[test]
fn miri_slab_pool_slot_arithmetic() {
    let page_size: usize = 4096;
    let slot_count = page_size / SLOT_SIZE;
    let mut page = vec![0_u8; page_size];
    let base = page.as_mut_ptr();

    // Write unique data to each slot (like grow_pool_unlocked + usage)
    for i in 0..slot_count {
        let ptr = unsafe { base.add(i * SLOT_SIZE) };
        let slot = unsafe { std::slice::from_raw_parts_mut(ptr, SLOT_SIZE) };
        slot.fill(i as u8);
    }

    // Read back and verify no overlaps
    for i in 0..slot_count {
        let ptr = unsafe { base.add(i * SLOT_SIZE) };
        let slot = unsafe { std::slice::from_raw_parts(ptr, SLOT_SIZE) };
        assert!(slot.iter().all(|&b| b == i as u8), "slot {i} corrupted");
    }

    // Wipe a slot (like pool_release does)
    let wipe_idx = slot_count / 2;
    let wipe_ptr = unsafe { base.add(wipe_idx * SLOT_SIZE) };
    let wipe_slot = unsafe { std::slice::from_raw_parts_mut(wipe_ptr, SLOT_SIZE) };
    wipe_bytes(wipe_slot);
    assert!(wipe_slot.iter().all(|&b| b == 0));

    // Verify adjacent slots are untouched
    if wipe_idx > 0 {
        let prev_ptr = unsafe { base.add((wipe_idx - 1) * SLOT_SIZE) };
        let prev = unsafe { std::slice::from_raw_parts(prev_ptr, SLOT_SIZE) };
        assert!(prev.iter().all(|&b| b == (wipe_idx - 1) as u8));
    }
    let next_ptr = unsafe { base.add((wipe_idx + 1) * SLOT_SIZE) };
    let next = unsafe { std::slice::from_raw_parts(next_ptr, SLOT_SIZE) };
    assert!(next.iter().all(|&b| b == (wipe_idx + 1) as u8));
}

/// Simulates hot cache pointer arithmetic: insert, get, LRU eviction.
/// Uses the same base_ptr + slot_idx * SLOT_SIZE pattern as HotKeyCache.
#[test]
fn miri_hot_cache_pointer_arithmetic() {
    let page_size: usize = 4096;
    let slot_count = page_size / SLOT_SIZE;
    let mut page = vec![0_u8; page_size];
    let base_ptr = page.as_mut_ptr();

    // Simulate insert: write plaintext into slot
    let test_key = [0xAB_u8; SLOT_SIZE];
    let slot_idx = 5;
    let ptr = unsafe { base_ptr.add(slot_idx * SLOT_SIZE) };
    let dst = unsafe { std::slice::from_raw_parts_mut(ptr, SLOT_SIZE) };
    dst.copy_from_slice(&test_key);

    // Simulate get: read from slot via const pointer
    let read_ptr = ptr as *const u8;
    let src = unsafe { std::slice::from_raw_parts(read_ptr, SLOT_SIZE) };
    assert_eq!(src, &test_key);

    // Simulate LRU eviction: wipe slot
    let evict_idx = slot_idx;
    let evict_ptr = unsafe { base_ptr.add(evict_idx * SLOT_SIZE) };
    let evict_slice = unsafe { std::slice::from_raw_parts_mut(evict_ptr, SLOT_SIZE) };
    wipe_bytes(evict_slice);
    assert!(evict_slice.iter().all(|&b| b == 0));

    // Fill all slots, then verify last slot boundary
    for i in 0..slot_count {
        let p = unsafe { base_ptr.add(i * SLOT_SIZE) };
        let s = unsafe { std::slice::from_raw_parts_mut(p, SLOT_SIZE) };
        s.fill((i & 0xFF) as u8);
    }
    // Verify last slot
    let last_ptr = unsafe { base_ptr.add((slot_count - 1) * SLOT_SIZE) };
    let last = unsafe { std::slice::from_raw_parts(last_ptr, SLOT_SIZE) };
    assert!(last.iter().all(|&b| b == ((slot_count - 1) & 0xFF) as u8));
}

/// Simulates the Coffer XOR-split pattern: key = left XOR hash(right).
/// Tests that the reconstitution logic works correctly.
#[test]
fn miri_coffer_xor_split_roundtrip() {
    let mut left = [0_u8; 32];
    let mut right = [0_u8; 32];

    // Fill with deterministic "random" data
    for (i, b) in left.iter_mut().enumerate() {
        *b = (i * 7 + 13) as u8;
    }
    for (i, b) in right.iter_mut().enumerate() {
        *b = (i * 11 + 37) as u8;
    }

    // XOR left with hash(right) — this is what init() does
    let hr = hash(&right);
    for (slot, hash_byte) in left.iter_mut().zip(hr.iter()) {
        *slot ^= hash_byte;
    }

    // Simulate Coffer::view() — reconstitute key
    let mut key = [0_u8; 32];
    let h = hash(&right);
    for (dst, (hash_byte, left_byte)) in key.iter_mut().zip(h.iter().zip(left.iter())) {
        *dst = hash_byte ^ left_byte;
    }

    // The reconstituted key should match the original pre-XOR left values
    for (i, &b) in key.iter().enumerate() {
        assert_eq!(b, (i * 7 + 13) as u8, "key mismatch at index {i}");
    }
}

// ============================================================================
// Cobhan buffer pointer arithmetic (simulated)
// These replicate the exact patterns from asherah-cobhan unsafe functions.
// ============================================================================

const BUFFER_HEADER_SIZE: usize = 8;

/// Simulates cobhan_buffer_get/set_length, cobhan_buffer_to_bytes, and
/// cobhan_bytes_to_buffer pointer operations.
#[test]
fn miri_cobhan_buffer_roundtrip() {
    let data = b"hello miri";
    let capacity = data.len() as i32;
    let total = BUFFER_HEADER_SIZE + data.len();
    let mut buf = vec![0_u8; total];

    // Write capacity (simulates buffer initialization)
    let cap_bytes = capacity.to_le_bytes();
    buf[..4].copy_from_slice(&cap_bytes);

    // Simulate cobhan_bytes_to_buffer: write data at header offset
    let buf_ptr = buf.as_mut_ptr();
    let data_ptr = unsafe { buf_ptr.add(BUFFER_HEADER_SIZE) };
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data.len());
    }

    // Update length
    let len_bytes = (data.len() as i32).to_le_bytes();
    buf[..4].copy_from_slice(&len_bytes);

    // Simulate cobhan_buffer_to_bytes: read length, create slice
    let len = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    assert_eq!(len, data.len() as i32);

    let read_ptr = unsafe { buf.as_ptr().add(BUFFER_HEADER_SIZE) };
    let slice = unsafe { std::slice::from_raw_parts(read_ptr, len as usize) };
    assert_eq!(slice, data);
}

/// Tests cobhan_int32_to_buffer and cobhan_int64_to_buffer patterns.
#[test]
fn miri_cobhan_int_buffer_writes() {
    // i32 write (like cobhan_int32_to_buffer)
    let mut buf = [0_u8; 8];
    let value: i32 = -42;
    let bytes = value.to_le_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.as_mut_ptr(), 4);
    }
    let readback = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    assert_eq!(readback, -42);

    // i64 write (like cobhan_int64_to_buffer)
    let mut buf64 = [0_u8; 8];
    let value64: i64 = i64::MAX;
    let bytes64 = value64.to_le_bytes();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes64.as_ptr(), buf64.as_mut_ptr(), 8);
    }
    let readback64 = i64::from_le_bytes(buf64);
    assert_eq!(readback64, i64::MAX);
}

/// Tests multiple cobhan buffers with different capacities and data,
/// simulating the Encrypt function which reads/writes multiple buffers.
#[test]
fn miri_cobhan_multi_buffer_ops() {
    let sizes = [16_usize, 64, 256];
    let mut buffers: Vec<Vec<u8>> = sizes
        .iter()
        .map(|&s| {
            let mut buf = vec![0_u8; BUFFER_HEADER_SIZE + s];
            let cap = (s as i32).to_le_bytes();
            buf[..4].copy_from_slice(&cap);
            buf
        })
        .collect();

    // Write different data to each
    for (i, buf) in buffers.iter_mut().enumerate() {
        let data_len = sizes[i];
        let data: Vec<u8> = (0..data_len).map(|j| (i * 37 + j) as u8).collect();

        let buf_ptr = buf.as_mut_ptr();
        let data_ptr = unsafe { buf_ptr.add(BUFFER_HEADER_SIZE) };
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), data_ptr, data.len());
        }
        let len = (data_len as i32).to_le_bytes();
        buf[..4].copy_from_slice(&len);
    }

    // Read back and verify
    for (i, buf) in buffers.iter().enumerate() {
        let len = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        assert_eq!(len, sizes[i]);
        let read_ptr = unsafe { buf.as_ptr().add(BUFFER_HEADER_SIZE) };
        let slice = unsafe { std::slice::from_raw_parts(read_ptr, len) };
        for (j, &b) in slice.iter().enumerate() {
            assert_eq!(b, (i * 37 + j) as u8, "buf {i} byte {j} mismatch");
        }
    }
}

// ============================================================================
// PoolSlot simulation — tests the unsafe Send impl is sound
// ============================================================================

/// Simulates PoolSlot being sent across threads (testing Send safety).
/// Wraps the raw pointer in a Send-able wrapper to mirror what PoolSlot does
/// with `unsafe impl Send`.
#[test]
fn miri_pool_slot_send_across_threads() {
    struct SendSlot {
        ptr: *mut u8,
        len: usize,
    }
    // This mirrors the `unsafe impl Send for PoolSlot` in memguard.rs
    unsafe impl Send for SendSlot {}

    let mut data = vec![0xFF_u8; SLOT_SIZE];
    let slot = SendSlot {
        ptr: data.as_mut_ptr(),
        len: SLOT_SIZE,
    };

    let handle = std::thread::spawn(move || {
        let bytes = unsafe { std::slice::from_raw_parts_mut(slot.ptr, slot.len) };
        bytes.fill(0xAA);
        assert!(bytes.iter().all(|&b| b == 0xAA));
        slot // return ownership
    });

    let returned = handle.join().unwrap();
    // Verify the write is visible in the original allocation
    assert_eq!(returned.ptr, data.as_mut_ptr());
    assert!(data.iter().all(|&b| b == 0xAA));
}
