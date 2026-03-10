#![allow(clippy::unwrap_used, clippy::expect_used, clippy::exit, unsafe_code)]
//! Tests that OS-level memory protection (mprotect, mlock, core dumps) actually
//! works on the current platform.

use asherah::memcall::{self, MemBuf, MemoryProtectionFlag};

// ──────────────────────── Protection transitions ────────────────────────

#[test]
fn protect_read_only_then_read_succeeds() {
    let mut buf = MemBuf::alloc(4096).unwrap();
    // Fill with 0xAA while RW
    for b in buf.as_mut_slice().iter_mut() {
        *b = 0xAA;
    }
    // Set read-only
    buf.protect(MemoryProtectionFlag::read_only()).unwrap();
    // Reading must succeed and return the data we wrote
    assert!(buf.as_slice().iter().all(|&b| b == 0xAA));
    // Restore RW so free/drop can wipe
    buf.protect(MemoryProtectionFlag::read_write()).unwrap();
    buf.free().unwrap();
}

#[test]
fn protect_transitions_preserve_data() {
    let mut buf = MemBuf::alloc(4096).unwrap();
    // Write a recognizable pattern
    for (i, b) in buf.as_mut_slice().iter_mut().enumerate() {
        *b = (i % 251) as u8; // prime mod to avoid trivial repeat at 256
    }

    // Cycle: read_write -> read_only -> no_access -> read_write
    buf.protect(MemoryProtectionFlag::read_only()).unwrap();
    buf.protect(MemoryProtectionFlag::no_access()).unwrap();
    buf.protect(MemoryProtectionFlag::read_write()).unwrap();

    // Data must survive the round-trip
    for (i, &b) in buf.as_slice().iter().enumerate() {
        assert_eq!(
            b,
            (i % 251) as u8,
            "byte {i} mutated during protection transitions"
        );
    }
    buf.free().unwrap();
}

// ──────────────────────── Lock / unlock ────────────────────────

#[test]
fn lock_prevents_swap_and_unlock_succeeds() {
    let mut buf = MemBuf::alloc(4096).unwrap();
    buf.lock().unwrap();
    // Write and read while locked
    buf.as_mut_slice()[0] = 0xDE;
    buf.as_mut_slice()[4095] = 0xAD;
    assert_eq!(buf.as_slice()[0], 0xDE);
    assert_eq!(buf.as_slice()[4095], 0xAD);
    buf.unlock().unwrap();
    // Data still intact after unlock
    assert_eq!(buf.as_slice()[0], 0xDE);
    assert_eq!(buf.as_slice()[4095], 0xAD);
    buf.free().unwrap();
}

// ──────────────────────── Fork-based signal tests (unix only) ────────────────────────

#[cfg(unix)]
#[test]
fn protect_no_access_on_child_process_segfaults() {
    let mut buf = MemBuf::alloc(4096).unwrap();
    // Write known data while RW
    buf.as_mut_slice()[0] = 0x42;
    // Set no_access
    buf.protect(MemoryProtectionFlag::no_access()).unwrap();

    let ptr = buf.as_ptr();

    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: attempt to read from no_access memory -> should SIGSEGV/SIGBUS
            let _byte = std::ptr::read_volatile(ptr);
            // Should never reach here
            std::process::exit(0);
        } else {
            // Parent: wait for child and verify it was killed by a signal
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);
            assert!(
                libc::WIFSIGNALED(status),
                "child should have been killed by signal, status={status}"
            );
            let sig = libc::WTERMSIG(status);
            assert!(
                sig == libc::SIGSEGV || sig == libc::SIGBUS,
                "expected SIGSEGV or SIGBUS, got {sig}"
            );
        }
    }

    // Restore RW so drop can clean up
    buf.protect(MemoryProtectionFlag::read_write()).unwrap();
    buf.free().unwrap();
}

#[cfg(unix)]
#[test]
fn protect_read_only_on_child_process_segfaults_on_write() {
    let mut buf = MemBuf::alloc(4096).unwrap();
    buf.as_mut_slice()[0] = 0x55;
    // Set read-only
    buf.protect(MemoryProtectionFlag::read_only()).unwrap();

    let ptr = buf.as_ptr() as *mut u8;

    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: attempt to write to read-only memory -> should SIGSEGV/SIGBUS
            std::ptr::write_volatile(ptr, 0xFF);
            // Should never reach here
            std::process::exit(0);
        } else {
            // Parent: wait for child and verify it was killed by a signal
            let mut status: i32 = 0;
            libc::waitpid(pid, &mut status, 0);
            assert!(
                libc::WIFSIGNALED(status),
                "child should have been killed by signal, status={status}"
            );
            let sig = libc::WTERMSIG(status);
            assert!(
                sig == libc::SIGSEGV || sig == libc::SIGBUS,
                "expected SIGSEGV or SIGBUS, got {sig}"
            );
        }
    }

    // Restore RW so drop can clean up
    buf.protect(MemoryProtectionFlag::read_write()).unwrap();
    buf.free().unwrap();
}

// ──────────────────────── Core dumps ────────────────────────

#[cfg(unix)]
#[test]
fn disable_core_dumps_zeroes_rlimit() {
    memcall::disable_core_dumps().unwrap();

    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        let rc = libc::getrlimit(libc::RLIMIT_CORE, &mut lim);
        assert_eq!(rc, 0, "getrlimit failed");
        assert_eq!(
            lim.rlim_cur, 0,
            "rlim_cur should be 0 after disable_core_dumps"
        );
        assert_eq!(
            lim.rlim_max, 0,
            "rlim_max should be 0 after disable_core_dumps"
        );
    }
}

// ──────────────────────── Zero-initialization ────────────────────────

#[test]
fn alloc_zero_initializes_memory() {
    let buf = MemBuf::alloc(4096).unwrap();
    assert!(
        buf.as_slice().iter().all(|&b| b == 0),
        "freshly allocated memory must be zero-initialized"
    );
    buf.free().unwrap();
}

// ──────────────────────── Re-alloc zero check ────────────────────────

#[test]
fn new_alloc_is_zero_after_prior_free() {
    // Alloc, fill with 0xFF, free, alloc again at same size, verify zeros.
    // mmap guarantees zero-fill for new pages.
    let mut buf = MemBuf::alloc(4096).unwrap();
    for b in buf.as_mut_slice().iter_mut() {
        *b = 0xFF;
    }
    buf.free().unwrap();

    let buf2 = MemBuf::alloc(4096).unwrap();
    assert!(
        buf2.as_slice().iter().all(|&b| b == 0),
        "newly allocated memory must be zero-initialized regardless of prior usage"
    );
    buf2.free().unwrap();
}

// ──────────────────────── Stress: alloc/free cycles ────────────────────────

#[test]
fn multiple_alloc_free_cycles() {
    for i in 0..100 {
        let mut buf = MemBuf::alloc(4096).unwrap();
        // Write a unique pattern per iteration
        let tag = (i & 0xFF) as u8;
        for b in buf.as_mut_slice().iter_mut() {
            *b = tag;
        }
        assert!(buf.as_slice().iter().all(|&b| b == tag));
        buf.free().unwrap();
    }
}
