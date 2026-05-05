// Embedded memcall (was memcall-rs)
//! Cross-platform wrappers for memory allocation with page protection controls,
//! locking, and core-dump behavior.

use core::ptr::NonNull;
use std::ffi::c_void;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryProtectionFlag {
    flag: u8,
}
impl MemoryProtectionFlag {
    pub fn no_access() -> Self {
        Self { flag: 1 }
    }
    pub fn read_only() -> Self {
        Self { flag: 2 }
    }
    pub fn read_write() -> Self {
        Self { flag: 6 }
    }
    #[cfg_attr(windows, allow(dead_code))]
    fn to_unix_prot(self) -> Result<i32, MemError> {
        #[cfg(not(windows))]
        {
            Ok(match self.flag {
                6 => libc::PROT_READ | libc::PROT_WRITE,
                2 => libc::PROT_READ,
                1 => libc::PROT_NONE,
                _ => return Err(MemError::InvalidFlag),
            })
        }
        #[cfg(windows)]
        {
            let _ = self;
            Err(MemError::InvalidFlag)
        }
    }
    #[cfg_attr(not(windows), allow(dead_code))]
    fn to_win_prot(self) -> Result<u32, MemError> {
        #[cfg(windows)]
        {
            Ok(match self.flag {
                6 => windows_sys::Win32::System::Memory::PAGE_READWRITE,
                2 => windows_sys::Win32::System::Memory::PAGE_READONLY,
                1 => windows_sys::Win32::System::Memory::PAGE_NOACCESS,
                _ => return Err(MemError::InvalidFlag),
            })
        }
        #[cfg(not(windows))]
        {
            let _ = self;
            Err(MemError::InvalidFlag)
        }
    }
}

pub const ERR_INVALID_FLAG: &str = "<memcall> memory protection flag is undefined";
#[derive(Debug)]
pub enum MemError {
    Sys(String),
    InvalidFlag,
}
impl std::fmt::Display for MemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemError::Sys(s) => write!(f, "{}", s),
            MemError::InvalidFlag => write!(f, "{}", ERR_INVALID_FLAG),
        }
    }
}
impl std::error::Error for MemError {}

#[derive(Debug)]
pub struct MemBuf {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: `MemBuf` exclusively owns the `ptr`/`len` region — `alloc`
// allocates and `Drop`/`free` deallocate. The struct exposes mutation only
// through `&mut self`, so an `&MemBuf` cannot mutate the buffer. Sending
// the buffer across threads transfers exclusive ownership of the bytes;
// sharing it (`&MemBuf`) only allows reads via `as_ptr` / `as_slice`,
// which never alias a concurrent write because there cannot be one
// without `&mut self`. Underlying `mlock`/`munlock`/`mprotect` syscalls
// are thread-safe by OS contract.
unsafe impl Send for MemBuf {}
unsafe impl Sync for MemBuf {}
impl MemBuf {
    pub fn alloc(len: usize) -> Result<Self, MemError> {
        Ok(Self {
            ptr: os::os_alloc(len)?,
            len,
        })
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr() as *const u8
    }
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.len) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.as_mut_ptr(), self.len) }
    }
    pub fn lock(&self) -> Result<(), MemError> {
        os::os_lock(self.ptr.as_ptr(), self.len)
    }
    pub fn unlock(&self) -> Result<(), MemError> {
        os::os_unlock(self.ptr.as_ptr(), self.len)
    }
    pub fn protect(&self, mpf: MemoryProtectionFlag) -> Result<(), MemError> {
        os::os_protect(self.ptr.as_ptr(), self.len, mpf)
    }
    pub fn free(mut self) -> Result<(), MemError> {
        // protect() may legitimately fail (e.g. the page is currently
        // PROT_NONE because of guard-page reuse). Skip the wipe in that
        // case — writing to a PROT_NONE page would segfault. The os_free
        // path itself reverts protections via munmap/VirtualFree. T17 in
        // docs/review-2026-05-05-findings.md.
        let protect_ok = self
            .protect(MemoryProtectionFlag::read_write())
            .inspect_err(|e| log::warn!("MemBuf::free: protect(rw) failed: {e}"))
            .is_ok();
        if protect_ok {
            wipe(self.as_mut_slice());
        }
        let result = os::os_free(self.ptr.as_ptr(), self.len);
        self.len = 0;
        result
    }
}
impl Drop for MemBuf {
    fn drop(&mut self) {
        if self.len == 0 {
            return;
        }
        // Same protect-before-wipe ordering as `free()`: skip the wipe if
        // the page can't be made writable, otherwise we'd segfault on a
        // PROT_NONE region.
        let protect_ok = self
            .protect(MemoryProtectionFlag::read_write())
            .inspect_err(|e| log::warn!("MemBuf::drop: protect(rw) failed: {e}"))
            .is_ok();
        if protect_ok {
            let s = unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) };
            wipe(s);
        }
        if let Err(e) = os::os_free(self.ptr.as_ptr(), self.len) {
            // Log free failures: an `os_free` error means we leaked a
            // mapping or VirtualFree'd a bogus address — silent loss
            // would mask either real bugs or RLIMIT/AS exhaustion.
            log::warn!("MemBuf::drop: os_free failed for {} bytes: {e}", self.len);
        }
        self.len = 0;
    }
}
fn wipe(buf: &mut [u8]) {
    // zeroize uses volatile writes plus a SeqCst compiler fence to prevent
    // dead-store elimination. This is the final wipe path called from
    // MemBuf::drop, where the optimizer can prove the memory is unreachable
    // after the call.
    use zeroize::Zeroize;
    buf.zeroize();
}
pub fn disable_core_dumps() -> Result<(), MemError> {
    os::os_disable_core_dumps()
}
/// # Safety
/// `ptr` must reference a valid allocation of at least `len` bytes obtained via this module.
pub unsafe fn protect_raw(
    ptr: *mut u8,
    len: usize,
    mpf: MemoryProtectionFlag,
) -> Result<(), MemError> {
    os::os_protect(ptr, len, mpf)
}
/// # Safety
/// `ptr` must reference a valid allocation of at least `len` bytes obtained via this module.
pub unsafe fn lock_raw(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    os::os_lock(ptr, len)
}
/// # Safety
/// `ptr` must reference a valid allocation of at least `len` bytes obtained via this module.
pub unsafe fn unlock_raw(ptr: *mut u8, len: usize) -> Result<(), MemError> {
    os::os_unlock(ptr, len)
}

mod os {
    use super::{c_void, MemError, MemoryProtectionFlag};
    use core::ptr::{self, NonNull};
    #[cfg(windows)]
    pub fn os_alloc(len: usize) -> Result<NonNull<u8>, MemError> {
        use windows_sys::Win32::System::Memory::{
            VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
        };
        let ptr = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                len,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE,
            )
        } as *mut u8;
        if ptr.is_null() {
            return Err(MemError::Sys("<memcall> could not allocate".into()));
        }
        unsafe { ptr::write_bytes(ptr, 0, len) };
        Ok(unsafe { NonNull::new_unchecked(ptr) })
    }
    #[cfg(not(windows))]
    pub fn os_alloc(len: usize) -> Result<NonNull<u8>, MemError> {
        #[cfg(any(
            target_os = "macos",
            target_os = "netbsd",
            target_os = "aix",
            target_os = "freebsd",
            target_os = "openbsd"
        ))]
        let map_anon = libc::MAP_ANON;
        #[cfg(not(any(
            target_os = "macos",
            target_os = "netbsd",
            target_os = "aix",
            target_os = "freebsd",
            target_os = "openbsd"
        )))]
        let map_anon = libc::MAP_ANONYMOUS;
        let flags = {
            #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
            {
                let mut f = libc::MAP_PRIVATE | map_anon;
                #[cfg(target_os = "freebsd")]
                {
                    f |= libc::MAP_NOCORE;
                }
                #[cfg(target_os = "openbsd")]
                {
                    f |= libc::MAP_CONCEAL;
                }
                f
            }
            #[cfg(not(any(target_os = "freebsd", target_os = "openbsd")))]
            {
                libc::MAP_PRIVATE | map_anon
            }
        };
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(MemError::Sys("<memcall> could not allocate".into()));
        }
        unsafe { ptr::write_bytes(ptr, 0, len) };
        Ok(unsafe { NonNull::new_unchecked(ptr.cast::<u8>()) })
    }
    #[cfg(windows)]
    pub fn os_free(ptr: *mut u8, _len: usize) -> Result<(), MemError> {
        use windows_sys::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
        let ok = unsafe { VirtualFree(ptr.cast::<c_void>(), 0, MEM_RELEASE) };
        if ok == 0 {
            return Err(MemError::Sys(format!(
                "<memcall> could not deallocate {ptr:p}"
            )));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    pub fn os_free(ptr: *mut u8, len: usize) -> Result<(), MemError> {
        let rc = unsafe { libc::munmap(ptr.cast::<c_void>(), len) };
        if rc != 0 {
            return Err(MemError::Sys(format!(
                "<memcall> could not deallocate {ptr:p}"
            )));
        }
        Ok(())
    }
    #[cfg(windows)]
    pub fn os_lock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
        use windows_sys::Win32::System::Memory::VirtualLock;
        let ok = unsafe { VirtualLock(ptr.cast::<c_void>(), len) };
        if ok == 0 {
            return Err(MemError::Sys(format!(
                "<memcall> could not acquire lock on {ptr:p}, limit reached?"
            )));
        }

        Ok(())
    }
    #[cfg(not(windows))]
    pub fn os_lock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
        // MADV_DONTDUMP / MADV_NOCORE excludes the region from core dumps.
        // Failure is non-fatal — secrets stay mlock'd either way — but a
        // silent ignore masks a tightened-seccomp deployment that *thinks*
        // it's getting core-dump exclusion when it isn't. Log debug so
        // operators with verbose logs can see it. T17 in
        // docs/review-2026-05-05-findings.md.
        #[cfg(target_os = "linux")]
        {
            let rc = unsafe { libc::madvise(ptr.cast::<c_void>(), len, libc::MADV_DONTDUMP) };
            if rc != 0 {
                let errno = std::io::Error::last_os_error();
                log::debug!(
                    "memcall: MADV_DONTDUMP failed on {ptr:p} len={len}: {errno}; \
                     core dumps may include locked memory"
                );
            }
        }
        #[cfg(target_os = "freebsd")]
        {
            let rc = unsafe { libc::madvise(ptr.cast::<c_void>(), len, libc::MADV_NOCORE) };
            if rc != 0 {
                let errno = std::io::Error::last_os_error();
                log::debug!(
                    "memcall: MADV_NOCORE failed on {ptr:p} len={len}: {errno}; \
                     core dumps may include locked memory"
                );
            }
        }
        let rc = unsafe { libc::mlock(ptr as *const c_void, len) };
        if rc != 0 {
            #[cfg(target_os = "aix")]
            if rc == libc::EPERM {
                return Err(MemError::Sys(format!(
                    "<memcall> could not acquire lock on {ptr:p}, do you have PV_ROOT?"
                )));
            }
            return Err(MemError::Sys(format!(
                "<memcall> could not acquire lock on {ptr:p}, limit reached?"
            )));
        }

        Ok(())
    }
    #[cfg(windows)]
    pub fn os_unlock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
        use windows_sys::Win32::System::Memory::VirtualUnlock;
        let ok = unsafe { VirtualUnlock(ptr.cast::<c_void>(), len) };
        if ok == 0 {
            return Err(MemError::Sys(format!(
                "<memcall> could not free lock on {ptr:p}"
            )));
        }

        Ok(())
    }
    #[cfg(not(windows))]
    pub fn os_unlock(ptr: *mut u8, len: usize) -> Result<(), MemError> {
        let rc = unsafe { libc::munlock(ptr as *const c_void, len) };
        if rc != 0 {
            #[cfg(target_os = "aix")]
            if rc == libc::EPERM {
                return Err(MemError::Sys(format!(
                    "<memcall> could not free lock on {ptr:p}, do you have PV_ROOT?"
                )));
            }
            return Err(MemError::Sys(format!(
                "<memcall> could not free lock on {ptr:p}"
            )));
        }

        Ok(())
    }
    #[cfg(windows)]
    pub fn os_protect(ptr: *mut u8, len: usize, mpf: MemoryProtectionFlag) -> Result<(), MemError> {
        use windows_sys::Win32::System::Memory::VirtualProtect;
        let prot = mpf.to_win_prot()?;
        let mut old: u32 = 0;
        let ok =
            unsafe { VirtualProtect(ptr.cast::<c_void>(), len, prot, std::ptr::addr_of_mut!(old)) };
        if ok == 0 {
            return Err(MemError::Sys(format!(
                "<memcall> could not set {prot} on {ptr:p}"
            )));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    pub fn os_protect(ptr: *mut u8, len: usize, mpf: MemoryProtectionFlag) -> Result<(), MemError> {
        let prot = mpf.to_unix_prot()?;
        let rc = unsafe { libc::mprotect(ptr.cast::<c_void>(), len, prot) };
        if rc != 0 {
            return Err(MemError::Sys(format!(
                "<memcall> could not set {prot} on {ptr:p}"
            )));
        }
        Ok(())
    }
    pub fn os_disable_core_dumps() -> Result<(), MemError> {
        #[cfg(windows)]
        {
            return Ok(());
        }
        #[cfg(not(windows))]
        unsafe {
            let lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            let rc = libc::setrlimit(libc::RLIMIT_CORE, &lim);
            if rc != 0 {
                return Err(MemError::Sys("<memcall> could not set rlimit".into()));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn membuf_alloc_and_free() {
        let buf = MemBuf::alloc(4096).unwrap();
        assert_eq!(buf.len(), 4096);
        assert!(!buf.is_empty());
        buf.free().unwrap();
    }

    #[test]
    fn membuf_read_write() {
        let mut buf = MemBuf::alloc(64).unwrap();
        let data = buf.as_mut_slice();
        data[0] = 0xAA;
        data[63] = 0xBB;
        assert_eq!(buf.as_slice()[0], 0xAA);
        assert_eq!(buf.as_slice()[63], 0xBB);
        buf.free().unwrap();
    }

    #[test]
    fn membuf_lock_unlock() {
        let buf = MemBuf::alloc(4096).unwrap();
        buf.lock().unwrap();
        buf.unlock().unwrap();
        buf.free().unwrap();
    }

    #[test]
    fn membuf_protect_read_write() {
        let mut buf = MemBuf::alloc(4096).unwrap();
        // Set read-only
        buf.protect(MemoryProtectionFlag::read_only()).unwrap();
        // Restore read-write so we can free
        buf.protect(MemoryProtectionFlag::read_write()).unwrap();
        buf.as_mut_slice()[0] = 42;
        assert_eq!(buf.as_slice()[0], 42);
        buf.free().unwrap();
    }

    #[test]
    fn membuf_protect_no_access_and_restore() {
        let buf = MemBuf::alloc(4096).unwrap();
        buf.protect(MemoryProtectionFlag::no_access()).unwrap();
        // Restore so we can free
        buf.protect(MemoryProtectionFlag::read_write()).unwrap();
        buf.free().unwrap();
    }

    #[test]
    fn membuf_drop_without_explicit_free() {
        // Should not leak or panic
        let mut buf = MemBuf::alloc(128).unwrap();
        buf.as_mut_slice()[0] = 1;
        drop(buf);
    }

    #[test]
    fn membuf_various_sizes() {
        for size in [1, 16, 256, 4096, 8192] {
            let mut buf = MemBuf::alloc(size).unwrap();
            assert_eq!(buf.len(), size);
            // Verify all bytes are zero-initialized
            assert!(buf.as_slice().iter().all(|&b| b == 0));
            buf.as_mut_slice()[size - 1] = 0xFF;
            assert_eq!(buf.as_slice()[size - 1], 0xFF);
            buf.free().unwrap();
        }
    }

    #[test]
    fn memory_protection_flag_values() {
        let na = MemoryProtectionFlag::no_access();
        let ro = MemoryProtectionFlag::read_only();
        let rw = MemoryProtectionFlag::read_write();
        // They should all be different
        assert_ne!(na, ro);
        assert_ne!(ro, rw);
        assert_ne!(na, rw);
    }

    #[test]
    fn disable_core_dumps_succeeds() {
        disable_core_dumps().unwrap();
    }

    #[test]
    fn mem_error_display() {
        let sys = MemError::Sys("test error".into());
        assert_eq!(format!("{sys}"), "test error");

        let inv = MemError::InvalidFlag;
        assert_eq!(format!("{inv}"), ERR_INVALID_FLAG);
    }
}
