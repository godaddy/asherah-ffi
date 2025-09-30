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
        let _ignored = self.protect(MemoryProtectionFlag::read_write());
        wipe(self.as_mut_slice());
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
        let _ignored = self.protect(MemoryProtectionFlag::read_write());
        if self.len > 0 {
            let s = unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) };
            wipe(s);
        }
        let _ignored = os::os_free(self.ptr.as_ptr(), self.len);
        self.len = 0;
    }
}
fn wipe(buf: &mut [u8]) {
    for b in buf {
        *b = 0;
    }
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
        #[cfg(target_os = "linux")]
        unsafe {
            libc::madvise(ptr.cast::<c_void>(), len, libc::MADV_DONTDUMP)
        };
        #[cfg(target_os = "freebsd")]
        unsafe {
            libc::madvise(ptr.cast::<c_void>(), len, libc::MADV_NOCORE)
        };
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
