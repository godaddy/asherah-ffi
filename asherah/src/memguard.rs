// Embedded memguard (was memguard-rs)
// Provides locked, page-protected buffers and sealed enclaves.

use crate::memcall;
use blake2::{Blake2b512, Digest};
use once_cell::sync::Lazy;
use parking_lot::{Condvar, Mutex};
use rand::rngs::OsRng;
use rand::TryRngCore;
// LessSafeKey: safe here — enclave sealing uses a monotonic atomic counter
// for nonces (NONCE_COUNTER), guaranteeing uniqueness without randomness.
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use subtle::ConstantTimeEq;

static PAGE_SIZE: Lazy<usize> = Lazy::new(page_size);

fn page_size() -> usize {
    #[cfg(unix)]
    unsafe {
        let ps = libc::sysconf(libc::_SC_PAGESIZE);
        if ps > 0 {
            ps as usize
        } else {
            4096
        }
    }
    #[cfg(windows)]
    {
        4096
    }
}
fn round_to_page_size(len: usize) -> usize {
    let ps = *PAGE_SIZE;
    (len + (ps - 1)) & !(ps - 1)
}

pub fn scramble_bytes(buf: &mut [u8]) {
    OsRng.try_fill_bytes(buf).expect("OsRng");
}
pub fn wipe_bytes(buf: &mut [u8]) {
    for b in buf {
        *b = 0;
    }
}
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut h = [0_u8; 32];
    let mut hasher = Blake2b512::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    h.copy_from_slice(&out[..32]);
    h
}
pub fn ct_copy(dst: &mut [u8], src: &[u8]) {
    let n = dst.len().min(src.len());
    dst[..n].copy_from_slice(&src[..n]);
}
pub fn ct_move(dst: &mut [u8], src: &mut [u8]) {
    ct_copy(dst, src);
    wipe_bytes(src);
}
pub fn ct_equal(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[derive(Debug)]
pub enum Error {
    NullBuffer,
    Mem(memcall::MemError),
    CanaryFailed,
    InvalidKeyLength,
    BufferTooSmall,
    DecryptionFailed,
    /// Input was not the required fixed size for this operation.
    InvalidSize {
        expected: usize,
        got: usize,
    },
}
impl From<memcall::MemError> for Error {
    fn from(e: memcall::MemError) -> Self {
        Error::Mem(e)
    }
}

#[allow(missing_debug_implementations)]
pub enum WithBytesError<E> {
    Buffer(Error),
    Callback(E),
}

#[derive(Debug)]
pub struct Buffer {
    mem: memcall::MemBuf,
    data_off: usize,
    data_len: usize,
    inner_off: usize,
    inner_len: usize,
    canary_len: usize,
    alive: bool,
    mutable: bool,
}

impl Buffer {
    pub fn new(size: usize) -> Result<Self, Error> {
        Lazy::force(&INIT); // ensure core dumps disabled
        if size < 1 {
            return Err(Error::NullBuffer);
        }
        let ps = *PAGE_SIZE;
        let inner_len = round_to_page_size(size);
        let total = 2 * ps + inner_len;
        let mut mem = memcall::MemBuf::alloc(total)?;
        let base = mem.as_mut_ptr();
        let pre = base;
        let inner = unsafe { base.add(ps) };
        let post = unsafe { inner.add(inner_len) };
        let data_off = ps + inner_len - size;
        unsafe {
            memcall::lock_raw(inner, inner_len)?;
        }
        let canary_len = inner_len - size;
        if canary_len > 0 {
            let canary = unsafe { std::slice::from_raw_parts_mut(inner, canary_len) };
            scramble_bytes(canary);
            let pre_s = unsafe { std::slice::from_raw_parts_mut(pre, ps) };
            let post_s = unsafe { std::slice::from_raw_parts_mut(post, ps) };
            for (idx, slot) in pre_s.iter_mut().enumerate() {
                *slot = canary[idx % canary_len];
            }
            for (idx, slot) in post_s.iter_mut().enumerate() {
                *slot = canary[idx % canary_len];
            }
        }
        unsafe {
            memcall::protect_raw(pre, ps, memcall::MemoryProtectionFlag::no_access())?;
            memcall::protect_raw(post, ps, memcall::MemoryProtectionFlag::no_access())?;
        }
        Ok(Self {
            mem,
            data_off,
            data_len: size,
            inner_off: ps,
            inner_len,
            canary_len,
            alive: true,
            mutable: true,
        })
    }
    fn base_ptr(&self) -> *mut u8 {
        self.mem.as_ptr() as *mut u8
    }
    fn inner_ptr(&self) -> *mut u8 {
        unsafe { self.base_ptr().add(self.inner_off) }
    }
    fn pre_ptr(&self) -> *mut u8 {
        self.base_ptr()
    }
    fn post_ptr(&self) -> *mut u8 {
        unsafe { self.inner_ptr().add(self.inner_len) }
    }
    fn data_ptr(&self) -> *mut u8 {
        unsafe { self.base_ptr().add(self.data_off) }
    }
    fn inner_raw(&self) -> (*mut u8, usize) {
        (self.inner_ptr(), self.inner_len)
    }
    pub fn bytes(&mut self) -> &mut [u8] {
        if !self.alive {
            return &mut [];
        }
        unsafe { std::slice::from_raw_parts_mut(self.data_ptr(), self.data_len) }
    }
    pub fn as_slice(&self) -> &[u8] {
        if !self.alive {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.data_ptr(), self.data_len) }
    }
    pub fn size(&self) -> usize {
        if self.alive {
            self.data_len
        } else {
            0
        }
    }
    pub fn alive(&self) -> bool {
        self.alive
    }
    pub fn mutable(&self) -> bool {
        self.mutable
    }
    pub fn freeze(&mut self) -> Result<(), Error> {
        if self.alive && self.mutable {
            unsafe {
                memcall::protect_raw(
                    self.inner_ptr(),
                    self.inner_len,
                    memcall::MemoryProtectionFlag::read_only(),
                )?;
            }
            self.mutable = false;
        }
        Ok(())
    }
    pub fn melt(&mut self) -> Result<(), Error> {
        if self.alive && !self.mutable {
            unsafe {
                memcall::protect_raw(
                    self.inner_ptr(),
                    self.inner_len,
                    memcall::MemoryProtectionFlag::read_write(),
                )?;
            }
            self.mutable = true;
        }
        Ok(())
    }
    pub fn scramble(&mut self) {
        scramble_bytes(self.bytes())
    }
    pub fn destroy(&mut self) -> Result<(), Error> {
        if !self.alive {
            return Ok(());
        }
        self.mem
            .protect(memcall::MemoryProtectionFlag::read_write())?;
        self.mutable = true;
        wipe_bytes(self.bytes());
        if self.canary_len > 0 {
            let can = unsafe { std::slice::from_raw_parts(self.inner_ptr(), self.canary_len) };
            let pre = unsafe { std::slice::from_raw_parts(self.pre_ptr(), *PAGE_SIZE) };
            let post = unsafe { std::slice::from_raw_parts(self.post_ptr(), *PAGE_SIZE) };
            for i in 0..*PAGE_SIZE {
                let exp = can[i % self.canary_len];
                if pre[i] != exp || post[i] != exp {
                    return Err(Error::CanaryFailed);
                }
            }
        }
        let full = unsafe {
            std::slice::from_raw_parts_mut(self.base_ptr(), 2 * (*PAGE_SIZE) + self.inner_len)
        };
        wipe_bytes(full);
        unsafe {
            memcall::unlock_raw(self.inner_ptr(), self.inner_len)?;
        }
        let mem = std::mem::replace(&mut self.mem, memcall::MemBuf::alloc(1)?);
        mem.free()?;
        self.alive = false;
        self.mutable = false;
        self.data_len = 0;
        Ok(())
    }
}

pub const OVERHEAD: usize = 12 + 16; // nonce + tag

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 32 {
        return Err(Error::InvalidKeyLength);
    }
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| Error::InvalidKeyLength)?;
    let aead_key = LessSafeKey::new(unbound);
    let ctr = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut nonce_bytes = [0_u8; 12];
    nonce_bytes[4..].copy_from_slice(&ctr.to_le_bytes());
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    aead_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| Error::DecryptionFailed)?;
    let mut out = Vec::with_capacity(12 + in_out.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    if key.len() != 32 {
        return Err(Error::InvalidKeyLength);
    }
    if ciphertext.len() < OVERHEAD {
        return Err(Error::DecryptionFailed);
    }
    if output.len() < ciphertext.len() - OVERHEAD {
        return Err(Error::BufferTooSmall);
    }
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| Error::InvalidKeyLength)?;
    let aead_key = LessSafeKey::new(unbound);
    let (nonce_bytes, ct_and_tag) = ciphertext.split_at(12);
    let nonce =
        Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| Error::DecryptionFailed)?;
    let mut in_out = ct_and_tag.to_vec();
    let pt = aead_key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| Error::DecryptionFailed)?;
    let n = pt.len();
    output[..n].copy_from_slice(pt);
    Ok(n)
}

static ENCLAVE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct Enclave {
    id: u64,
    ciphertext: Vec<u8>,
    data_len: usize,
}
impl Enclave {
    /// Seal a SLOT_SIZE byte slice directly without allocating a page-locked
    /// Buffer. The plaintext is encrypted and inserted into the SLAB hot cache.
    /// This avoids 6 syscalls (mmap/mlock/mprotect/munlock/munmap) per key.
    pub fn seal_bytes(plaintext: &[u8]) -> Result<Self, Error> {
        if plaintext.len() != SLOT_SIZE {
            return Err(Error::InvalidSize {
                expected: SLOT_SIZE,
                got: plaintext.len(),
            });
        }
        let mut key = coffer_view()?;
        let id = ENCLAVE_ID.fetch_add(1, Ordering::Relaxed);
        cache_insert(id, plaintext);
        let ct = encrypt(plaintext, key.bytes())?;
        pool_release(key);
        Ok(Self {
            id,
            ciphertext: ct,
            data_len: SLOT_SIZE,
        })
    }

    pub fn new_from(buf: &mut Buffer) -> Result<Self, Error> {
        let mut key = coffer_view()?;
        let data_len = buf.size();
        let id = ENCLAVE_ID.fetch_add(1, Ordering::Relaxed);
        // Populate hot cache before we destroy the plaintext
        if data_len == SLOT_SIZE {
            cache_insert(id, buf.as_slice());
        }
        let ct = encrypt(buf.as_slice(), key.bytes())?;
        buf.melt()?;
        buf.scramble();
        buf.destroy()?;
        pool_release(key);
        Ok(Self {
            id,
            ciphertext: ct,
            data_len,
        })
    }
    pub fn open(&self) -> Result<PoolSlot, Error> {
        // Fast path: check hot cache (no crypto needed)
        if self.data_len == SLOT_SIZE {
            if let Some(slot) = cache_get(self.id) {
                return Ok(slot);
            }
        }
        // Slow path: AES-256-GCM unseal
        let mut out = pool_acquire(self.data_len)?;
        let mut key = coffer_view()?;
        let n = decrypt(&self.ciphertext, key.bytes(), out.bytes())?;
        debug_assert_eq!(n, out.size());
        pool_release(key);
        // Promote to hot cache for next time
        if self.data_len == SLOT_SIZE {
            cache_insert(self.id, out.as_slice());
        }
        Ok(out)
    }
    pub fn plaintext_len(&self) -> usize {
        self.data_len
    }
    pub fn size(&self) -> usize {
        self.data_len
    }
}

// -- Unified secure slab --
// A single mlock'd page subdivided into 32-byte slots.
//
// Layout:
//   Slot 0: Coffer left half  (permanent, key XOR hash(right))
//   Slot 1: Coffer right half (permanent, random)
//   Slots 2..N: shared between hot key cache and transient operations
//
// The Coffer stores the XSalsa20 master key used to encrypt/decrypt Enclaves.
// Hot cache entries hold recently-decrypted keys (LRU-evicted).
// Transient slots are acquired briefly during crypto operations, then released.
// When no free slots remain, the LRU cache entry is evicted to make room.
pub const SLOT_SIZE: usize = 32; // AES-256 key size
const COFFER_LEFT: usize = 0;
const COFFER_RIGHT: usize = 1;
const FIRST_SHARED_SLOT: usize = 2;

struct SecureSlab {
    #[allow(dead_code)]
    _page: Buffer,
    base: *mut u8,
    slot_count: usize,

    // Free list of shared slot indices (LIFO for cache locality)
    free: Vec<usize>,

    // Hot key cache: maps enclave_id → slot index
    cache_map: HashMap<u64, usize>,
    cache_slot_to_id: Vec<u64>, // slot_idx → enclave_id (0 = not cached)
    cache_lru: VecDeque<usize>, // front = least recently used
}

// SAFETY: base points into mlock'd mmap memory owned by _page.
unsafe impl Send for SecureSlab {}

impl SecureSlab {
    fn new() -> Result<Self, Error> {
        Lazy::force(&INIT);
        let ps = *PAGE_SIZE;
        let mut page = Buffer::new(ps)?;
        let base = page.bytes().as_mut_ptr();
        wipe_bytes(page.bytes());
        let slot_count = ps / SLOT_SIZE;

        // Initialize Coffer: slots 0 (left) and 1 (right)
        let left = unsafe { std::slice::from_raw_parts_mut(base, SLOT_SIZE) };
        scramble_bytes(left);
        let right = unsafe { std::slice::from_raw_parts_mut(base.add(SLOT_SIZE), SLOT_SIZE) };
        scramble_bytes(right);
        let hr = hash(right);
        let left = unsafe { std::slice::from_raw_parts_mut(base, SLOT_SIZE) };
        for (slot, hash_byte) in left.iter_mut().zip(hr.iter()) {
            *slot ^= hash_byte;
        }

        // All remaining slots start on the free list
        let shared_count = slot_count - FIRST_SHARED_SLOT;
        let mut free = Vec::with_capacity(shared_count);
        for i in FIRST_SHARED_SLOT..slot_count {
            free.push(i);
        }

        Ok(Self {
            _page: page,
            base,
            slot_count,
            free,
            cache_map: HashMap::with_capacity(shared_count),
            cache_slot_to_id: vec![0_u64; slot_count],
            cache_lru: VecDeque::with_capacity(shared_count),
        })
    }

    fn slot_ptr(&self, idx: usize) -> *mut u8 {
        debug_assert!(idx < self.slot_count);
        unsafe { self.base.add(idx * SLOT_SIZE) }
    }

    fn slot_slice_mut(&mut self, idx: usize) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.slot_ptr(idx), SLOT_SIZE) }
    }

    fn ptr_to_idx(&self, ptr: *mut u8) -> usize {
        let offset = ptr as usize - self.base as usize;
        offset / SLOT_SIZE
    }

    /// Acquire a shared slot. Tries free list first, then evicts from cache.
    /// `exclude` prevents evicting a specific cache slot (used when the caller
    /// holds a reference to that slot).
    fn acquire_slot(&mut self, exclude: Option<usize>) -> Option<usize> {
        // Try free list (O(1))
        if let Some(idx) = self.free.pop() {
            return Some(idx);
        }
        // Evict from hot cache LRU
        for i in 0..self.cache_lru.len() {
            let evict_idx = self.cache_lru[i];
            if Some(evict_idx) == exclude {
                continue;
            }
            self.cache_lru.remove(i);
            let evict_id = self.cache_slot_to_id[evict_idx];
            self.cache_map.remove(&evict_id);
            self.cache_slot_to_id[evict_idx] = 0;
            wipe_bytes(self.slot_slice_mut(evict_idx));
            return Some(evict_idx);
        }
        None
    }

    /// Reconstruct the Coffer master key into a transient slot.
    fn coffer_view(&mut self) -> Option<PoolSlot> {
        let out_idx = self.acquire_slot(None)?;
        // Use raw pointers to avoid borrow conflicts on non-overlapping slots
        let right_ptr = self.slot_ptr(COFFER_RIGHT);
        let right = unsafe { std::slice::from_raw_parts(right_ptr, SLOT_SIZE) };
        let hr = hash(right);
        let left_ptr = self.slot_ptr(COFFER_LEFT);
        let out_ptr = self.slot_ptr(out_idx);
        let left = unsafe { std::slice::from_raw_parts(left_ptr, SLOT_SIZE) };
        let out = unsafe { std::slice::from_raw_parts_mut(out_ptr, SLOT_SIZE) };
        for (dst, (hash_byte, left_byte)) in out.iter_mut().zip(hr.iter().zip(left.iter())) {
            *dst = hash_byte ^ left_byte;
        }
        Some(PoolSlot {
            ptr: out_ptr,
            len: SLOT_SIZE,
            origin: SlotOrigin::Slab,
        })
    }

    /// Re-initialize Coffer with a new random key (for purge/rekey).
    fn rekey_coffer(&mut self) {
        let left = self.slot_slice_mut(COFFER_LEFT);
        scramble_bytes(left);
        let right = self.slot_slice_mut(COFFER_RIGHT);
        scramble_bytes(right);
        let hr = hash(right);
        let left = self.slot_slice_mut(COFFER_LEFT);
        for (slot, hash_byte) in left.iter_mut().zip(hr.iter()) {
            *slot ^= hash_byte;
        }
    }

    /// Wipe Coffer key material (for shutdown).
    fn wipe_coffer(&mut self) {
        wipe_bytes(self.slot_slice_mut(COFFER_LEFT));
        wipe_bytes(self.slot_slice_mut(COFFER_RIGHT));
    }

    /// Look up a cached key by enclave_id. On hit, copies into a transient slot.
    fn cache_get(&mut self, enclave_id: u64) -> Option<PoolSlot> {
        let &src_idx = self.cache_map.get(&enclave_id)?;
        // Touch LRU: move to back (most recent)
        if let Some(pos) = self.cache_lru.iter().position(|&s| s == src_idx) {
            self.cache_lru.remove(pos);
        }
        self.cache_lru.push_back(src_idx);
        // Acquire a transient slot (don't evict the one we just found)
        let out_idx = self.acquire_slot(Some(src_idx))?;
        // Use raw pointers to avoid borrow conflicts on non-overlapping slots
        let src_ptr = self.slot_ptr(src_idx);
        let dst_ptr = self.slot_ptr(out_idx);
        unsafe {
            std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, SLOT_SIZE);
        }
        Some(PoolSlot {
            ptr: self.slot_ptr(out_idx),
            len: SLOT_SIZE,
            origin: SlotOrigin::Slab,
        })
    }

    /// Insert plaintext into the hot cache for the given enclave_id.
    fn cache_insert(&mut self, enclave_id: u64, plaintext: &[u8]) {
        debug_assert_eq!(plaintext.len(), SLOT_SIZE);
        if self.cache_map.contains_key(&enclave_id) {
            return;
        }
        let slot_idx = match self.acquire_slot(None) {
            Some(idx) => idx,
            None => return, // all slots held transiently, skip caching
        };
        self.slot_slice_mut(slot_idx).copy_from_slice(plaintext);
        self.cache_map.insert(enclave_id, slot_idx);
        self.cache_slot_to_id[slot_idx] = enclave_id;
        self.cache_lru.push_back(slot_idx);
    }

    /// Clear all hot cache entries, returning slots to the free list.
    fn clear_cache(&mut self) {
        let indices: Vec<usize> = self.cache_map.values().copied().collect();
        for idx in indices {
            wipe_bytes(self.slot_slice_mut(idx));
            self.cache_slot_to_id[idx] = 0;
            self.free.push(idx);
        }
        self.cache_map.clear();
        self.cache_lru.clear();
    }

    /// Release a slot back to the free list.
    fn release_slot(&mut self, idx: usize) {
        debug_assert!(idx >= FIRST_SHARED_SLOT && idx < self.slot_count);
        wipe_bytes(self.slot_slice_mut(idx));
        self.free.push(idx);
    }
}

static SLAB: Lazy<Mutex<SecureSlab>> =
    Lazy::new(|| Mutex::new(SecureSlab::new().expect("secure slab initialization")));
static SLAB_CV: Lazy<Condvar> = Lazy::new(Condvar::new);

/// A handle to a 32-byte slot in the secure slab or a standalone Buffer.
#[allow(missing_debug_implementations)]
pub struct PoolSlot {
    ptr: *mut u8,
    len: usize,
    origin: SlotOrigin,
}

enum SlotOrigin {
    Slab,
    Standalone(Buffer),
}

// SAFETY: Slab-backed slots point into the mlock'd slab page which outlives
// the slot. Standalone slots own their Buffer. Neither is aliased.
unsafe impl Send for PoolSlot {}

impl PoolSlot {
    pub fn bytes(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
    pub fn size(&self) -> usize {
        self.len
    }
}

pub fn pool_acquire(size: usize) -> Result<PoolSlot, Error> {
    if size != SLOT_SIZE {
        // Non-standard sizes get a standalone mlock'd buffer
        let buf = Buffer::new(size)?;
        let ptr = buf.data_ptr();
        let len = buf.data_len;
        return Ok(PoolSlot {
            ptr,
            len,
            origin: SlotOrigin::Standalone(buf),
        });
    }
    let mut slab = SLAB.lock();
    if let Some(idx) = slab.acquire_slot(None) {
        return Ok(PoolSlot {
            ptr: slab.slot_ptr(idx),
            len: SLOT_SIZE,
            origin: SlotOrigin::Slab,
        });
    }
    // All slots held transiently — wait for one to be released
    loop {
        SLAB_CV.wait(&mut slab);
        if let Some(idx) = slab.acquire_slot(None) {
            return Ok(PoolSlot {
                ptr: slab.slot_ptr(idx),
                len: SLOT_SIZE,
                origin: SlotOrigin::Slab,
            });
        }
    }
}

pub fn pool_release(slot: PoolSlot) {
    match slot.origin {
        SlotOrigin::Slab => {
            let mut slab = SLAB.lock();
            let idx = slab.ptr_to_idx(slot.ptr);
            slab.release_slot(idx);
            SLAB_CV.notify_one();
        }
        SlotOrigin::Standalone(mut buf) => {
            drop(buf.destroy());
        }
    }
}

/// Reconstruct the Coffer master key into a transient pool slot.
pub fn coffer_view() -> Result<PoolSlot, Error> {
    let mut slab = SLAB.lock();
    loop {
        if let Some(slot) = slab.coffer_view() {
            return Ok(slot);
        }
        SLAB_CV.wait(&mut slab);
    }
}

/// Look up a cached decrypted key. Returns None on cache miss.
fn cache_get(enclave_id: u64) -> Option<PoolSlot> {
    SLAB.lock().cache_get(enclave_id)
}

/// Insert a decrypted key into the hot cache.
fn cache_insert(enclave_id: u64, plaintext: &[u8]) {
    if plaintext.len() == SLOT_SIZE {
        SLAB.lock().cache_insert(enclave_id, plaintext);
    }
}

use std::sync::{Arc, Weak};

static REGISTRY: Lazy<Mutex<Vec<Weak<Mutex<Buffer>>>>> = Lazy::new(|| Mutex::new(Vec::new()));
fn registry_add(w: Weak<Mutex<Buffer>>) {
    REGISTRY.lock().push(w);
}
fn registry_remove(ptr: *const Mutex<Buffer>) {
    let mut v = REGISTRY.lock();
    v.retain(|w| !std::ptr::eq(w.as_ptr(), ptr));
}
fn registry_copy() -> Vec<Arc<Mutex<Buffer>>> {
    let v = REGISTRY.lock();
    v.iter().filter_map(|w| w.upgrade()).collect()
}
fn registry_flush() -> Vec<Arc<Mutex<Buffer>>> {
    let mut v = REGISTRY.lock();
    let out: Vec<_> = v.iter().filter_map(|w| w.upgrade()).collect();
    v.clear();
    out
}

#[derive(Debug)]
pub struct LockedBuffer(Arc<Mutex<Buffer>>);
impl LockedBuffer {
    pub fn new(size: usize) -> Result<Self, Error> {
        let b = Buffer::new(size)?;
        let arc = Arc::new(Mutex::new(b));
        registry_add(Arc::downgrade(&arc));
        Ok(Self(arc))
    }
    pub fn random(size: usize) -> Result<Self, Error> {
        let mut b = Buffer::new(size)?;
        b.scramble();
        b.freeze()?;
        Ok(Self::from_buffer_owned(b))
    }
    pub fn from_bytes(mut bytes: Vec<u8>) -> Result<Self, Error> {
        let b = Self::new(bytes.len())?;
        {
            let mut g = b.0.lock();
            ct_move(g.bytes(), &mut bytes);
            g.freeze()?;
        }
        Ok(b)
    }
    fn from_buffer_owned(buf: Buffer) -> Self {
        let arc = Arc::new(Mutex::new(buf));
        registry_add(Arc::downgrade(&arc));
        Self(arc)
    }
    pub fn freeze(&self) -> Result<(), Error> {
        self.0.lock().freeze()
    }
    pub fn melt(&self) -> Result<(), Error> {
        self.0.lock().melt()
    }
    pub fn scramble(&self) {
        self.0.lock().scramble()
    }
    pub fn wipe(&self) {
        wipe_bytes(self.0.lock().bytes());
    }
    pub fn size(&self) -> usize {
        self.0.lock().size()
    }
    pub fn is_alive(&self) -> bool {
        self.0.lock().alive()
    }
    pub fn is_mutable(&self) -> bool {
        self.0.lock().mutable()
    }
    pub fn bytes(&self) -> Vec<u8> {
        self.0.lock().as_slice().to_vec()
    }
    pub fn copy(&self, src: &[u8]) {
        self.copy_at(0, src);
    }
    pub fn copy_at(&self, offset: usize, src: &[u8]) {
        let mut g = self.0.lock();
        ct_copy(&mut g.bytes()[offset..], src);
    }
    pub fn r#move(&self, src: &mut [u8]) {
        self.move_at(0, src);
    }
    pub fn move_at(&self, offset: usize, src: &mut [u8]) {
        let mut g = self.0.lock();
        ct_move(&mut g.bytes()[offset..], src);
    }
    pub fn seal(&self) -> Result<Enclave, Error> {
        let mut g = self.0.lock();
        Enclave::new_from(&mut g)
    }
    pub fn destroy(&self) -> Result<(), Error> {
        let ptr = Arc::as_ptr(&self.0);
        registry_remove(ptr);
        self.0.lock().destroy()
    }
    pub fn inner_raw(&self) -> (*mut u8, usize) {
        self.0.lock().inner_raw()
    }
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R, Error> {
        let g = self.0.lock();
        if !g.alive() {
            return Err(Error::CanaryFailed);
        }
        Ok(f(g.as_slice()))
    }
}

pub fn purge() -> Result<(), Error> {
    {
        let mut slab = SLAB.lock();
        slab.clear_cache();
        slab.rekey_coffer();
    }
    let snapshot = registry_flush();
    let mut op_err: Option<String> = None;
    for arc in snapshot {
        let mut b = arc.lock();
        if let Err(e) = b.destroy() {
            let mut wiped = false;
            if let Ok(()) = b.melt() {
                wipe_bytes(b.bytes());
                wiped = true;
            }
            let msg = if wiped {
                format!("{:?} (wiped)", e)
            } else {
                format!("{:?}", e)
            };
            op_err = Some(match op_err {
                None => msg,
                Some(prev) => format!("{}; {}", prev, msg),
            });
        }
    }
    if let Some(m) = op_err {
        return Err(Error::Mem(memcall::MemError::Sys(m)));
    }
    Ok(())
}
#[allow(clippy::exit)]
pub fn safe_exit(code: i32) -> ! {
    {
        let mut slab = SLAB.lock();
        slab.wipe_coffer();
        slab.clear_cache();
    }
    let snapshot = registry_copy();
    for arc in snapshot {
        let mut b = arc.lock();
        let _destroyed = b.destroy();
    }
    std::process::exit(code)
}
#[cfg(not(windows))]
pub fn catch_signal<F: Fn(std::io::Result<libc::c_int>) + Send + Sync + 'static>(
    signals: &[libc::c_int],
    handler: F,
) {
    use signal_hook::iterator::Signals;
    let signals_vec = signals.to_vec();
    std::thread::spawn(move || {
        let mut sigs = Signals::new(&signals_vec).expect("signals");
        if let Some(sig) = (&mut sigs).into_iter().next() {
            handler(Ok(sig));
            safe_exit(1);
        }
    });
}

#[cfg(windows)]
pub fn catch_signal<F: Fn(std::io::Result<libc::c_int>) + Send + Sync + 'static>(
    _signals: &[libc::c_int],
    handler: F,
) {
    std::thread::spawn(move || {
        handler(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "signal handling not supported on Windows",
        )));
    });
}
pub fn catch_interrupt() {
    catch_signal(&[libc::SIGINT], |_s| {});
}
static INIT: Lazy<()> = Lazy::new(|| {
    let _result = memcall::disable_core_dumps();
});
pub static mut STREAM_CHUNK_SIZE: usize = 0;
