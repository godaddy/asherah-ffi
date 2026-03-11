// Embedded memguard (was memguard-rs)
// Provides locked, page-protected buffers and sealed enclaves.

use crate::memcall;
use blake2::{Blake2b512, Digest};
use once_cell::sync::Lazy;
use parking_lot::{Condvar, Mutex};
use rand::rngs::OsRng;
use rand::TryRngCore;
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
    pub fn new_from(buf: &mut Buffer) -> Result<Self, Error> {
        let mut key = get_or_create_key().view()?;
        let data_len = buf.size();
        let id = ENCLAVE_ID.fetch_add(1, Ordering::Relaxed);
        // Populate hot cache before we destroy the plaintext
        if data_len == SLOT_SIZE {
            hot_cache_insert_plaintext(id, buf.as_slice());
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
            if let Some(slot) = hot_cache_get(self.id) {
                return Ok(slot);
            }
        }
        // Slow path: XSalsa20 unseal
        let mut out = pool_acquire(self.data_len)?;
        let mut key = get_or_create_key().view()?;
        let n = decrypt(&self.ciphertext, key.bytes(), out.bytes())?;
        debug_assert_eq!(n, out.size());
        pool_release(key);
        // Promote to hot cache for next time
        if self.data_len == SLOT_SIZE {
            hot_cache_insert_plaintext(self.id, out.as_slice());
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

// -- Slab pool for mlock robustness --
// Subdivides mlock'd pages into 32-byte slots so one page serves many keys.
// Guard pages on each slab page protect the entire region from memory scanning.
// Free list gives O(1) acquire/release. When mlock is exhausted, callers block.
const SLOT_SIZE: usize = 32; // AES-256 key size

struct FreeSlot {
    ptr: *mut u8,
}

// SAFETY: ptr points into mlock'd mmap memory that is never freed.
unsafe impl Send for FreeSlot {}

struct SlabPool {
    #[allow(dead_code)] // own the mmaps — must not be dropped
    pages: Vec<Buffer>,
    free: Vec<FreeSlot>,
    outstanding: usize,
}

static POOL: Lazy<Mutex<SlabPool>> = Lazy::new(|| {
    Mutex::new(SlabPool {
        pages: Vec::new(),
        free: Vec::new(),
        outstanding: 0,
    })
});
static POOL_CONDVAR: Lazy<Condvar> = Lazy::new(Condvar::new);

/// Allocate a new slab page (mmap+mlock outside lock), then push slots.
fn grow_pool_unlocked() -> Result<(), Error> {
    let ps = *PAGE_SIZE;
    let mut buffer = Buffer::new(ps)?;
    let base = buffer.bytes().as_mut_ptr();
    wipe_bytes(buffer.bytes());
    let slot_count = ps / SLOT_SIZE;
    let mut pool = POOL.lock();
    pool.pages.push(buffer);
    pool.free.reserve(slot_count);
    for i in 0..slot_count {
        let ptr = unsafe { base.add(i * SLOT_SIZE) };
        pool.free.push(FreeSlot { ptr });
    }
    Ok(())
}

/// A handle to a 32-byte slot in a slab page or a standalone Buffer.
/// Provides `bytes()` / `as_slice()` like Buffer.
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

// SAFETY: Slab-backed slots point into mlock'd mmap regions that outlive
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
        let buf = Buffer::new(size)?;
        let ptr = buf.data_ptr();
        let len = buf.data_len;
        return Ok(PoolSlot {
            ptr,
            len,
            origin: SlotOrigin::Standalone(buf),
        });
    }
    // 1. Try free list (O(1) pop)
    {
        let mut pool = POOL.lock();
        if let Some(slot) = pool.free.pop() {
            pool.outstanding += 1;
            return Ok(PoolSlot {
                ptr: slot.ptr,
                len: SLOT_SIZE,
                origin: SlotOrigin::Slab,
            });
        }
    }
    // 2. Try allocating a new slab page — unlocked so mmap/mlock don't block others
    match grow_pool_unlocked() {
        Ok(()) => {
            let mut pool = POOL.lock();
            let slot = pool.free.pop().expect("just grew pool");
            pool.outstanding += 1;
            Ok(PoolSlot {
                ptr: slot.ptr,
                len: SLOT_SIZE,
                origin: SlotOrigin::Slab,
            })
        }
        Err(alloc_err) => {
            // 3. mlock exhausted — block until a slot is freed
            let mut pool = POOL.lock();
            if pool.outstanding == 0 && pool.free.is_empty() {
                return Err(alloc_err);
            }
            while pool.free.is_empty() {
                POOL_CONDVAR.wait(&mut pool);
            }
            let slot = pool
                .free
                .pop()
                .expect("condvar signaled but free list empty");
            pool.outstanding += 1;
            Ok(PoolSlot {
                ptr: slot.ptr,
                len: SLOT_SIZE,
                origin: SlotOrigin::Slab,
            })
        }
    }
}

pub fn pool_release(mut slot: PoolSlot) {
    match slot.origin {
        SlotOrigin::Slab => {
            wipe_bytes(slot.bytes());
            let mut pool = POOL.lock();
            pool.free.push(FreeSlot { ptr: slot.ptr });
            pool.outstanding = pool.outstanding.saturating_sub(1);
            POOL_CONDVAR.notify_one();
        }
        SlotOrigin::Standalone(mut buf) => {
            drop(buf.destroy());
        }
    }
}

// -- Hot key cache --
// One mlock'd slab page of decrypted keys, LRU-evicted.
// Avoids XSalsa20 unseal for frequently-used keys.
struct HotKeyCache {
    #[allow(dead_code)] // owns the mmap — must not be dropped
    page: Buffer,
    base_ptr: *mut u8,
    slot_count: usize,
    index: HashMap<u64, usize>, // enclave_id -> slot_idx
    slot_to_id: Vec<u64>,       // slot_idx -> enclave_id (0 = empty)
    lru: VecDeque<usize>,       // slot indices, front = least recent
}

// SAFETY: base_ptr points into mlock'd mmap memory owned by `page`.
unsafe impl Send for HotKeyCache {}

impl HotKeyCache {
    fn new() -> Result<Self, Error> {
        let ps = *PAGE_SIZE;
        let mut page = Buffer::new(ps)?;
        let base_ptr = page.bytes().as_mut_ptr();
        wipe_bytes(page.bytes());
        let slot_count = ps / SLOT_SIZE;
        Ok(Self {
            page,
            base_ptr,
            slot_count,
            index: HashMap::with_capacity(slot_count),
            slot_to_id: vec![0; slot_count],
            lru: VecDeque::with_capacity(slot_count),
        })
    }

    fn get(&mut self, enclave_id: u64) -> Option<*const u8> {
        let &slot_idx = self.index.get(&enclave_id)?;
        // Touch LRU: move to back (most recent)
        if let Some(pos) = self.lru.iter().position(|&s| s == slot_idx) {
            self.lru.remove(pos);
        }
        self.lru.push_back(slot_idx);
        let ptr = unsafe { self.base_ptr.add(slot_idx * SLOT_SIZE) };
        Some(ptr as *const u8)
    }

    fn insert(&mut self, enclave_id: u64, plaintext: &[u8]) {
        debug_assert_eq!(plaintext.len(), SLOT_SIZE);
        // Already cached?
        if self.index.contains_key(&enclave_id) {
            return;
        }
        let slot_idx = if self.index.len() < self.slot_count {
            // Free slot available
            self.index.len()
        } else {
            // Evict LRU
            let evict_idx = self.lru.pop_front().expect("LRU non-empty when full");
            let evict_id = self.slot_to_id[evict_idx];
            self.index.remove(&evict_id);
            // Wipe evicted slot
            let evict_ptr = unsafe { self.base_ptr.add(evict_idx * SLOT_SIZE) };
            let evict_slice = unsafe { std::slice::from_raw_parts_mut(evict_ptr, SLOT_SIZE) };
            wipe_bytes(evict_slice);
            evict_idx
        };
        // Write plaintext into slot
        let ptr = unsafe { self.base_ptr.add(slot_idx * SLOT_SIZE) };
        let dst = unsafe { std::slice::from_raw_parts_mut(ptr, SLOT_SIZE) };
        dst.copy_from_slice(plaintext);
        self.index.insert(enclave_id, slot_idx);
        self.slot_to_id[slot_idx] = enclave_id;
        self.lru.push_back(slot_idx);
    }
}

static HOT_CACHE: Lazy<Mutex<Option<HotKeyCache>>> = Lazy::new(|| Mutex::new(None));

fn hot_cache_get(enclave_id: u64) -> Option<PoolSlot> {
    let mut guard = HOT_CACHE.lock();
    let cache = guard.as_mut()?;
    let src_ptr = cache.get(enclave_id)?;
    // Copy from hot cache into a pool slot (so caller has an owned buffer)
    let mut slot = pool_acquire(SLOT_SIZE).ok()?;
    let src = unsafe { std::slice::from_raw_parts(src_ptr, SLOT_SIZE) };
    slot.bytes().copy_from_slice(src);
    Some(slot)
}

fn hot_cache_insert_plaintext(enclave_id: u64, plaintext: &[u8]) {
    if plaintext.len() != SLOT_SIZE {
        return;
    }
    let mut guard = HOT_CACHE.lock();
    let cache = guard.get_or_insert_with(|| HotKeyCache::new().expect("hot cache page allocation"));
    cache.insert(enclave_id, plaintext);
}

use std::sync::{Arc, Weak};
#[derive(Debug)]
struct CofferInner {
    left: Buffer,
    right: Buffer,
}
impl CofferInner {
    fn init(&mut self) -> Result<(), Error> {
        scramble_bytes(self.left.bytes());
        scramble_bytes(self.right.bytes());
        let hr = hash(self.right.as_slice());
        for (slot, hash_byte) in self.left.bytes().iter_mut().zip(hr.iter()) {
            *slot ^= hash_byte;
        }
        Ok(())
    }
    fn view(&mut self) -> Result<PoolSlot, Error> {
        let mut b = pool_acquire(32)?;
        let h = hash(self.right.as_slice());
        for (dst, (hash_byte, left_byte)) in
            b.bytes().iter_mut().zip(h.iter().zip(self.left.as_slice()))
        {
            *dst = hash_byte ^ left_byte;
        }
        Ok(b)
    }
}
#[derive(Debug)]
pub struct Coffer(Arc<Mutex<CofferInner>>);
impl Coffer {
    pub fn new() -> Result<Self, Error> {
        let mut inner = CofferInner {
            left: Buffer::new(32)?,
            right: Buffer::new(32)?,
        };
        inner.init()?;
        Ok(Coffer(Arc::new(Mutex::new(inner))))
    }
    pub fn view(&self) -> Result<PoolSlot, Error> {
        self.0.lock().view()
    }
    pub fn destroy(&self) -> Result<(), Error> {
        let mut g = self.0.lock();
        let _left = g.left.destroy();
        let _right = g.right.destroy();
        Ok(())
    }
}

static KEY: Lazy<Mutex<Option<Arc<Coffer>>>> = Lazy::new(|| Mutex::new(None));
fn get_or_create_key() -> Arc<Coffer> {
    let mut k = KEY.lock();
    if let Some(c) = &*k {
        return c.clone();
    }
    let c = Arc::new(Coffer::new().expect("init coffer"));
    *k = Some(c.clone());
    c
}

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
        let mut k = KEY.lock();
        *k = Some(Arc::new(Coffer::new()?));
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
    if let Some(c) = KEY.lock().as_ref() {
        let _destroyed = c.destroy();
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
