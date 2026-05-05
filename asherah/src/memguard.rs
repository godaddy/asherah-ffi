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
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    // Saturating add prevents `usize::MAX + (ps - 1)` from panicking under
    // `overflow-checks = true`. The caller (`Buffer::new`) treats a
    // round-up smaller than the input as an explicit error, so saturating
    // to `usize::MAX` here is fine — the subsequent check rejects.
    len.saturating_add(ps - 1) & !(ps - 1)
}

/// Overwrite `buf` with random bytes from OsRng.
///
/// On OsRng failure, `buf` is zero-filled (so the buffer is left in a
/// deterministic state, not partially-random / partially-undefined per
/// `try_fill_bytes`'s contract) and an `Err` is returned. The original
/// fall-back-and-pretend-nothing-happened behavior was unsafe for the
/// Coffer-init and `LockedBuffer::random` call sites: a silent zero-fill
/// of the master key would let the system keep running with cryptography
/// reduced to a known key. Callers in destruct paths (memory about to be
/// freed, where zero-fill is genuinely safe) can use `let _ = ...` to
/// keep the previous best-effort semantics; crypto-critical callers must
/// `?`-propagate.
pub fn scramble_bytes(buf: &mut [u8]) -> Result<(), Error> {
    if let Err(e) = OsRng.try_fill_bytes(buf) {
        log::error!("scramble_bytes: OsRng failed: {e}; falling back to zero-fill");
        wipe_bytes(buf);
        return Err(Error::Mem(memcall::MemError::Sys(format!(
            "OsRng failed: {e}"
        ))));
    }
    Ok(())
}
pub fn wipe_bytes(buf: &mut [u8]) {
    // zeroize uses volatile writes plus a SeqCst compiler fence to prevent
    // the optimizer from eliminating the wipe as a dead store when the
    // buffer is about to be freed.
    use zeroize::Zeroize;
    buf.zeroize();
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
    /// `pool_acquire` / `coffer_view` timed out waiting for a slab slot
    /// to be released. Indicates either (a) genuine slot pressure that
    /// outstrips the slab capacity, or (b) a leaked `PoolSlot` that
    /// never had `pool_release` called on it.
    OutOfSlots,
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
        // Reject sizes that would overflow during layout calculation.
        // `round_to_page_size(size)` wraps to 0 for inputs near
        // `usize::MAX - ps`; `total = 2*ps + inner_len` would then be
        // 2*ps and we'd allocate two guard pages with no inner region.
        // The data_off computation (`ps + inner_len - size`) would also
        // underflow. Guard explicitly. T16/finding #1 in
        // docs/review-2026-05-05-findings.md.
        let inner_len = round_to_page_size(size);
        if inner_len < size {
            return Err(Error::Mem(memcall::MemError::Sys(format!(
                "Buffer::new: size {size} too large to round up to a page boundary"
            ))));
        }
        let total = match (2_usize.checked_mul(ps)).and_then(|two_ps| two_ps.checked_add(inner_len))
        {
            Some(t) => t,
            None => {
                return Err(Error::Mem(memcall::MemError::Sys(format!(
                    "Buffer::new: layout for size {size} (ps={ps}, inner_len={inner_len}) \
                     overflows usize"
                ))));
            }
        };
        // Sanity: data_off = ps + inner_len - size must not underflow.
        let data_off = match ps.checked_add(inner_len).and_then(|x| x.checked_sub(size)) {
            Some(d) => d,
            None => {
                return Err(Error::Mem(memcall::MemError::Sys(format!(
                    "Buffer::new: data offset for size {size} underflows (ps={ps}, \
                     inner_len={inner_len})"
                ))));
            }
        };
        let mut mem = memcall::MemBuf::alloc(total)?;
        let base = mem.as_mut_ptr();
        let pre = base;
        // SAFETY: `mem` owns the contiguous `total = 2*ps + inner_len`
        // bytes starting at `base`. `base.add(ps)` lands on byte `ps`
        // (the inner region's start) and `inner.add(inner_len)` lands on
        // byte `2*ps + inner_len - ps = ps + inner_len` (the post guard
        // page's start) — both within the allocation.
        let inner = unsafe { base.add(ps) };
        let post = unsafe { inner.add(inner_len) };
        unsafe {
            memcall::lock_raw(inner, inner_len)?;
        }
        let canary_len = inner_len - size;
        if canary_len > 0 {
            let canary = unsafe { std::slice::from_raw_parts_mut(inner, canary_len) };
            scramble_bytes(canary)?;
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
        // SAFETY: `inner_off = ps` is set in `new()` and is always
        // `<= total = 2*ps + inner_len`. The pointer offset stays within
        // the allocation owned by `self.mem`.
        unsafe { self.base_ptr().add(self.inner_off) }
    }
    fn pre_ptr(&self) -> *mut u8 {
        self.base_ptr()
    }
    fn post_ptr(&self) -> *mut u8 {
        // SAFETY: `inner_off + inner_len = ps + inner_len <= total`, so
        // adding `inner_len` past `inner_ptr()` lands on the post-guard
        // page's start, still within the allocation.
        unsafe { self.inner_ptr().add(self.inner_len) }
    }
    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: `data_off` is computed in `new()` as
        // `ps + inner_len - size`, so `0 <= data_off < total` by the
        // same overflow-checked layout invariants.
        unsafe { self.base_ptr().add(self.data_off) }
    }
    fn inner_raw(&self) -> (*mut u8, usize) {
        (self.inner_ptr(), self.inner_len)
    }
    pub fn bytes(&mut self) -> &mut [u8] {
        if !self.alive {
            return &mut [];
        }
        // SAFETY: `data_ptr()..data_ptr()+data_len` is the user-visible
        // window inside the locked inner region (`inner_off..inner_off+inner_len`)
        // owned by `self.mem`. `&mut self` guarantees no aliasing
        // reference exists for the duration of the returned slice.
        unsafe { std::slice::from_raw_parts_mut(self.data_ptr(), self.data_len) }
    }
    pub fn as_slice(&self) -> &[u8] {
        if !self.alive {
            return &[];
        }
        // SAFETY: same window as `bytes()`. `&self` guarantees no
        // mutating reference exists for the duration of the slice.
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
    /// Overwrite the buffer's data with OsRng bytes.
    ///
    /// Returns `Err` if OsRng fails. The buffer is zero-filled in that case,
    /// so callers in destruct paths can safely `let _ = scramble()` if the
    /// memory is about to be freed; crypto-critical callers must propagate.
    pub fn scramble(&mut self) -> Result<(), Error> {
        scramble_bytes(self.bytes())
    }
    pub fn destroy(&mut self) -> Result<(), Error> {
        if !self.alive {
            return Ok(());
        }
        // Allocate the swap-in placeholder FIRST. The previous order ran
        // `protect`, `wipe`, the canary check, `unlock_raw`, and only
        // then allocated the placeholder — so an alloc failure mid-
        // destroy left the buffer half-destroyed with `alive=true`,
        // and a retry would fail the canary check on already-wiped
        // pages with `CanaryFailed`. With the alloc up front, an alloc
        // failure surfaces while the buffer is still in its original
        // state, so `destroy()` is genuinely retryable. T-finding
        // "Buffer::destroy allocates inside the destroy path" in
        // `docs/review-2026-05-05-findings.md`.
        let placeholder = memcall::MemBuf::alloc(1)?;

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
        let mem = std::mem::replace(&mut self.mem, placeholder);
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

impl Drop for Enclave {
    fn drop(&mut self) {
        // Evict this enclave's entry from the hot-cache slab so that the
        // plaintext key bytes are wiped immediately when the owning CryptoKey
        // is dropped (e.g. on cache eviction), rather than waiting for LRU
        // pressure to evict them.
        //
        // SLAB.lock() can `panic` if the slab mutex is poisoned (a previous
        // holder panicked) or if this Drop runs during another panic
        // unwind. A double-panic would abort the process and skip every
        // other Drop in the unwind path — including page-wipes for other
        // CryptoKeys. Catch and log instead. T-finding "Enclave::Drop
        // takes SLAB.lock(); reachable from a panic unwind" in
        // `docs/review-2026-05-05-findings.md`.
        let id = self.id;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            cache_evict(id);
        }));
        if let Err(payload) = result {
            // Don't `resume_unwind` — that would re-trigger the
            // double-panic abort we're trying to avoid. Just log.
            let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic payload".to_string()
            };
            log::error!("Enclave::drop: cache_evict({id}) panicked: {msg}");
        }
    }
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
        // Destruct path: best-effort scramble before destroy. On OsRng failure
        // the buffer is zero-filled by scramble_bytes (see its docs); destroy
        // then runs and overwrites again, so an OsRng outage here is safe.
        drop(buf.scramble());
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

/// Maximum time `pool_acquire` / `coffer_view` will wait for a slab slot
/// before returning `Error::OutOfSlots`. 30 seconds is generous enough
/// that genuine traffic spikes don't trip it but short enough that a
/// leaked `PoolSlot` (FFI caller forgot `pool_release`) shows up as a
/// loud error rather than a hung process.
const POOL_ACQUIRE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);
const COFFER_LEFT: usize = 0;
const COFFER_RIGHT: usize = 1;
const FIRST_SHARED_SLOT: usize = 2;

struct SecureSlab {
    #[allow(dead_code)]
    _page: Buffer,
    base: *mut u8,
    slot_count: usize,

    // Free list of shared slot indices (LIFO for cache locality).
    free: Vec<usize>,

    // Slots currently checked out as transient PoolSlot handles. A slot is
    // in exactly one of three states at any moment: on the `free` list, in
    // `cache_lru`/`cache_map`, or in `transient`. The set lets us assert
    // single-release and gives explicit positive tracking that
    // `acquire_slot` will not re-issue or evict an outstanding slot. See
    // T2 in `docs/review-2026-05-05-findings.md`.
    transient: HashSet<usize>,

    // Hot key cache: maps enclave_id → slot index.
    cache_map: HashMap<u64, usize>,
    cache_slot_to_id: Vec<u64>, // slot_idx → enclave_id (0 = not cached)
    cache_lru: VecDeque<usize>, // front = least recently used
}

// SAFETY: `base` is a `*mut u8` derived from the `mmap`'d, `mlock`'d page
// owned by `_page`. The page lives for the lifetime of `SecureSlab` (we
// never replace `_page`), and access through `base` only happens via the
// `Mutex<SecureSlab>` wrapper around the static `SLAB`. Sending the slab
// across threads is therefore equivalent to sending the owned buffer plus
// the index/cache state, which contains no thread-local invariants.
// `SecureSlab` is intentionally NOT `Sync` — concurrent shared access
// would race on `free`, `transient`, `cache_lru`, and `cache_map`.
unsafe impl Send for SecureSlab {}

impl SecureSlab {
    fn new() -> Result<Self, Error> {
        Lazy::force(&INIT);
        let ps = *PAGE_SIZE;
        let mut page = Buffer::new(ps)?;
        let base = page.bytes().as_mut_ptr();
        wipe_bytes(page.bytes());
        let slot_count = ps / SLOT_SIZE;

        // Initialize Coffer: slots 0 (left) and 1 (right). Both halves are
        // crypto-critical — they form the AES-256 master key for every
        // Enclave seal/unseal. If OsRng fails we MUST propagate; a silent
        // zero-fill here would let the system run with a known master key.
        let left = unsafe { std::slice::from_raw_parts_mut(base, SLOT_SIZE) };
        scramble_bytes(left)?;
        let right = unsafe { std::slice::from_raw_parts_mut(base.add(SLOT_SIZE), SLOT_SIZE) };
        scramble_bytes(right)?;
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
            transient: HashSet::with_capacity(shared_count),
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
    /// `exclude` prevents evicting a specific cache slot (used when the
    /// caller holds a reference to that slot).
    ///
    /// The returned index is OFF the free list and OFF `cache_lru`. The
    /// caller is responsible for placing it into exactly one of:
    ///
    /// - `self.transient` (via `acquire_transient_slot`) — for handles
    ///   returned to user code as `PoolSlot`.
    /// - `cache_lru` + `cache_map` — for `cache_insert`.
    ///
    /// Failing to do this is a leak; doing it twice is a soundness bug.
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

    /// Like `acquire_slot` but records the slot in `transient` so a
    /// concurrent `release_slot` for the same idx can be detected, and so
    /// the slot is observably "checked out" rather than just absent.
    fn acquire_transient_slot(&mut self, exclude: Option<usize>) -> Option<usize> {
        let idx = self.acquire_slot(exclude)?;
        debug_assert!(
            !self.transient.contains(&idx),
            "acquire_transient_slot: slot {idx} was already transient — \
             slab invariant violation",
        );
        self.transient.insert(idx);
        Some(idx)
    }

    /// Reconstruct the Coffer master key into a transient slot.
    fn coffer_view(&mut self) -> Option<PoolSlot> {
        let out_idx = self.acquire_transient_slot(None)?;
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
    ///
    /// Returns `Err` if OsRng fails: a silent zero-fill of the master key
    /// would silently break enclave protection for every key sealed after
    /// the rekey. Callers (purge) propagate.
    fn rekey_coffer(&mut self) -> Result<(), Error> {
        let left = self.slot_slice_mut(COFFER_LEFT);
        scramble_bytes(left)?;
        let right = self.slot_slice_mut(COFFER_RIGHT);
        scramble_bytes(right)?;
        let hr = hash(right);
        let left = self.slot_slice_mut(COFFER_LEFT);
        for (slot, hash_byte) in left.iter_mut().zip(hr.iter()) {
            *slot ^= hash_byte;
        }
        Ok(())
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
        let out_idx = self.acquire_transient_slot(Some(src_idx))?;
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

    /// Remove one entry from the hot cache by enclave_id, wiping its slot.
    fn cache_remove(&mut self, enclave_id: u64) {
        if let Some(&slot_idx) = self.cache_map.get(&enclave_id) {
            wipe_bytes(self.slot_slice_mut(slot_idx));
            self.cache_slot_to_id[slot_idx] = 0;
            self.cache_lru.retain(|&i| i != slot_idx);
            self.free.push(slot_idx);
            self.cache_map.remove(&enclave_id);
        }
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

    /// Release a transient slot back to the free list. Asserts the slot
    /// was actually checked out as transient — a release without a prior
    /// `acquire_transient_slot` (or a double release) indicates a leaked
    /// or duplicated PoolSlot.
    fn release_slot(&mut self, idx: usize) {
        debug_assert!(idx >= FIRST_SHARED_SLOT && idx < self.slot_count);
        debug_assert!(
            self.transient.remove(&idx),
            "release_slot: slot {idx} was not in transient set — double \
             release or release without acquire",
        );
        debug_assert!(
            !self.free.contains(&idx),
            "release_slot: slot {idx} already on free list",
        );
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

// SAFETY for `Send`:
//   - SlotOrigin::Slab: `ptr` references a slot inside the static `SLAB`'s
//     `mmap`'d page. The page outlives any individual `PoolSlot`. While a
//     `PoolSlot` exists, the slot index it references is recorded in
//     `SecureSlab::transient`; `acquire_slot` never returns a transient idx
//     and `release_slot` debug-asserts the idx is in `transient` before
//     reusing it. Crossing a thread boundary therefore transfers exclusive
//     ownership of those bytes — there is no concurrent access via the
//     slab data structures.
//   - SlotOrigin::Standalone: the wrapped `Buffer` exclusively owns its
//     `mmap`/`mlock`'d region; sending it is equivalent to sending an
//     owned `Box<[u8]>`.
// `PoolSlot` deliberately does NOT implement `Sync`. The `bytes()` and
// `as_slice()` methods hand out exclusive references to the underlying
// region, and concurrent `&PoolSlot` access from two threads would alias
// these references.
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
    if let Some(idx) = slab.acquire_transient_slot(None) {
        return Ok(PoolSlot {
            ptr: slab.slot_ptr(idx),
            len: SLOT_SIZE,
            origin: SlotOrigin::Slab,
        });
    }
    // All slots are held transiently — wait for one to be released, with
    // a hard deadline so a leaked PoolSlot (FFI caller forgot to release)
    // can't deadlock the pool indefinitely. T-finding "SLAB_CV.wait holds
    // MutexGuard indefinitely" in `docs/review-2026-05-05-findings.md`.
    //
    // The loop has two exit paths:
    //   - a slot becomes free (notify_one wakes us); we acquire and return
    //   - we exceed `POOL_ACQUIRE_DEADLINE`; bail with `OutOfSlots` so the
    //     caller can fall back to a standalone allocation or surface the
    //     error rather than block forever
    let start = std::time::Instant::now();
    loop {
        let remaining = POOL_ACQUIRE_DEADLINE.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            log::error!(
                "pool_acquire: timed out after {POOL_ACQUIRE_DEADLINE:?} waiting for a \
                 slab slot; suspected PoolSlot leak"
            );
            return Err(Error::OutOfSlots);
        }
        SLAB_CV.wait_for(&mut slab, remaining);
        if let Some(idx) = slab.acquire_transient_slot(None) {
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
    let start = std::time::Instant::now();
    loop {
        if let Some(slot) = slab.coffer_view() {
            return Ok(slot);
        }
        let remaining = POOL_ACQUIRE_DEADLINE.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            log::error!(
                "coffer_view: timed out after {POOL_ACQUIRE_DEADLINE:?} waiting for a slab slot"
            );
            return Err(Error::OutOfSlots);
        }
        SLAB_CV.wait_for(&mut slab, remaining);
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

/// Remove an entry from the hot cache by enclave_id, wiping the slab slot.
/// Called from Enclave::drop so that key bytes in the slab are wiped as soon
/// as the CryptoKey that holds the Enclave is dropped (e.g. on cache eviction).
fn cache_evict(enclave_id: u64) {
    SLAB.lock().cache_remove(enclave_id);
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
        // Crypto-critical: a caller asking for a "random" buffer is using it
        // as key material. Propagate OsRng failure rather than handing back
        // a zero-filled buffer that the caller will treat as random.
        b.scramble()?;
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
    pub fn scramble(&self) -> Result<(), Error> {
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
        slab.rekey_coffer()?;
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
        // The previous `Signals::new(...).expect("signals")` aborted the
        // spawned thread on EAGAIN/seccomp-restricted hosts and left the
        // user with no signal handling at all (T4 in
        // `docs/review-2026-05-05-findings.md`). Surface the failure to the
        // user-supplied handler instead — they can log, retry, or exit.
        let mut sigs = match Signals::new(&signals_vec) {
            Ok(s) => s,
            Err(e) => {
                log::error!("catch_signal: signal_hook init failed: {e}");
                handler(Err(e));
                return;
            }
        };
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
/// Streaming-mode chunk size, exposed for advanced callers that build
/// streaming pipelines on top of `memguard` primitives. Stored as an
/// `AtomicUsize` rather than a `pub static mut` so reads and writes are
/// well-defined under concurrent access (T17/finding #3 in
/// `docs/review-2026-05-05-findings.md`). Use `set_stream_chunk_size` /
/// `stream_chunk_size` instead of dereferencing the static directly.
pub static STREAM_CHUNK_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Read the configured streaming chunk size. Defaults to 0 when unset.
pub fn stream_chunk_size() -> usize {
    STREAM_CHUNK_SIZE.load(Ordering::Relaxed)
}

/// Configure the streaming chunk size. Pass 0 to clear.
pub fn set_stream_chunk_size(value: usize) {
    STREAM_CHUNK_SIZE.store(value, Ordering::Relaxed);
}
