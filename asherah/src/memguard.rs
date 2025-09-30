// Embedded memguard (was memguard-rs)
// Provides locked, page-protected buffers and sealed enclaves.

use blake2::{Blake2b512, Digest};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use xsalsa20poly1305::aead::{Aead, KeyInit};
use xsalsa20poly1305::{Key, Nonce, XSalsa20Poly1305};
// use std::collections::VecDeque; // not used in this embedded subset
use crate::memcall; // use embedded memcall

const INTERVAL_MS: u64 = 500; // coffer rekey interval
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
    OsRng.fill_bytes(buf);
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

pub const OVERHEAD: usize = 24 + 16; // nonce + tag
pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 32 {
        return Err(Error::InvalidKeyLength);
    }
    let cipher = XSalsa20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut out = nonce.to_vec();
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::DecryptionFailed)?;
    out.extend_from_slice(&ct);
    Ok(out)
}
pub fn decrypt(ciphertext: &[u8], key: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    if key.len() != 32 {
        return Err(Error::InvalidKeyLength);
    }
    if output.len() < ciphertext.len().saturating_sub(OVERHEAD) {
        return Err(Error::BufferTooSmall);
    }
    if ciphertext.len() < OVERHEAD {
        return Err(Error::DecryptionFailed);
    }
    let cipher = XSalsa20Poly1305::new(Key::from_slice(key));
    let (nonce, ct) = ciphertext.split_at(24);
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| Error::DecryptionFailed)?;
    let n = pt.len();
    output[..n].copy_from_slice(&pt);
    Ok(n)
}

#[derive(Debug)]
pub struct Enclave {
    ciphertext: Vec<u8>,
}
impl Enclave {
    pub fn new_from(buf: &mut Buffer) -> Result<Self, Error> {
        let mut key = get_or_create_key().view()?;
        let ct = encrypt(buf.as_slice(), key.bytes())?;
        buf.melt()?;
        buf.scramble();
        buf.destroy()?;
        key.destroy()?;
        Ok(Self { ciphertext: ct })
    }
    pub fn open(&self) -> Result<Buffer, Error> {
        let mut out = Buffer::new(self.plaintext_len())?;
        let mut key = get_or_create_key().view()?;
        let n = decrypt(&self.ciphertext, key.bytes(), out.bytes())?;
        debug_assert_eq!(n, out.size());
        key.destroy()?;
        Ok(out)
    }
    pub fn plaintext_len(&self) -> usize {
        self.ciphertext.len().saturating_sub(OVERHEAD)
    }
    pub fn size(&self) -> usize {
        self.plaintext_len()
    }
}

use std::sync::{Arc, Weak};
#[derive(Debug)]
struct CofferInner {
    left: Buffer,
    right: Buffer,
    rand: Buffer,
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
    fn view(&mut self) -> Result<Buffer, Error> {
        let mut b = Buffer::new(32)?;
        let h = hash(self.right.as_slice());
        for (dst, (hash_byte, left_byte)) in
            b.bytes().iter_mut().zip(h.iter().zip(self.left.as_slice()))
        {
            *dst = hash_byte ^ left_byte;
        }
        b.freeze()?;
        Ok(b)
    }
    fn rekey(&mut self) -> Result<(), Error> {
        scramble_bytes(self.rand.bytes());
        let right_cur_h = hash(self.right.as_slice());
        for (slot, rnd) in self.right.bytes().iter_mut().zip(self.rand.as_slice()) {
            *slot ^= rnd;
        }
        let right_new_h = hash(self.right.as_slice());
        for ((slot, cur), new) in self
            .left
            .bytes()
            .iter_mut()
            .zip(right_cur_h.iter())
            .zip(right_new_h.iter())
        {
            *slot ^= cur ^ new;
        }
        Ok(())
    }
}
#[derive(Debug)]
pub struct Coffer(Arc<Mutex<CofferInner>>);
impl Coffer {
    pub fn new() -> Result<Self, Error> {
        let mut inner = CofferInner {
            left: Buffer::new(32)?,
            right: Buffer::new(32)?,
            rand: Buffer::new(32)?,
        };
        inner.init()?;
        let c = Coffer(Arc::new(Mutex::new(inner)));
        let weak = Arc::downgrade(&c.0);
        std::thread::spawn(move || {
            use std::time::Duration;
            loop {
                match weak.upgrade() {
                    None => break,
                    Some(strong) => {
                        let mut g = strong.lock();
                        let _ignored = g.rekey();
                        std::thread::sleep(Duration::from_millis(INTERVAL_MS));
                    }
                }
            }
        });
        Ok(c)
    }
    pub fn view(&self) -> Result<Buffer, Error> {
        self.0.lock().view()
    }
    pub fn destroy(&self) -> Result<(), Error> {
        let mut g = self.0.lock();
        let _left = g.left.destroy();
        let _right = g.right.destroy();
        let _rand = g.rand.destroy();
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
pub fn catch_interrupt() {
    catch_signal(&[libc::SIGINT], |_s| {});
}
static INIT: Lazy<()> = Lazy::new(|| {
    let _result = memcall::disable_core_dumps();
});
pub static mut STREAM_CHUNK_SIZE: usize = 0;
