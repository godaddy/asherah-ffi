use hardware_enclave::{pool_release, MemoryEnclave, SecureBuffer};
use zeroize::Zeroize as _;
use zeroize::Zeroizing;

const SLOT_SIZE: usize = 32; // AES-256 key size (matches hardware_enclave pool slot size)

pub struct CryptoKey {
    created: i64,
    revoked: bool,
    secret: MemoryEnclave,
    /// Pre-expanded AES-256-GCM key schedule (avoids re-expansion on every use).
    /// See aead.rs for nonce safety documentation.
    cached_key: Option<crate::aead::PreparedAes256GcmKey>,
}

// The prepared key state may not impl Debug and must not expose key-equivalent
// material if it ever does.
impl std::fmt::Debug for CryptoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoKey")
            .field("created", &self.created)
            .field("revoked", &self.revoked)
            .field("secret", &self.secret)
            .field("cached_key", &self.cached_key.is_some())
            .finish()
    }
}

impl CryptoKey {
    pub fn new(created: i64, revoked: bool, bytes: Vec<u8>) -> anyhow::Result<Self> {
        Self::new_with_key_schedule_cache(created, revoked, bytes, true)
    }

    pub fn new_with_key_schedule_cache(
        created: i64,
        revoked: bool,
        bytes: Vec<u8>,
        cache_key_schedule: bool,
    ) -> anyhow::Result<Self> {
        let mut bytes = Zeroizing::new(bytes);
        // Pre-expand key schedule for 32-byte keys. Surface preparation errors
        // rather than silently falling through to the raw-key path so a backend
        // feature or hardware mismatch is visible during key load/create.
        let cached_key = if cache_key_schedule && bytes.len() == SLOT_SIZE {
            Some(crate::aead::prepare_key(bytes.as_slice()).map_err(|e| {
                anyhow::anyhow!("internal: failed to prepare 32-byte AES-256-GCM key state: {e}")
            })?)
        } else {
            None
        };
        let enclave = if bytes.len() == SLOT_SIZE {
            // Fast path for 32-byte keys: seal directly from the Vec without
            // allocating a page-locked Buffer. The Enclave immediately encrypts
            // the key and stores it in the SLAB hot cache. This avoids 6 syscalls
            // (mmap, mlock, 2× mprotect, munlock, munmap) per key.
            let enc = MemoryEnclave::seal(bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("failed to seal key into enclave: {:?}", e))?;
            bytes.zeroize();
            enc
        } else {
            let mut buf = SecureBuffer::new(bytes.len()).map_err(|e| {
                anyhow::anyhow!(
                    "failed to allocate secure buffer ({} bytes): {:?}",
                    bytes.len(),
                    e
                )
            })?;
            buf.bytes().copy_from_slice(bytes.as_slice());
            bytes.zeroize();
            MemoryEnclave::seal_buffer(&mut buf)
                .map_err(|e| anyhow::anyhow!("failed to seal key into enclave: {:?}", e))?
        };
        Ok(Self {
            created,
            revoked,
            secret: enclave,
            cached_key,
        })
    }
    pub fn created(&self) -> i64 {
        self.created
    }
    pub fn revoked(&self) -> bool {
        self.revoked
    }
    /// Returns the prepared AES-256-GCM key state if available (32-byte keys).
    pub fn prepared_key(&self) -> Option<&crate::aead::PreparedAes256GcmKey> {
        self.cached_key.as_ref()
    }

    /// Backwards-compatible alias for older internal tests/callers.
    pub fn less_safe_key(&self) -> Option<&crate::aead::PreparedAes256GcmKey> {
        self.prepared_key()
    }
    pub fn with_key_func<R>(&self, f: impl FnOnce(&[u8]) -> R) -> anyhow::Result<R> {
        let buf = self
            .secret
            .open()
            .map_err(|e| anyhow::anyhow!("failed to open key enclave: {:?}", e))?;
        // Guard the caller closure with `catch_unwind` so a panic
        // doesn't leak the borrowed slot from the SLAB pool. Without
        // this, a panic in `f(...)` would unwind past the
        // `pool_release` call and the slot would stay marked as in
        // use forever — eventually exhausting the pool. Repackage
        // any payload as an anyhow error so the caller can decide
        // whether to bubble or recover. T-finding "with_key_func
        // lacks panic guard; closure panic leaks buffer from pool"
        // in `docs/review-2026-05-05-findings.md`.
        let key_len = self.secret.plaintext_len();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f(&buf.as_slice()[..key_len])
        }));
        pool_release(buf);
        match result {
            Ok(r) => Ok(r),
            Err(payload) => {
                let msg = payload
                    .downcast_ref::<&str>()
                    .copied()
                    .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                    .unwrap_or("(non-string panic payload)");
                Err(anyhow::anyhow!(
                    "CryptoKey::with_key_func: closure panicked: {msg}"
                ))
            }
        }
    }
}

pub fn generate_key(created: i64) -> anyhow::Result<CryptoKey> {
    generate_key_with_key_schedule_cache(created, true)
}

pub fn generate_key_with_key_schedule_cache(
    created: i64,
    cache_key_schedule: bool,
) -> anyhow::Result<CryptoKey> {
    let mut raw = Zeroizing::new(vec![0_u8; SLOT_SIZE]);
    crate::aead::fast_random_bytes(raw.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("failed to generate AES key: {e}"))?;
    let raw = std::mem::take(&mut *raw);
    CryptoKey::new_with_key_schedule_cache(created, false, raw, cache_key_schedule)
}

pub fn is_key_expired(created_s: i64, expire_after_s: i64, now_s: i64) -> bool {
    now_s - created_s >= expire_after_s
}
