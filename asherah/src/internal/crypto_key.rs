use hardware_enclave::{pool_release, MemoryEnclave, SecureBuffer};
use zeroize::Zeroize as _;
use zeroize::Zeroizing;

const SLOT_SIZE: usize = 32; // AES-256 key size (matches hardware_enclave pool slot size)
                             // LessSafeKey: safe in our usage — encryption always uses a fresh random nonce
                             // per operation (see aead.rs). The cached key schedule is a performance
                             // optimization that avoids re-expanding the AES key on every encrypt/decrypt.
use ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM};

pub struct CryptoKey {
    created: i64,
    revoked: bool,
    secret: MemoryEnclave,
    /// Pre-expanded AES-256-GCM key schedule (avoids re-expansion on every use).
    /// See aead.rs for nonce safety documentation.
    cached_lsk: Option<LessSafeKey>,
}

// LessSafeKey doesn't impl Debug
impl std::fmt::Debug for CryptoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoKey")
            .field("created", &self.created)
            .field("revoked", &self.revoked)
            .field("secret", &self.secret)
            .field("cached_lsk", &self.cached_lsk.is_some())
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
        // Pre-expand key schedule for 32-byte keys.
        //
        // `UnboundKey::new` returns Err only for an algorithm/key-length
        // mismatch. We've already gated on `bytes.len() == 32` for
        // AES-256-GCM, so the error path is unreachable. Surface a
        // contextual error rather than the previous `.ok()` silent
        // discard so that a future regression (changing the gate
        // without updating the algo) doesn't disappear into a
        // `cached_lsk: None` and silently fall through to the
        // not-cached path. T-finding "UnboundKey::new(&AES_256_GCM,
        // &bytes).ok() silently discards unreachable error" in
        // `docs/review-2026-05-05-findings.md`.
        let cached_lsk = if cache_key_schedule && bytes.len() == 32 {
            match UnboundKey::new(&AES_256_GCM, bytes.as_slice()) {
                Ok(k) => Some(LessSafeKey::new(k)),
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "internal: UnboundKey::new failed for 32-byte AES-256-GCM key — \
                         algorithm/key-length gate mismatch (please report)"
                    ));
                }
            }
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
            cached_lsk,
        })
    }
    pub fn created(&self) -> i64 {
        self.created
    }
    pub fn revoked(&self) -> bool {
        self.revoked
    }
    /// Returns the pre-expanded AES-256-GCM key if available (32-byte keys).
    /// Named `LessSafeKey` by ring because it doesn't enforce nonce uniqueness
    /// at the type level — our callers handle nonce generation correctly.
    pub fn less_safe_key(&self) -> Option<&LessSafeKey> {
        self.cached_lsk.as_ref()
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
    let mut raw = Zeroizing::new(vec![0_u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(raw.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("OsRng: {e}"))?;
    let raw = std::mem::take(&mut *raw);
    CryptoKey::new_with_key_schedule_cache(created, false, raw, cache_key_schedule)
}

pub fn is_key_expired(created_s: i64, expire_after_s: i64, now_s: i64) -> bool {
    now_s - created_s >= expire_after_s
}

use rand::TryRngCore;
