use crate::memguard::{wipe_bytes, Buffer, Enclave};
use ring::aead::{LessSafeKey, UnboundKey, AES_256_GCM};

pub struct CryptoKey {
    created: i64,
    revoked: bool,
    secret: Enclave,
    /// Pre-expanded AES-256-GCM key schedule (avoids re-expansion on every use).
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
    pub fn new(created: i64, revoked: bool, mut bytes: Vec<u8>) -> anyhow::Result<Self> {
        // Pre-expand key schedule for 32-byte keys
        let cached_lsk = if bytes.len() == 32 {
            UnboundKey::new(&AES_256_GCM, &bytes)
                .ok()
                .map(LessSafeKey::new)
        } else {
            None
        };
        let mut buf = Buffer::new(bytes.len()).map_err(|e| {
            anyhow::anyhow!(
                "failed to allocate secure buffer ({} bytes): {:?}",
                bytes.len(),
                e
            )
        })?;
        buf.bytes().copy_from_slice(&bytes);
        wipe_bytes(&mut bytes);
        let enclave = Enclave::new_from(&mut buf)
            .map_err(|e| anyhow::anyhow!("failed to seal key into enclave: {:?}", e))?;
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
    /// Returns the pre-expanded LessSafeKey if available (32-byte AES-256 keys).
    pub fn less_safe_key(&self) -> Option<&LessSafeKey> {
        self.cached_lsk.as_ref()
    }
    pub fn with_key_func<R>(&self, f: impl FnOnce(&[u8]) -> R) -> anyhow::Result<R> {
        let buf = self
            .secret
            .open()
            .map_err(|e| anyhow::anyhow!("failed to open key enclave: {:?}", e))?;
        let result = f(buf.as_slice());
        crate::memguard::pool_release(buf);
        Ok(result)
    }
}

pub fn generate_key(created: i64) -> anyhow::Result<CryptoKey> {
    let mut raw = vec![0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut raw)
        .map_err(|e| anyhow::anyhow!("OsRng: {e}"))?;
    CryptoKey::new(created, false, raw)
}

pub fn is_key_expired(created_s: i64, expire_after_s: i64, now_s: i64) -> bool {
    now_s - created_s >= expire_after_s
}

use rand::TryRngCore;
