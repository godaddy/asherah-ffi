use async_trait::async_trait;

use crate::traits::KeyManagementService;
use crate::traits::AEAD;
use std::sync::Arc;
use zeroize::Zeroizing;

#[allow(missing_debug_implementations)]
pub struct StaticKMS<A: AEAD + Send + Sync + 'static> {
    aead: Arc<A>,
    /// 32-byte AES master key. Wrapped in `Zeroizing` so the buffer is
    /// volatile-wiped when the `StaticKMS` (or any clone) is dropped — a
    /// raw `Vec<u8>` would leave the master key resident in the freed
    /// allocator slab. T-finding "master_key plaintext, never wiped" in
    /// `docs/review-2026-05-05-findings.md`.
    master_key: Arc<Zeroizing<Vec<u8>>>,
}

// Manual Clone: `Zeroizing` doesn't impl Clone, but the inner key is
// shared via `Arc` so cloning is just a refcount bump.
impl<A: AEAD + Send + Sync + 'static> Clone for StaticKMS<A> {
    fn clone(&self) -> Self {
        Self {
            aead: Arc::clone(&self.aead),
            master_key: Arc::clone(&self.master_key),
        }
    }
}

impl<A: AEAD + Send + Sync + 'static> StaticKMS<A> {
    pub fn new(aead: Arc<A>, master_key: Vec<u8>) -> anyhow::Result<Self> {
        // Wrap in `Zeroizing` immediately so any early-return path
        // (e.g., invalid key length below) wipes the moved-in
        // bytes before drop. The previous order validated length
        // first and dropped the parameter Vec without wiping on
        // the error path. T-finding "static master-key plaintext
        // Vec not wiped" in `docs/review-2026-05-05-findings.md`.
        let master_key = Zeroizing::new(master_key);
        if master_key.len() != 32 {
            return Err(anyhow::anyhow!(
                "invalid key size {}, must be 32 bytes",
                master_key.len()
            ));
        }
        Ok(Self {
            aead,
            master_key: Arc::new(master_key),
        })
    }
}

#[async_trait]
impl<A: AEAD + Send + Sync + 'static> KeyManagementService for StaticKMS<A> {
    fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.aead
            .encrypt(key_bytes, self.master_key.as_slice())
            .map_err(|e| {
                log::error!("StaticKMS encrypt_key failed: {e:#}");
                e
            })
    }
    fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.aead
            .decrypt(blob, self.master_key.as_slice())
            .map_err(|e| {
                log::error!(
                    "StaticKMS decrypt_key failed (blob_len={}): {e:#}",
                    blob.len()
                );
                e
            })
    }
}
