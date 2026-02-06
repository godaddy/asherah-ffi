use crate::traits::KeyManagementService;
use crate::traits::AEAD;
use std::sync::Arc;

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct StaticKMS<A: AEAD + Send + Sync + 'static> {
    aead: Arc<A>,
    master_key: Vec<u8>,
}

impl<A: AEAD + Send + Sync + 'static> StaticKMS<A> {
    pub fn new(aead: Arc<A>, master_key: Vec<u8>) -> anyhow::Result<Self> {
        if master_key.len() != 32 {
            return Err(anyhow::anyhow!(
                "invalid key size {}, must be 32 bytes",
                master_key.len()
            ));
        }
        Ok(Self { aead, master_key })
    }
}

impl<A: AEAD + Send + Sync + 'static> KeyManagementService for StaticKMS<A> {
    fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.aead.encrypt(key_bytes, &self.master_key)
    }
    fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.aead.decrypt(blob, &self.master_key)
    }
}
