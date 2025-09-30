use crate::traits::KeyManagementService;
use crate::traits::AEAD;
use std::sync::Arc;

#[derive(Clone)]
pub struct StaticKMS<A: AEAD + Send + Sync + 'static> {
    aead: Arc<A>,
    master_key: Vec<u8>,
}

impl<A: AEAD + Send + Sync + 'static> StaticKMS<A> {
    pub fn new(aead: Arc<A>, master_key: Vec<u8>) -> Self {
        Self { aead, master_key }
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
