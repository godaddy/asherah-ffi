use crate::types::EnvelopeKeyRecord;
use async_trait::async_trait;

pub trait AEAD: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error>;
    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error>;
}

#[async_trait]
pub trait KeyManagementService: Send + Sync {
    fn encrypt_key(&self, ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error>;
    fn decrypt_key(&self, ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error>;

    /// Async variant — defaults to calling the sync method.
    /// AWS KMS implementations override this with native `.await`.
    async fn encrypt_key_async(
        &self,
        ctx: &(),
        key_bytes: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        self.encrypt_key(ctx, key_bytes)
    }
    async fn decrypt_key_async(&self, ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.decrypt_key(ctx, blob)
    }
}

#[async_trait]
pub trait Metastore: Send + Sync {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error>;
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error>;
    fn store(&self, id: &str, created: i64, ekr: &EnvelopeKeyRecord)
        -> Result<bool, anyhow::Error>;
    fn region_suffix(&self) -> Option<String> {
        None
    }

    /// Async variant — defaults to calling the sync method.
    /// DynamoDB overrides this with native `.await`.
    async fn load_async(
        &self,
        id: &str,
        created: i64,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        self.load(id, created)
    }
    async fn load_latest_async(
        &self,
        id: &str,
    ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        self.load_latest(id)
    }
    async fn store_async(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        self.store(id, created, ekr)
    }
}

pub trait Partition: Send + Sync {
    fn system_key_id(&self) -> String;
    fn intermediate_key_id(&self) -> String;
    fn is_valid_intermediate_key_id(&self, id: &str) -> bool;
}

pub trait Loader {
    fn load(
        &self,
        key: &serde_json::Value,
    ) -> Result<Option<crate::types::DataRowRecord>, anyhow::Error>;
}

pub trait Storer {
    fn store(&self, d: &crate::types::DataRowRecord) -> Result<serde_json::Value, anyhow::Error>;
}

// Context-aware variants to mirror Go's context signatures
pub trait LoaderCtx {
    fn load_ctx(
        &self,
        _ctx: &(),
        key: &serde_json::Value,
    ) -> Result<Option<crate::types::DataRowRecord>, anyhow::Error>;
}

pub trait StorerCtx {
    fn store_ctx(
        &self,
        _ctx: &(),
        d: &crate::types::DataRowRecord,
    ) -> Result<serde_json::Value, anyhow::Error>;
}
