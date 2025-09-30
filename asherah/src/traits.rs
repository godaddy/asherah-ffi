use crate::types::EnvelopeKeyRecord;

pub trait AEAD: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error>;
    fn decrypt(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error>;
}

pub trait KeyManagementService: Send + Sync {
    fn encrypt_key(&self, ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error>;
    fn decrypt_key(&self, ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error>;
}

pub trait Metastore: Send + Sync {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error>;
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error>;
    fn store(&self, id: &str, created: i64, ekr: &EnvelopeKeyRecord)
        -> Result<bool, anyhow::Error>;
    fn region_suffix(&self) -> Option<String> {
        None
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
