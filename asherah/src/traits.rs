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
    /// Replace the reserved internal configuration drift guard record.
    ///
    /// Normal key records must remain insert-if-absent; this hook exists only
    /// for the explicit drift-guard repair path.
    fn upsert_config_drift_guard(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<(), anyhow::Error> {
        if self.store(id, created, ekr)? {
            Ok(())
        } else {
            anyhow::bail!("metastore does not support replacing config drift guard records")
        }
    }
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
    async fn upsert_config_drift_guard_async(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<(), anyhow::Error> {
        self.upsert_config_drift_guard(id, created, ekr)
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

/// Async counterpart to [`Storer`]: persist a [`DataRowRecord`] without
/// blocking the calling executor. Use with
/// [`crate::session::PublicSession::store_async`].
///
/// The `Send + Sync` supertrait lets the returned future cross `.await`
/// points in a multi-threaded runtime (e.g. an axum handler), matching the
/// async metastore/KMS paths.
#[async_trait]
pub trait StorerAsync: Send + Sync {
    async fn store_async(
        &self,
        d: &crate::types::DataRowRecord,
    ) -> Result<serde_json::Value, anyhow::Error>;
}

/// Async counterpart to [`Loader`]. Use with
/// [`crate::session::PublicSession::load_async`].
#[async_trait]
pub trait LoaderAsync: Send + Sync {
    async fn load_async(
        &self,
        key: &serde_json::Value,
    ) -> Result<Option<crate::types::DataRowRecord>, anyhow::Error>;
}

/// Async counterpart to [`StorerCtx`] (the context is an unused placeholder
/// that mirrors Go's signatures). Use with
/// [`crate::session::PublicSession::store_ctx_async`].
#[async_trait]
pub trait StorerCtxAsync: Send + Sync {
    async fn store_ctx_async(
        &self,
        _ctx: &(),
        d: &crate::types::DataRowRecord,
    ) -> Result<serde_json::Value, anyhow::Error>;
}

/// Async counterpart to [`LoaderCtx`]. Use with
/// [`crate::session::PublicSession::load_ctx_async`].
#[async_trait]
pub trait LoaderCtxAsync: Send + Sync {
    async fn load_ctx_async(
        &self,
        _ctx: &(),
        key: &serde_json::Value,
    ) -> Result<Option<crate::types::DataRowRecord>, anyhow::Error>;
}
