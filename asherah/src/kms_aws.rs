use std::sync::Arc;

use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_kms::{config::Region, primitives::Blob, Client};

use crate::traits::{KeyManagementService, AEAD};

// AWS KMS adapter using AWS SDK for Rust (async under the hood, blocked on a Runtime)
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct AwsKms<A: AEAD + Send + Sync + 'static> {
    client: Client,
    key_id: String,
    _aead: Arc<A>, // kept for API symmetry and potential envelope helpers
    rt: Option<Arc<tokio::runtime::Runtime>>, // present when we created one
}

impl<A: AEAD + Send + Sync + 'static> AwsKms<A> {
    pub fn new(
        aead: Arc<A>,
        key_id: impl Into<String>,
        region: Option<String>,
    ) -> anyhow::Result<Self> {
        // Build a dedicated runtime to block_on AWS async calls
        // Attempt to use existing runtime when available to avoid nested-runtime issues
        let handle = tokio::runtime::Handle::try_current().ok();
        let rt = if handle.is_some() {
            None
        } else {
            Some(Arc::new(tokio::runtime::Runtime::new()?))
        };
        let region_provider = if let Some(r) = region {
            RegionProviderChain::first_try(Region::new(r))
        } else {
            RegionProviderChain::default_provider()
        };
        let conf_fut = async {
            let shared_config = crate::aws_sdk_load::load_sdk_config(region_provider, None).await;
            let mut b = aws_sdk_kms::config::Builder::from(&shared_config);
            if let Ok(url) = std::env::var("AWS_ENDPOINT_URL") {
                b = b.endpoint_url(url);
            }
            b.build()
        };
        let conf = match (&rt, handle) {
            (Some(rt), _) => {
                if tokio::runtime::Handle::try_current().is_ok() {
                    tokio::task::block_in_place(|| rt.block_on(conf_fut))
                } else {
                    rt.block_on(conf_fut)
                }
            }
            (None, Some(h)) => tokio::task::block_in_place(|| h.block_on(conf_fut)),
            (None, None) => unreachable!("tokio runtime unavailable"),
        };
        let client = Client::from_conf(conf);
        Ok(Self {
            client,
            key_id: key_id.into(),
            _aead: aead,
            rt,
        })
    }

    /// Async constructor — loads AWS config on the caller's tokio runtime.
    pub async fn new_async(
        aead: Arc<A>,
        key_id: impl Into<String>,
        region: Option<String>,
    ) -> anyhow::Result<Self> {
        let region_provider = if let Some(r) = region {
            RegionProviderChain::first_try(Region::new(r))
        } else {
            RegionProviderChain::default_provider()
        };
        let shared_config = crate::aws_sdk_load::load_sdk_config(region_provider, None).await;
        let mut b = aws_sdk_kms::config::Builder::from(&shared_config);
        if let Ok(url) = std::env::var("AWS_ENDPOINT_URL") {
            b = b.endpoint_url(url);
        }
        let conf = b.build();
        let client = Client::from_conf(conf);
        // Keep a runtime for sync callers (encrypt_key/decrypt_key)
        let rt = Some(Arc::new(tokio::runtime::Runtime::new()?));
        Ok(Self {
            client,
            key_id: key_id.into(),
            _aead: aead,
            rt,
        })
    }

    fn block_on_maybe<F: std::future::Future>(&self, f: F) -> F::Output {
        match &self.rt {
            Some(rt) => {
                if tokio::runtime::Handle::try_current().is_ok() {
                    tokio::task::block_in_place(|| rt.block_on(f))
                } else {
                    rt.block_on(f)
                }
            }
            None => match tokio::runtime::Handle::try_current() {
                Ok(h) => tokio::task::block_in_place(|| h.block_on(f)),
                Err(_) => tokio::runtime::Runtime::new()
                    .expect("failed to create temporary tokio runtime")
                    .block_on(f),
            },
        }
    }

    async fn encrypt_key_impl(&self, key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        log::debug!("AwsKms encrypt_key: key_id={}", self.key_id);
        let resp = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(Blob::new(key_bytes.to_vec()))
            .send()
            .await
            .map_err(|e| {
                log::error!(
                    "AwsKms encrypt_key failed: key_id={}, error={e:#}",
                    self.key_id
                );
                anyhow::anyhow!("KMS Encrypt call failed for key {}: {e}", self.key_id)
            })?;
        let ct = resp.ciphertext_blob().ok_or_else(|| {
            anyhow::anyhow!("KMS Encrypt returned no ciphertext for key {}", self.key_id)
        })?;
        Ok(ct.as_ref().to_vec())
    }

    async fn decrypt_key_impl(&self, blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        log::debug!(
            "AwsKms decrypt_key: key_id={}, blob_len={}",
            self.key_id,
            blob.len()
        );
        let resp = self
            .client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(Blob::new(blob.to_vec()))
            .send()
            .await
            .map_err(|e| {
                log::error!(
                    "AwsKms decrypt_key failed: key_id={}, error={e:#}",
                    self.key_id
                );
                anyhow::anyhow!("KMS Decrypt call failed for key {}: {e}", self.key_id)
            })?;
        let pt = resp.plaintext().ok_or_else(|| {
            anyhow::anyhow!("KMS Decrypt returned no plaintext for key {}", self.key_id)
        })?;
        Ok(pt.as_ref().to_vec())
    }
}

#[async_trait]
impl<A: AEAD + Send + Sync + 'static> KeyManagementService for AwsKms<A> {
    fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.block_on_maybe(self.encrypt_key_impl(key_bytes))
    }

    fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.block_on_maybe(self.decrypt_key_impl(blob))
    }

    async fn encrypt_key_async(
        &self,
        _ctx: &(),
        key_bytes: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        self.encrypt_key_impl(key_bytes).await
    }

    async fn decrypt_key_async(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.decrypt_key_impl(blob).await
    }
}
