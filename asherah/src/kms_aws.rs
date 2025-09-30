use std::sync::Arc;

use aws_config::meta::region::RegionProviderChain;
use aws_sdk_kms::{config::Region, primitives::Blob, Client};

use crate::traits::{KeyManagementService, AEAD};

// AWS KMS adapter using AWS SDK for Rust (async under the hood, blocked on a Runtime)
#[derive(Clone)]
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
            let shared_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(region_provider)
                .load()
                .await;
            let mut b = aws_sdk_kms::config::Builder::from(&shared_config);
            if let Ok(url) = std::env::var("AWS_ENDPOINT_URL") {
                b = b.endpoint_url(url);
            }
            b.build()
        };
        let conf = match &rt {
            Some(rt) => rt.block_on(conf_fut),
            None => handle.unwrap().block_on(conf_fut),
        };
        let client = Client::from_conf(conf);
        Ok(Self {
            client,
            key_id: key_id.into(),
            _aead: aead,
            rt,
        })
    }
}

impl<A: AEAD + Send + Sync + 'static> KeyManagementService for AwsKms<A> {
    fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let fut = async {
            self.client
                .encrypt()
                .key_id(&self.key_id)
                .plaintext(Blob::new(key_bytes.to_vec()))
                .send()
                .await
        };
        let resp = match &self.rt {
            Some(rt) => rt.block_on(fut)?,
            None => {
                tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))?
            }
        };
        let ct = resp
            .ciphertext_blob()
            .ok_or_else(|| anyhow::anyhow!("missing ciphertext_blob"))?;
        Ok(ct.as_ref().to_vec())
    }

    fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let fut = async {
            self.client
                .decrypt()
                .key_id(&self.key_id)
                .ciphertext_blob(Blob::new(blob.to_vec()))
                .send()
                .await
        };
        let resp = match &self.rt {
            Some(rt) => rt.block_on(fut)?,
            None => {
                tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))?
            }
        };
        let pt = resp
            .plaintext()
            .ok_or_else(|| anyhow::anyhow!("missing plaintext"))?;
        Ok(pt.as_ref().to_vec())
    }
}
