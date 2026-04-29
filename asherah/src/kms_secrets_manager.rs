// AWS Secrets Manager KMS — fetches a static master key from Secrets Manager
// at construction time and uses it for the lifetime of the process.
// This is a security posture improvement over KMS=static (key not in env vars)
// but NOT a key management improvement (no rotation without re-encryption).

use std::sync::Arc;

use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_secretsmanager::{config::Region, Client};

use crate::traits::{KeyManagementService, AEAD};

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct SecretsManagerKMS<A: AEAD + Send + Sync + 'static> {
    aead: Arc<A>,
    master_key: Vec<u8>,
}

impl<A: AEAD + Send + Sync + 'static> SecretsManagerKMS<A> {
    /// Sync constructor — fetches the secret from Secrets Manager, blocking on a
    /// tokio runtime. The secret must be either:
    /// - A hex-encoded 32-byte key (64 hex characters) stored as SecretString, or
    /// - A raw 32-byte value stored as SecretBinary.
    ///
    /// `aws_profile_name` selects an aws-config named profile (typically
    /// from `~/.aws/credentials`); pass `None` for the default credential
    /// chain.
    pub fn new(
        aead: Arc<A>,
        secret_id: impl Into<String>,
        region: Option<String>,
        aws_profile_name: Option<&str>,
    ) -> anyhow::Result<Self> {
        let secret_id = secret_id.into();
        let handle = tokio::runtime::Handle::try_current().ok();
        let rt = if handle.is_some() {
            None
        } else {
            Some(tokio::runtime::Runtime::new()?)
        };
        let fetch_fut = fetch_secret(&secret_id, region, aws_profile_name);
        let master_key = match (&rt, handle) {
            (Some(rt), _) => {
                if tokio::runtime::Handle::try_current().is_ok() {
                    tokio::task::block_in_place(|| rt.block_on(fetch_fut))
                } else {
                    rt.block_on(fetch_fut)
                }
            }
            (None, Some(h)) => tokio::task::block_in_place(|| h.block_on(fetch_fut)),
            (None, None) => unreachable!("tokio runtime unavailable"),
        }?;
        log::warn!(
            "Using static master key from Secrets Manager (secret_id={secret_id}). \
             This is better than an environment variable but the key is still static — \
             there is no automatic rotation of the master key."
        );
        Ok(Self { aead, master_key })
    }

    /// Async constructor — fetches the secret on the caller's runtime.
    pub async fn new_async(
        aead: Arc<A>,
        secret_id: impl Into<String>,
        region: Option<String>,
        aws_profile_name: Option<&str>,
    ) -> anyhow::Result<Self> {
        let secret_id = secret_id.into();
        let master_key = fetch_secret(&secret_id, region, aws_profile_name).await?;
        log::warn!(
            "Using static master key from Secrets Manager (secret_id={secret_id}). \
             This is better than an environment variable but the key is still static — \
             there is no automatic rotation of the master key."
        );
        Ok(Self { aead, master_key })
    }
}

/// Fetch a 32-byte master key from AWS Secrets Manager.
///
/// Tries SecretString first (hex-encoded), then SecretBinary (raw 32 bytes).
async fn fetch_secret(
    secret_id: &str,
    region: Option<String>,
    aws_profile_name: Option<&str>,
) -> anyhow::Result<Vec<u8>> {
    let region_provider = if let Some(r) = region {
        RegionProviderChain::first_try(Region::new(r))
    } else {
        RegionProviderChain::default_provider()
    };
    let shared_config =
        crate::aws_sdk_load::load_sdk_config(region_provider, aws_profile_name).await;
    let mut b = aws_sdk_secretsmanager::config::Builder::from(&shared_config);
    if let Ok(url) = std::env::var("AWS_ENDPOINT_URL") {
        b = b.endpoint_url(url);
    }
    let client = Client::from_conf(b.build());

    let resp = client
        .get_secret_value()
        .secret_id(secret_id)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Secrets Manager GetSecretValue failed: {e}"))?;

    // Prefer SecretString (hex-encoded) over SecretBinary
    if let Some(hex) = resp.secret_string() {
        let hex = hex.trim();
        if hex.len() % 2 != 0 {
            anyhow::bail!(
                "Secrets Manager secret has odd-length hex string ({} chars)",
                hex.len()
            );
        }
        let mut key = vec![0_u8; hex.len() / 2];
        for i in 0..key.len() {
            key[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| {
                anyhow::anyhow!(
                    "Secrets Manager secret contains invalid hex at position {}",
                    2 * i
                )
            })?;
        }
        if key.len() != 32 {
            anyhow::bail!(
                "Secrets Manager secret decoded to {} bytes, expected 32",
                key.len()
            );
        }
        return Ok(key);
    }

    if let Some(blob) = resp.secret_binary() {
        let bytes = blob.as_ref();
        if bytes.len() != 32 {
            anyhow::bail!(
                "Secrets Manager SecretBinary is {} bytes, expected 32",
                bytes.len()
            );
        }
        return Ok(bytes.to_vec());
    }

    anyhow::bail!("Secrets Manager secret '{secret_id}' has neither SecretString nor SecretBinary")
}

#[async_trait]
impl<A: AEAD + Send + Sync + 'static> KeyManagementService for SecretsManagerKMS<A> {
    fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.aead.encrypt(key_bytes, &self.master_key).map_err(|e| {
            log::error!("SecretsManagerKMS encrypt_key failed: {e:#}");
            e
        })
    }
    fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.aead.decrypt(blob, &self.master_key).map_err(|e| {
            log::error!(
                "SecretsManagerKMS decrypt_key failed (blob_len={}): {e:#}",
                blob.len()
            );
            e
        })
    }
}
