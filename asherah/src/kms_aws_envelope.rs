use std::sync::Arc;

use aws_config::meta::region::RegionProviderChain;
use aws_sdk_kms::{config::Region, primitives::Blob, types::DataKeySpec, Client};

use crate::traits::{KeyManagementService, AEAD};

#[derive(Clone)]
struct RegionalClient {
    client: Client,
    region: String,
    key_arn: String, // provided key id/arn
}

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct AwsKmsEnvelope<A: AEAD + Send + Sync + 'static> {
    clients: Vec<RegionalClient>,
    preferred: usize,
    aead: Arc<A>,
    rt: Option<Arc<tokio::runtime::Runtime>>, // present when we created one
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KekEnvelope {
    #[serde(rename = "encryptedKey")]
    encrypted_key: Vec<u8>,
    #[serde(rename = "kmsKeks")]
    keks: Vec<RegionalKek>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RegionalKek {
    #[serde(rename = "region")]
    region: String,
    #[serde(rename = "arn")]
    arn: String,
    #[serde(rename = "encryptedKek")]
    encrypted_kek: Vec<u8>,
}

impl<A: AEAD + Send + Sync + 'static> AwsKmsEnvelope<A> {
    pub fn new_single(
        aead: Arc<A>,
        key_id: String,
        region: Option<String>,
    ) -> anyhow::Result<Self> {
        let (client, resolved_region, rt) = new_kms_client(region)?;
        let rc = RegionalClient {
            client,
            region: resolved_region,
            key_arn: key_id,
        };
        Ok(Self {
            clients: vec![rc],
            preferred: 0,
            aead,
            rt,
        })
    }

    pub fn new_multi(
        aead: Arc<A>,
        preferred: usize,
        entries: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        if entries.is_empty() {
            return Err(anyhow::anyhow!("no kms entries provided"));
        }
        // Build clients per entry; share one runtime if needed
        let mut rt: Option<Arc<tokio::runtime::Runtime>> = None;
        let mut clients = Vec::with_capacity(entries.len());
        for (region, key) in entries.into_iter() {
            let (client, resolved_region, new_rt) =
                new_kms_client_with_rt(region.clone(), rt.clone())?;
            if rt.is_none() {
                rt = new_rt;
            }
            clients.push(RegionalClient {
                client,
                region: resolved_region,
                key_arn: key,
            });
        }
        let pref = if preferred < clients.len() {
            preferred
        } else {
            0
        };
        Ok(Self {
            clients,
            preferred: pref,
            aead,
            rt,
        })
    }
}

fn new_kms_client(
    region: Option<String>,
) -> anyhow::Result<(Client, String, Option<Arc<tokio::runtime::Runtime>>)> {
    // Use existing runtime if present; else create one
    let handle = tokio::runtime::Handle::try_current().ok();
    let rt = if handle.is_some() {
        None
    } else {
        Some(Arc::new(tokio::runtime::Runtime::new()?))
    };
    let region_provider = if let Some(r) = region.clone() {
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
    let conf = match (&rt, handle) {
        (Some(rt), _) => rt.block_on(conf_fut),
        (None, Some(h)) => h.block_on(conf_fut),
        (None, None) => unreachable!("tokio runtime unavailable"),
    };
    let client = Client::from_conf(conf.clone());
    let resolved_region = conf
        .region()
        .map(|r| r.to_string())
        .unwrap_or(region.unwrap_or_default());
    Ok((client, resolved_region, rt))
}

fn new_kms_client_with_rt(
    region: String,
    rt: Option<Arc<tokio::runtime::Runtime>>,
) -> anyhow::Result<(Client, String, Option<Arc<tokio::runtime::Runtime>>)> {
    let handle = tokio::runtime::Handle::try_current().ok();
    let mut rt_local = rt;
    if handle.is_none() && rt_local.is_none() {
        rt_local = Some(Arc::new(tokio::runtime::Runtime::new()?));
    }
    let region_provider = RegionProviderChain::first_try(Region::new(region.clone()));
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
    let conf = match (&rt_local, handle) {
        (Some(rt), _) => rt.block_on(conf_fut),
        (None, Some(h)) => h.block_on(conf_fut),
        (None, None) => unreachable!(),
    };
    let client = Client::from_conf(conf.clone());
    let resolved_region = conf.region().map(|r| r.to_string()).unwrap_or(region);
    Ok((client, resolved_region, rt_local))
}

impl<A: AEAD + Send + Sync + 'static> KeyManagementService for AwsKmsEnvelope<A> {
    fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        // Generate data key in preferred region
        let pref = &self.clients[self.preferred];
        let fut = async {
            pref.client
                .generate_data_key()
                .key_id(pref.key_arn.clone())
                .key_spec(DataKeySpec::Aes256)
                .send()
                .await
        };
        let resp = match &self.rt {
            Some(rt) => rt.block_on(fut)?,
            None => {
                tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))?
            }
        };
        let plaintext = resp
            .plaintext()
            .ok_or_else(|| anyhow::anyhow!("missing plaintext"))?;
        let preferred_ciphertext = resp
            .ciphertext_blob()
            .ok_or_else(|| anyhow::anyhow!("missing ciphertext_blob"))?;
        let key_id = resp.key_id().unwrap_or("").to_string();

        // AEAD-encrypt the key with the plaintext data key
        let enc_key = self.aead.encrypt(key_bytes, plaintext.as_ref())?;

        // Encrypt KEK in all regions
        let mut keks: Vec<RegionalKek> = Vec::with_capacity(self.clients.len());
        for (i, c) in self.clients.iter().enumerate() {
            if i == self.preferred {
                keks.push(RegionalKek {
                    region: c.region.clone(),
                    arn: key_id.clone(),
                    encrypted_kek: preferred_ciphertext.as_ref().to_vec(),
                });
                continue;
            }
            let fut = async {
                c.client
                    .encrypt()
                    .key_id(&c.key_arn)
                    .plaintext(Blob::new(plaintext.as_ref().to_vec()))
                    .send()
                    .await
            };
            let out = match &self.rt {
                Some(rt) => rt.block_on(fut)?,
                None => {
                    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))?
                }
            };
            let blob = out
                .ciphertext_blob()
                .ok_or_else(|| anyhow::anyhow!("missing ciphertext_blob"))?;
            keks.push(RegionalKek {
                region: c.region.clone(),
                arn: c.key_arn.clone(),
                encrypted_kek: blob.as_ref().to_vec(),
            });
        }

        let env = KekEnvelope {
            encrypted_key: enc_key,
            keks,
        };
        let bytes = serde_json::to_vec(&env)?;
        Ok(bytes)
    }

    fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let env: KekEnvelope = serde_json::from_slice(blob)?;
        // Build map region->kek
        let mut map = std::collections::HashMap::new();
        for k in &env.keks {
            map.insert(k.region.as_str(), k);
        }
        // Try preferred first, then others
        for (i, c) in self.clients.iter().enumerate() {
            let reg_kek = match map.get(c.region.as_str()) {
                Some(k) => *k,
                None => continue,
            };
            let fut = async {
                c.client
                    .decrypt()
                    .key_id(&c.key_arn)
                    .ciphertext_blob(Blob::new(reg_kek.encrypted_kek.clone()))
                    .send()
                    .await
            };
            let out = match &self.rt {
                Some(rt) => rt.block_on(fut),
                None => {
                    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut))
                }
            };
            let out = match out {
                Ok(v) => v,
                Err(_) => {
                    if i == self.preferred { /* try fallbacks */ }
                    continue;
                }
            };
            let dk = match out.plaintext() {
                Some(p) => p.as_ref().to_vec(),
                None => continue,
            };
            if let Ok(key) = self.aead.decrypt(&env.encrypted_key, &dk) {
                return Ok(key);
            }
        }
        Err(anyhow::anyhow!("all KMS backends failed to decrypt"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_json_field_names_and_roundtrip() -> anyhow::Result<()> {
        let env = KekEnvelope {
            encrypted_key: vec![1, 2, 3],
            keks: vec![RegionalKek {
                region: "us-east-1".into(),
                arn: "arn:aws:kms:...".into(),
                encrypted_kek: vec![9, 8, 7],
            }],
        };
        let j = serde_json::to_string(&env)?;
        // Check JSON field names match Go
        assert!(j.contains("\"encryptedKey\""));
        assert!(j.contains("\"kmsKeks\""));
        assert!(j.contains("\"region\""));
        assert!(j.contains("\"arn\""));
        assert!(j.contains("\"encryptedKek\""));
        // Roundtrip
        let back: KekEnvelope = serde_json::from_str(&j)?;
        assert_eq!(back.encrypted_key, vec![1, 2, 3]);
        assert_eq!(back.keks.len(), 1);
        assert_eq!(back.keks[0].region, "us-east-1");
        assert_eq!(back.keks[0].arn, "arn:aws:kms:...");
        assert_eq!(back.keks[0].encrypted_kek, vec![9, 8, 7]);
        Ok(())
    }
}
