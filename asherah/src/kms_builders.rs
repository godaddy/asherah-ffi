use std::sync::Arc;

use crate::traits::KeyManagementService;

pub fn aws_kms_from_env<A: crate::traits::AEAD + Send + Sync + 'static>(
    aead: Arc<A>,
) -> anyhow::Result<Arc<dyn KeyManagementService>> {
    let key_id = std::env::var("KMS_KEY_ID")?;
    let region = std::env::var("AWS_REGION").ok();
    // AWS_PROFILE is honored automatically by the SDK's default credential
    // chain when we pass `None` here, so this matches the env-var contract
    // users already expect.
    let kms = crate::kms_aws::AwsKms::new(aead, key_id, region, None)?;
    Ok(Arc::new(kms))
}

// Multi-region builder
#[allow(missing_debug_implementations)]
pub struct AwsKmsBuilder<A: crate::traits::AEAD + Send + Sync + 'static> {
    aead: Arc<A>,
    preferred_region: Option<String>,
    profile_name: Option<String>,
    entries: Vec<(String, String)>, // (region, key_id)
}

impl<A: crate::traits::AEAD + Send + Sync + 'static> AwsKmsBuilder<A> {
    pub fn new(aead: Arc<A>) -> Self {
        Self {
            aead,
            preferred_region: None,
            profile_name: None,
            entries: vec![],
        }
    }
    pub fn preferred_region(mut self, region: impl Into<String>) -> Self {
        self.preferred_region = Some(region.into());
        self
    }
    /// Optional AWS shared-credentials profile name (typically from
    /// `~/.aws/credentials`). When omitted, the SDK's default credential
    /// chain is used.
    pub fn profile_name(mut self, name: impl Into<String>) -> Self {
        self.profile_name = Some(name.into());
        self
    }
    pub fn add(mut self, region: impl Into<String>, key_id: impl Into<String>) -> Self {
        self.entries.push((region.into(), key_id.into()));
        self
    }
    pub fn build(self) -> anyhow::Result<Arc<dyn KeyManagementService>> {
        if self.entries.is_empty() {
            return Err(anyhow::anyhow!("no entries configured"));
        }
        let mut backends: Vec<Arc<dyn KeyManagementService>> = Vec::new();
        let mut preferred_idx = 0_usize;
        let profile = self.profile_name.as_deref();
        for (i, (region, key)) in self.entries.iter().enumerate() {
            if let Some(pref) = &self.preferred_region {
                if pref == region {
                    preferred_idx = i;
                }
            }
            let kms = crate::kms_aws::AwsKms::new(
                self.aead.clone(),
                key.clone(),
                Some(region.clone()),
                profile,
            )?;
            backends.push(Arc::new(kms));
        }
        let multi = crate::kms_multi::MultiKms::new(preferred_idx, backends)?;
        Ok(Arc::new(multi))
    }
}
