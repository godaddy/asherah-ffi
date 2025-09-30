use crate::policy::CryptoPolicy;

#[derive(Clone, Debug)]
pub struct Config {
    pub service: String,
    pub product: String,
    pub policy: CryptoPolicy,
    pub region_suffix: Option<String>,
}

impl Config {
    pub fn new(service: impl Into<String>, product: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            product: product.into(),
            policy: CryptoPolicy::default(),
            region_suffix: None,
        }
    }
    pub fn with_policy(mut self, policy: CryptoPolicy) -> Self {
        self.policy = policy;
        self
    }
    pub fn with_policy_options(mut self, opts: &[crate::policy::PolicyOption]) -> Self {
        self.policy = crate::policy::new_crypto_policy(opts);
        self
    }
    pub fn with_region_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.region_suffix = Some(suffix.into());
        self
    }
}
