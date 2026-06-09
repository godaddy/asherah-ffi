use crate::policy::CryptoPolicy;

#[derive(Clone, Debug)]
pub struct Config {
    pub service: String,
    pub product: String,
    pub policy: CryptoPolicy,
    pub region_suffix: Option<String>,
    /// Additional region suffixes to try as a last resort when a decrypt
    /// would otherwise fail because the row's intermediate-key id does not
    /// match this session's partition (e.g. data written under a different
    /// region's suffix, or before region suffixing was enabled). Recovery is
    /// always best-effort and AEAD-authenticated, so a wrong key can never
    /// yield wrong plaintext; this list only widens the set of candidate keys
    /// tried. The empty suffix is always tried regardless of this list.
    pub recovery_region_suffixes: Vec<String>,
}

impl Config {
    pub fn new(service: impl Into<String>, product: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            product: product.into(),
            policy: CryptoPolicy::default(),
            region_suffix: None,
            recovery_region_suffixes: Vec::new(),
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
    pub fn with_recovery_region_suffixes(mut self, suffixes: Vec<String>) -> Self {
        self.recovery_region_suffixes = suffixes;
        self
    }
}
