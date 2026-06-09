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
    /// When a decrypt is rescued by the best-effort recovery path using a key
    /// stored under a different id/created than the row references, write a copy
    /// of that key back under the id/created the row expects, so future reads of
    /// rows like it take the normal fast path instead of recovery. The copy is
    /// AEAD-verified (the recovered key already decrypted the row) and stored
    /// insert-if-absent with the same `created`, so it cannot win key rotation.
    /// Best-effort: a failed write never fails the decrypt. Default `true`.
    /// Disable for read-only decryptors that lack metastore write permission.
    pub self_heal_recovered_keys: bool,
}

impl Config {
    pub fn new(service: impl Into<String>, product: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            product: product.into(),
            policy: CryptoPolicy::default(),
            region_suffix: None,
            recovery_region_suffixes: Vec::new(),
            self_heal_recovered_keys: true,
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
    pub fn with_self_heal_recovered_keys(mut self, enabled: bool) -> Self {
        self.self_heal_recovered_keys = enabled;
        self
    }
}
