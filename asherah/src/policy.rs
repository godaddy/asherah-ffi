/// Minimum cache sizes — prevents users from shooting themselves in the foot.
/// System keys: there's typically 1 per service/product, but allow headroom for rotation.
const MIN_SYSTEM_KEY_CACHE_SIZE: usize = 10;
/// Intermediate keys: at least enough for a reasonable number of partitions.
const MIN_INTERMEDIATE_KEY_CACHE_SIZE: usize = 100;
/// Sessions: at least enough to avoid thrashing under moderate concurrency.
const MIN_SESSION_CACHE_SIZE: usize = 100;

#[derive(Debug, Clone)]
pub struct CryptoPolicy {
    // units: seconds
    pub create_date_precision_s: i64,
    pub expire_key_after_s: i64,
    // Caches are always enabled. These booleans are kept for backward
    // compatibility with config parsing but are ignored — setting them
    // to false is a no-op. Use cache max sizes to control capacity.
    pub cache_system_keys: bool,
    pub cache_intermediate_keys: bool,
    /// Cache pre-expanded AEAD key schedules outside the locked enclave.
    /// Disable this for higher assurance against microarchitectural disclosure
    /// of long-lived SK/IK key-equivalent material.
    pub cache_key_schedules: bool,
    pub shared_intermediate_key_cache: bool,
    pub intermediate_key_cache_max_size: usize,
    pub intermediate_key_cache_eviction_policy: String,
    pub system_key_cache_max_size: usize,
    pub system_key_cache_eviction_policy: String,
    pub cache_sessions: bool,
    pub session_cache_max_size: usize,
    pub session_cache_ttl_s: i64,
    pub session_cache_eviction_policy: String,
    pub revoke_check_interval_s: i64,
}

impl Default for CryptoPolicy {
    /// Defaults match the Go reference implementation. Notable
    /// trade-offs:
    ///
    /// * `expire_key_after_s = 90 days`, `revoke_check_interval_s =
    ///   1 hour`. Once a key is revoked in the metastore, in-flight
    ///   encrypt/decrypt calls keep using the cached key for at most
    ///   `revoke_check_interval_s` before the cache re-checks.
    ///   Operators who need tighter revocation latency should lower
    ///   `revoke_check_interval_s` at the cost of higher metastore
    ///   read load. T-finding "Default simple IK cache + 90-day TTL +
    ///   revocation gap = IK can stay cached past revocation" in
    ///   `docs/review-2026-05-05-findings.md`.
    /// * `intermediate_key_cache_eviction_policy = "simple"` is
    ///   unbounded by design — paired with `cache_max_size = 1000`
    ///   the cache will warn at construction (see `cache.rs:162`) and
    ///   operators wanting bounded cardinality should pick `lru`,
    ///   `slru`, `lfu`, or `tinylfu`.
    fn default() -> Self {
        Self {
            create_date_precision_s: 60,
            expire_key_after_s: 60 * 60 * 24 * 90,
            cache_system_keys: true,
            cache_intermediate_keys: true,
            cache_key_schedules: true,
            shared_intermediate_key_cache: true,
            intermediate_key_cache_max_size: 1000,
            intermediate_key_cache_eviction_policy: "simple".to_string(),
            system_key_cache_max_size: 1000,
            system_key_cache_eviction_policy: "simple".to_string(),
            cache_sessions: true,
            session_cache_max_size: 1000,
            session_cache_ttl_s: 2 * 60 * 60,
            session_cache_eviction_policy: "slru".to_string(),
            revoke_check_interval_s: 60 * 60,
        }
    }
}

impl CryptoPolicy {
    /// Enforce minimum cache sizes and enable all caches.
    /// Called from env-var-based configuration where disabling caches
    /// would be a performance footgun. The programmatic `NoCache` option
    /// bypasses this for test scenarios.
    pub fn enforce_minimums(&mut self) {
        self.system_key_cache_max_size = self
            .system_key_cache_max_size
            .max(MIN_SYSTEM_KEY_CACHE_SIZE);
        self.intermediate_key_cache_max_size = self
            .intermediate_key_cache_max_size
            .max(MIN_INTERMEDIATE_KEY_CACHE_SIZE);
        self.session_cache_max_size = self.session_cache_max_size.max(MIN_SESSION_CACHE_SIZE);
        // Enable all caches — env vars cannot disable them
        self.cache_system_keys = true;
        self.cache_intermediate_keys = true;
        self.cache_sessions = true;
        // Defense-in-depth: clamp create_date_precision_s ≤ expire_key_after_s.
        // Without this, a config with `expire_after_s < create_date_precision_s`
        // (e.g. expire=1, default precision=60) makes the engine fail closed
        // on the second encrypt within a precision window — every binding
        // user setting `expireAfter < 60` hits this. Mirror clamp logic in
        // asherah-config::resolve, but apply it here too so any code path
        // that builds a CryptoPolicy benefits, including direct
        // `Config::new()` consumers and integration tests. T-finding
        // `expire_smaller_than_precision_fails_closed` in
        // asherah/tests/rotation_timing_edges.rs.
        if self.expire_key_after_s > 0 && self.create_date_precision_s > self.expire_key_after_s {
            self.create_date_precision_s = self.expire_key_after_s;
        }
    }
}

// PolicyOption equivalents to Go's functional options
#[derive(Debug, Clone)]
pub enum PolicyOption {
    RevokeCheckIntervalSecs(i64),
    ExpireAfterSecs(i64),
    NoCache,
    CacheKeySchedules(bool),
    SharedIntermediateKeyCache(bool),
    IntermediateKeyCacheMaxSize(usize),
    IntermediateKeyCacheEvictionPolicy(String),
    SystemKeyCacheMaxSize(usize),
    SystemKeyCacheEvictionPolicy(String),
    SessionCache(bool),
    SessionCacheMaxSize(usize),
    SessionCacheDurationSecs(i64),
    SessionCacheEvictionPolicy(String),
    CreateDatePrecisionSecs(i64),
}

pub fn new_crypto_policy(opts: &[PolicyOption]) -> CryptoPolicy {
    let mut p = CryptoPolicy::default();
    let mut explicit_no_cache = false;
    for o in opts {
        match *o {
            PolicyOption::RevokeCheckIntervalSecs(s) => p.revoke_check_interval_s = s,
            PolicyOption::ExpireAfterSecs(s) => p.expire_key_after_s = s,
            PolicyOption::NoCache => {
                // NoCache is honored from the programmatic API (for tests)
                // but NOT from env vars (see builders.rs).
                p.cache_system_keys = false;
                p.cache_intermediate_keys = false;
                explicit_no_cache = true;
            }
            PolicyOption::CacheKeySchedules(b) => p.cache_key_schedules = b,
            PolicyOption::SharedIntermediateKeyCache(b) => p.shared_intermediate_key_cache = b,
            PolicyOption::IntermediateKeyCacheMaxSize(sz) => p.intermediate_key_cache_max_size = sz,
            PolicyOption::IntermediateKeyCacheEvictionPolicy(ref s) => {
                p.intermediate_key_cache_eviction_policy = s.clone()
            }
            PolicyOption::SystemKeyCacheMaxSize(sz) => p.system_key_cache_max_size = sz,
            PolicyOption::SystemKeyCacheEvictionPolicy(ref s) => {
                p.system_key_cache_eviction_policy = s.clone()
            }
            PolicyOption::SessionCache(b) => p.cache_sessions = b,
            PolicyOption::SessionCacheMaxSize(sz) => p.session_cache_max_size = sz,
            PolicyOption::SessionCacheDurationSecs(s) => p.session_cache_ttl_s = s,
            PolicyOption::SessionCacheEvictionPolicy(ref s) => {
                p.session_cache_eviction_policy = s.clone()
            }
            PolicyOption::CreateDatePrecisionSecs(s) => p.create_date_precision_s = s,
        }
    }
    // Enforce minimum sizes unless explicitly disabled for testing
    if !explicit_no_cache {
        p.enforce_minimums();
    }
    p
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn policy_with(expire_s: i64, precision_s: i64) -> CryptoPolicy {
        CryptoPolicy {
            expire_key_after_s: expire_s,
            create_date_precision_s: precision_s,
            ..CryptoPolicy::default()
        }
    }

    /// `enforce_minimums` clamps `create_date_precision_s` so it never
    /// exceeds `expire_key_after_s` (when expire is positive). This is
    /// the defense-in-depth runtime clamp that protects every binding
    /// from the precision-window collision footgun.
    ///
    /// If this test ever fails, the runtime clamp isn't compiled in
    /// and bindings will hit `failed to create or load IK after retry`
    /// when an operator sets `expireAfter` < default precision.
    #[test]
    fn enforce_minimums_clamps_precision_to_expire() {
        let mut p = policy_with(1, 60);
        p.enforce_minimums();
        assert_eq!(
            p.create_date_precision_s, 1,
            "enforce_minimums must clamp precision to expire_key_after_s",
        );
    }

    /// When precision is already smaller than expire, the clamp leaves
    /// it alone.
    #[test]
    fn enforce_minimums_preserves_smaller_precision() {
        let mut p = policy_with(3600, 60);
        p.enforce_minimums();
        assert_eq!(p.create_date_precision_s, 60);
    }

    /// When precision equals expire, the clamp leaves it alone.
    #[test]
    fn enforce_minimums_preserves_equal_precision() {
        let mut p = policy_with(60, 60);
        p.enforce_minimums();
        assert_eq!(p.create_date_precision_s, 60);
    }

    /// Zero and negative `expire_key_after_s` are degenerate
    /// configurations; the clamp is a no-op.
    #[test]
    fn enforce_minimums_zero_or_negative_expire_no_op() {
        let mut p = policy_with(0, 60);
        p.enforce_minimums();
        assert_eq!(
            p.create_date_precision_s, 60,
            "expire=0 leaves precision alone"
        );

        let mut p = policy_with(-1, 60);
        p.enforce_minimums();
        assert_eq!(
            p.create_date_precision_s, 60,
            "expire=-1 leaves precision alone"
        );
    }
}
