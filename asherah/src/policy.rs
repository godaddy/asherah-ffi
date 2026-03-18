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
    fn default() -> Self {
        Self {
            create_date_precision_s: 60,
            expire_key_after_s: 60 * 60 * 24 * 90,
            cache_system_keys: true,
            cache_intermediate_keys: true,
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
    }
}

// PolicyOption equivalents to Go's functional options
#[derive(Debug, Clone)]
pub enum PolicyOption {
    RevokeCheckIntervalSecs(i64),
    ExpireAfterSecs(i64),
    NoCache,
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
