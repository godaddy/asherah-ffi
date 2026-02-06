#[derive(Debug, Clone)]
pub struct CryptoPolicy {
    // units: seconds
    pub create_date_precision_s: i64,
    pub expire_key_after_s: i64,
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
            shared_intermediate_key_cache: false,
            intermediate_key_cache_max_size: 1000,
            intermediate_key_cache_eviction_policy: "simple".to_string(),
            system_key_cache_max_size: 1000,
            system_key_cache_eviction_policy: "simple".to_string(),
            cache_sessions: false,
            session_cache_max_size: 1000,
            session_cache_ttl_s: 2 * 60 * 60,
            session_cache_eviction_policy: "slru".to_string(),
            revoke_check_interval_s: 60 * 60,
        }
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
    for o in opts {
        match *o {
            PolicyOption::RevokeCheckIntervalSecs(s) => p.revoke_check_interval_s = s,
            PolicyOption::ExpireAfterSecs(s) => p.expire_key_after_s = s,
            PolicyOption::NoCache => {
                p.cache_system_keys = false;
                p.cache_intermediate_keys = false;
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
    p
}
