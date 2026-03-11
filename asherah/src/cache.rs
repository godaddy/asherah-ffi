use crate::internal::crypto_key::is_key_expired;
use crate::internal::CryptoKey;
use crate::types::KeyMeta;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    Simple,
    Lru,
    Lfu,
    Slru,
    TinyLfu,
}

impl CachePolicy {
    pub fn parse(s: &str, default: CachePolicy) -> CachePolicy {
        match s.to_ascii_lowercase().as_str() {
            "simple" => CachePolicy::Simple,
            "lru" => CachePolicy::Lru,
            "lfu" => CachePolicy::Lfu,
            "slru" => CachePolicy::Slru,
            "tinylfu" => CachePolicy::TinyLfu,
            _ => default,
        }
    }
}

const SEG_PROBATIONARY: u8 = 0;
const SEG_PROTECTED: u8 = 1;

struct CacheEntry {
    key: Arc<CryptoKey>,
    loaded_at: Instant,
    last_access: AtomicU64,
    freq: AtomicU64,
    segment: AtomicU8,
}

// Use Arc<str> keys to avoid String clones on cache lookups.
type CacheKey = (Arc<str>, i64);

pub trait KeyCacher: Send + Sync {
    fn get_or_load_latest(
        &self,
        id: &str,
        loader: &mut dyn FnMut() -> anyhow::Result<Arc<CryptoKey>>,
    ) -> anyhow::Result<Arc<CryptoKey>>;
    fn get_or_load(
        &self,
        meta: &KeyMeta,
        loader: &mut dyn FnMut() -> anyhow::Result<Arc<CryptoKey>>,
    ) -> anyhow::Result<Arc<CryptoKey>>;
    fn close(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct NeverCache;

impl KeyCacher for NeverCache {
    fn get_or_load_latest(
        &self,
        _id: &str,
        loader: &mut dyn FnMut() -> anyhow::Result<Arc<CryptoKey>>,
    ) -> anyhow::Result<Arc<CryptoKey>> {
        loader()
    }
    fn get_or_load(
        &self,
        _meta: &KeyMeta,
        loader: &mut dyn FnMut() -> anyhow::Result<Arc<CryptoKey>>,
    ) -> anyhow::Result<Arc<CryptoKey>> {
        loader()
    }
}

pub struct SimpleKeyCache {
    by_meta: scc::HashMap<CacheKey, CacheEntry>,
    latest: scc::HashMap<Arc<str>, i64>,
    ttl: Duration,
    max: usize,
    policy: CachePolicy,
    expire_after_s: i64,
    access_ctr: AtomicU64,
    decay_ctr: AtomicU64,
}

impl std::fmt::Debug for SimpleKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleKeyCache")
            .field("ttl", &self.ttl)
            .field("max", &self.max)
            .field("policy", &self.policy)
            .finish()
    }
}

impl SimpleKeyCache {
    pub fn new_with_ttl(ttl_s: i64) -> Self {
        Self::new_with_policy(ttl_s, 0, CachePolicy::Simple, 0)
    }

    pub fn new_with_policy(
        ttl_s: i64,
        max: usize,
        policy: CachePolicy,
        expire_after_s: i64,
    ) -> Self {
        Self {
            by_meta: scc::HashMap::new(),
            latest: scc::HashMap::new(),
            ttl: if ttl_s <= 0 {
                Duration::from_secs(0)
            } else {
                Duration::from_secs(ttl_s as u64)
            },
            max,
            policy,
            expire_after_s,
            access_ctr: AtomicU64::new(0),
            decay_ctr: AtomicU64::new(0),
        }
    }
    pub fn new() -> Self {
        Self::new_with_ttl(60 * 60)
    }

    fn next_access(&self) -> u64 {
        self.access_ctr.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn is_expired(&self, loaded_at: Instant) -> bool {
        if self.ttl == Duration::from_secs(0) {
            return true;
        }
        loaded_at.elapsed() >= self.ttl
    }

    fn is_invalid(&self, key: &CryptoKey) -> bool {
        if key.revoked() {
            return true;
        }
        if self.expire_after_s <= 0 {
            return false;
        }
        let now_s = crate::session::now_s();
        is_key_expired(key.created(), self.expire_after_s, now_s)
    }

    fn get_latest_if_fresh(&self, id: &str) -> Option<(Arc<CryptoKey>, bool, bool)> {
        // read() takes a shared lock on the bucket, not exclusive
        let (interned_id, created) = self.latest.read(id, |k, &v| (k.clone(), v))?;

        let result = self.by_meta.read(&(interned_id, created), |_, entry| {
            let expired = self.is_expired(entry.loaded_at);
            let invalid = self.is_invalid(&entry.key);
            entry
                .last_access
                .store(self.next_access(), Ordering::Relaxed);
            entry.freq.fetch_add(1, Ordering::Relaxed);
            let seg = entry.segment.load(Ordering::Relaxed);
            let promote = self.policy == CachePolicy::Slru && seg == SEG_PROBATIONARY;
            if promote {
                entry.segment.store(SEG_PROTECTED, Ordering::Relaxed);
            }
            (entry.key.clone(), expired, invalid, promote)
        })?;
        let (key_ref, expired, invalid, promote) = result;
        if promote {
            self.slru_rebalance();
        }
        Some((key_ref, expired, invalid))
    }

    fn get_meta_if_fresh(&self, meta: &KeyMeta) -> Option<(Arc<CryptoKey>, bool)> {
        let cache_key = (Arc::<str>::from(meta.id.as_str()), meta.created);
        let result = self.by_meta.read(&cache_key, |_, entry| {
            let mut expired = self.is_expired(entry.loaded_at);
            if entry.key.revoked() {
                expired = false;
            }
            entry
                .last_access
                .store(self.next_access(), Ordering::Relaxed);
            entry.freq.fetch_add(1, Ordering::Relaxed);
            let seg = entry.segment.load(Ordering::Relaxed);
            let promote = self.policy == CachePolicy::Slru && seg == SEG_PROBATIONARY;
            if promote {
                entry.segment.store(SEG_PROTECTED, Ordering::Relaxed);
            }
            (entry.key.clone(), expired, promote)
        })?;
        let (key_ref, expired, promote) = result;
        if promote {
            self.slru_rebalance();
        }
        Some((key_ref, expired))
    }

    fn insert_latest(&self, id: &str, key: Arc<CryptoKey>) {
        let meta = KeyMeta {
            id: id.to_string(),
            created: key.created(),
        };
        self.insert_meta(&meta, key);
    }

    fn insert_meta(&self, meta: &KeyMeta, key: Arc<CryptoKey>) {
        let interned_id: Arc<str> = Arc::from(meta.id.as_str());
        let entry = CacheEntry {
            key,
            loaded_at: Instant::now(),
            last_access: AtomicU64::new(self.next_access()),
            freq: AtomicU64::new(1),
            segment: AtomicU8::new(SEG_PROBATIONARY),
        };
        drop(
            self.by_meta
                .insert((interned_id.clone(), meta.created), entry),
        );
        // Update latest pointer
        let should_update = self
            .latest
            .read(&interned_id, |_, &existing| existing < meta.created)
            .unwrap_or(true);
        if should_update {
            let _ = self.latest.upsert(interned_id, meta.created);
        }
        self.evict_if_needed();
    }

    fn evict_if_needed(&self) {
        if self.policy == CachePolicy::Simple || self.max == 0 {
            return;
        }
        while self.by_meta.len() > self.max {
            self.evict_one();
        }
    }

    fn evict_one(&self) {
        match self.policy {
            CachePolicy::Lru => {
                let mut victim: Option<(CacheKey, u64)> = None;
                self.by_meta.scan(|k, v| {
                    let access = v.last_access.load(Ordering::Relaxed);
                    let dominated = match &victim {
                        None => true,
                        Some((_, min_access)) => access < *min_access,
                    };
                    if dominated {
                        victim = Some((k.clone(), access));
                    }
                });
                if let Some((k, _)) = victim {
                    self.by_meta.remove(&k);
                }
            }
            CachePolicy::Lfu => {
                let mut victim: Option<(CacheKey, (u64, u64))> = None;
                self.by_meta.scan(|k, v| {
                    let score = (
                        v.freq.load(Ordering::Relaxed),
                        v.last_access.load(Ordering::Relaxed),
                    );
                    let dominated = match &victim {
                        None => true,
                        Some((_, min_score)) => score < *min_score,
                    };
                    if dominated {
                        victim = Some((k.clone(), score));
                    }
                });
                if let Some((k, _)) = victim {
                    self.by_meta.remove(&k);
                }
            }
            CachePolicy::TinyLfu => {
                self.decay_if_needed();
                let mut victim: Option<(CacheKey, (u64, u64))> = None;
                self.by_meta.scan(|k, v| {
                    let score = (
                        v.freq.load(Ordering::Relaxed),
                        v.last_access.load(Ordering::Relaxed),
                    );
                    let dominated = match &victim {
                        None => true,
                        Some((_, min_score)) => score < *min_score,
                    };
                    if dominated {
                        victim = Some((k.clone(), score));
                    }
                });
                if let Some((k, _)) = victim {
                    self.by_meta.remove(&k);
                }
            }
            CachePolicy::Slru => {
                self.slru_rebalance();
                let mut victim: Option<(CacheKey, u64)> = None;
                self.by_meta.scan(|k, v| {
                    if v.segment.load(Ordering::Relaxed) == SEG_PROBATIONARY {
                        let access = v.last_access.load(Ordering::Relaxed);
                        let dominated = match &victim {
                            None => true,
                            Some((_, min_access)) => access < *min_access,
                        };
                        if dominated {
                            victim = Some((k.clone(), access));
                        }
                    }
                });
                if let Some((k, _)) = victim {
                    self.by_meta.remove(&k);
                    return;
                }
                let mut victim: Option<(CacheKey, u64)> = None;
                self.by_meta.scan(|k, v| {
                    if v.segment.load(Ordering::Relaxed) == SEG_PROTECTED {
                        let access = v.last_access.load(Ordering::Relaxed);
                        let dominated = match &victim {
                            None => true,
                            Some((_, min_access)) => access < *min_access,
                        };
                        if dominated {
                            victim = Some((k.clone(), access));
                        }
                    }
                });
                if let Some((k, _)) = victim {
                    self.by_meta.remove(&k);
                }
            }
            CachePolicy::Simple => {}
        }
    }

    fn slru_rebalance(&self) {
        if self.max == 0 {
            return;
        }
        let protected_cap = std::cmp::max(1, self.max / 2);
        let mut protected_count = 0_usize;
        let mut victim: Option<(CacheKey, u64)> = None;
        self.by_meta.scan(|k, v| {
            if v.segment.load(Ordering::Relaxed) == SEG_PROTECTED {
                protected_count += 1;
                let access = v.last_access.load(Ordering::Relaxed);
                let dominated = match &victim {
                    None => true,
                    Some((_, min_access)) => access < *min_access,
                };
                if dominated {
                    victim = Some((k.clone(), access));
                }
            }
        });
        if protected_count > protected_cap {
            if let Some((k, _)) = victim {
                self.by_meta.read(&k, |_, v| {
                    v.segment.store(SEG_PROBATIONARY, Ordering::Relaxed);
                });
            }
        }
    }

    fn decay_if_needed(&self) {
        if self.max == 0 {
            return;
        }
        let threshold = std::cmp::max(1, self.max as u64 * 10);
        let n = self.decay_ctr.fetch_add(1, Ordering::Relaxed) + 1;
        #[allow(clippy::manual_is_multiple_of)]
        if n % threshold == 0 {
            self.by_meta.scan(|_, v| {
                let old = v.freq.load(Ordering::Relaxed);
                v.freq.store(std::cmp::max(1, old / 2), Ordering::Relaxed);
            });
        }
    }
}

impl Default for SimpleKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyCacher for SimpleKeyCache {
    fn get_or_load_latest(
        &self,
        id: &str,
        loader: &mut dyn FnMut() -> anyhow::Result<Arc<CryptoKey>>,
    ) -> anyhow::Result<Arc<CryptoKey>> {
        if let Some((v, expired, invalid)) = self.get_latest_if_fresh(id) {
            if !expired && !invalid {
                crate::metrics::record_cache_hit("latest");
                return Ok(v);
            }
        }
        crate::metrics::record_cache_miss("latest");
        let v = loader()?;
        self.insert_latest(id, v.clone());
        Ok(v)
    }
    fn get_or_load(
        &self,
        meta: &KeyMeta,
        loader: &mut dyn FnMut() -> anyhow::Result<Arc<CryptoKey>>,
    ) -> anyhow::Result<Arc<CryptoKey>> {
        if let Some((v, expired)) = self.get_meta_if_fresh(meta) {
            if !expired {
                crate::metrics::record_cache_hit("meta");
                return Ok(v);
            }
        }
        crate::metrics::record_cache_miss("meta");
        let v = loader()?;
        self.insert_meta(meta, v.clone());
        Ok(v)
    }
}
