use crate::internal::crypto_key::is_key_expired;
use crate::internal::CryptoKey;
use crate::types::KeyMeta;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Jitter factor for cache TTL to prevent thundering herd.
/// Each entry gets up to 10% of the TTL added as random jitter,
/// so entries loaded at the same time don't all expire simultaneously.
const TTL_JITTER_FRACTION: f64 = 0.10;

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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

struct CacheEntry {
    key: Arc<CryptoKey>,
    /// Epoch milliseconds when this entry was last loaded/validated from the metastore.
    /// Stored as AtomicU64 so stale-while-revalidate can CAS it without exclusive locks.
    loaded_at_ms: AtomicU64,
    /// Per-entry jitter (millis) added to TTL to prevent thundering herd expiry.
    ttl_jitter_ms: u64,
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
    ttl_ms: u64,
    max: usize,
    policy: CachePolicy,
    expire_after_s: i64,
    access_ctr: AtomicU64,
    decay_ctr: AtomicU64,
}

impl std::fmt::Debug for SimpleKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleKeyCache")
            .field("ttl_ms", &self.ttl_ms)
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
            ttl_ms: if ttl_s <= 0 { 0 } else { ttl_s as u64 * 1000 },
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

    fn is_expired(&self, loaded_at_ms: u64, jitter_ms: u64) -> bool {
        if self.ttl_ms == 0 {
            return true;
        }
        now_ms().saturating_sub(loaded_at_ms) >= self.ttl_ms + jitter_ms
    }

    /// Generate a random jitter in milliseconds, up to TTL_JITTER_FRACTION of the TTL.
    fn random_jitter_ms(&self) -> u64 {
        if self.ttl_ms == 0 {
            return 0;
        }
        let max_jitter_ms = (self.ttl_ms as f64 * TTL_JITTER_FRACTION) as u64;
        if max_jitter_ms == 0 {
            return 0;
        }
        // Use the access counter as a cheap pseudo-random seed (no syscall)
        let pseudo_rand = self.access_ctr.load(Ordering::Relaxed);
        pseudo_rand
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1)
            % max_jitter_ms
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
            let loaded = entry.loaded_at_ms.load(Ordering::Relaxed);
            let expired = self.is_expired(loaded, entry.ttl_jitter_ms);
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
            let loaded = entry.loaded_at_ms.load(Ordering::Relaxed);
            let mut expired = self.is_expired(loaded, entry.ttl_jitter_ms);
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
        let cache_key = (interned_id.clone(), meta.created);
        let entry = CacheEntry {
            key,
            loaded_at_ms: AtomicU64::new(now_ms()),
            ttl_jitter_ms: self.random_jitter_ms(),
            last_access: AtomicU64::new(self.next_access()),
            freq: AtomicU64::new(1),
            segment: AtomicU8::new(SEG_PROBATIONARY),
        };
        // upsert replaces existing entries — scc::HashMap::insert does NOT,
        // which would leave stale entries with old loaded_at forever.
        self.by_meta.upsert(cache_key, entry);
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

    /// Attempt to claim the reload for the latest key of `id` by CAS-ing loaded_at_ms.
    /// Returns true if this thread claimed the reload (and should do the metastore query).
    /// Other threads see the updated loaded_at and return the stale key without reloading.
    fn try_claim_reload_latest(&self, id: &str) -> bool {
        let Some((interned_id, created)) = self.latest.read(id, |k, &v| (k.clone(), v)) else {
            return false;
        };
        let fresh = now_ms();
        let mut claimed = false;
        self.by_meta.read(&(interned_id, created), |_, entry| {
            let old = entry.loaded_at_ms.load(Ordering::Relaxed);
            if fresh.saturating_sub(old) >= self.ttl_ms + entry.ttl_jitter_ms {
                claimed = entry
                    .loaded_at_ms
                    .compare_exchange(old, fresh, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok();
            }
        });
        claimed
    }

    /// Attempt to claim the reload for a specific key meta by CAS-ing loaded_at_ms.
    fn try_claim_reload_meta(&self, meta: &KeyMeta) -> bool {
        let cache_key = (Arc::<str>::from(meta.id.as_str()), meta.created);
        let fresh = now_ms();
        let mut claimed = false;
        self.by_meta.read(&cache_key, |_, entry| {
            let old = entry.loaded_at_ms.load(Ordering::Relaxed);
            if fresh.saturating_sub(old) >= self.ttl_ms + entry.ttl_jitter_ms {
                claimed = entry
                    .loaded_at_ms
                    .compare_exchange(old, fresh, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok();
            }
        });
        claimed
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
                if crate::metrics::is_enabled() {
                    crate::metrics::record_cache_hit("latest");
                }
                return Ok(v);
            }
            // Stale-while-revalidate: stale but not invalid (not revoked, not policy-expired).
            // Try to claim the reload via CAS. Only one thread does the metastore query;
            // all others return the stale key immediately.
            if expired && !invalid {
                if self.try_claim_reload_latest(id) {
                    // We claimed the reload. Do the metastore query.
                    // Other threads now see fresh loaded_at and won't reload.
                    if crate::metrics::is_enabled() {
                        crate::metrics::record_cache_stale("latest");
                    }
                    match loader() {
                        Ok(new_key) => {
                            self.insert_latest(id, new_key.clone());
                            // Return the loaded key: handles key rotation and
                            // revocation discovery (loader returns a new valid key
                            // when the cached one was revoked in the metastore).
                            return Ok(new_key);
                        }
                        Err(_) => {
                            // Metastore error: loaded_at was already bumped by the CAS,
                            // so we won't retry until next TTL expiry. This is acceptable
                            // since the metastore is unreachable anyway.
                        }
                    }
                } else if crate::metrics::is_enabled() {
                    crate::metrics::record_cache_stale("latest");
                }
                return Ok(v);
            }
            // Key is invalid (revoked or policy-expired): must do a full reload
        }
        // Cold miss or invalid key — must load from metastore
        if crate::metrics::is_enabled() {
            crate::metrics::record_cache_miss("latest");
        }
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
                if crate::metrics::is_enabled() {
                    crate::metrics::record_cache_hit("meta");
                }
                return Ok(v);
            }
            // Stale-while-revalidate for meta lookups (decrypt path).
            // Revoked keys are never marked expired by get_meta_if_fresh, so we
            // only reach here for non-revoked stale entries loaded by exact
            // (id, created). The key material is identical whether we reload or
            // not — just bump loaded_at via CAS so the entry stays fresh.
            // No loader call needed: zero metastore queries on the decrypt path.
            let _ = self.try_claim_reload_meta(meta);
            if crate::metrics::is_enabled() {
                crate::metrics::record_cache_stale("meta");
            }
            return Ok(v);
        }
        // Cold miss — must load from metastore
        if crate::metrics::is_enabled() {
            crate::metrics::record_cache_miss("meta");
        }
        let v = loader()?;
        self.insert_meta(meta, v.clone());
        Ok(v)
    }
}
