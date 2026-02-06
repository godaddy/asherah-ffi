use crate::internal::crypto_key::is_key_expired;
use crate::internal::CryptoKey;
use crate::types::KeyMeta;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
            "" => default,
            "simple" => CachePolicy::Simple,
            "lru" => CachePolicy::Lru,
            "lfu" => CachePolicy::Lfu,
            "slru" => CachePolicy::Slru,
            "tinylfu" => CachePolicy::TinyLfu,
            _ => default,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Segment {
    Probationary,
    Protected,
}

#[derive(Debug)]
struct CacheEntry {
    key: Arc<CryptoKey>,
    loaded_at: Instant,
    last_access: u64,
    freq: u64,
    segment: Segment,
}

type MetaCacheInner = HashMap<(String, i64), CacheEntry>;
type LatestMetaInner = HashMap<String, KeyMeta>;

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

#[derive(Debug)]
pub struct SimpleKeyCache {
    by_meta: Mutex<MetaCacheInner>,
    latest: Mutex<LatestMetaInner>,
    ttl: Duration,
    max: usize,
    policy: CachePolicy,
    expire_after_s: i64,
    access_ctr: AtomicU64,
    decay_ctr: AtomicU64,
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
            by_meta: Mutex::new(HashMap::new()),
            latest: Mutex::new(HashMap::new()),
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

impl SimpleKeyCache {
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
        let latest = { self.latest.lock().get(id).cloned() };
        let meta = match latest {
            Some(m) => m,
            None => return None,
        };
        let key = (meta.id.clone(), meta.created);
        let mut map = self.by_meta.lock();
        if map.contains_key(&key) {
            let (key_ref, expired, invalid, promote) = {
                let entry = map.get_mut(&key).expect("entry present");
                let expired = self.is_expired(entry.loaded_at);
                let invalid = self.is_invalid(&entry.key);
                entry.last_access = self.next_access();
                entry.freq = entry.freq.saturating_add(1);
                let promote =
                    self.policy == CachePolicy::Slru && entry.segment == Segment::Probationary;
                if promote {
                    entry.segment = Segment::Protected;
                }
                (entry.key.clone(), expired, invalid, promote)
            };
            if promote {
                self.slru_rebalance(&mut map);
            }
            return Some((key_ref, expired, invalid));
        }
        None
    }

    fn get_meta_if_fresh(&self, meta: &KeyMeta) -> Option<(Arc<CryptoKey>, bool)> {
        let key = (meta.id.clone(), meta.created);
        let mut map = self.by_meta.lock();
        if map.contains_key(&key) {
            let (key_ref, expired, promote) = {
                let entry = map.get_mut(&key).expect("entry present");
                let mut expired = self.is_expired(entry.loaded_at);
                if entry.key.revoked() {
                    expired = false;
                }
                entry.last_access = self.next_access();
                entry.freq = entry.freq.saturating_add(1);
                let promote =
                    self.policy == CachePolicy::Slru && entry.segment == Segment::Probationary;
                if promote {
                    entry.segment = Segment::Protected;
                }
                (entry.key.clone(), expired, promote)
            };
            if promote {
                self.slru_rebalance(&mut map);
            }
            return Some((key_ref, expired));
        }
        None
    }

    fn insert_latest(&self, id: &str, key: Arc<CryptoKey>) {
        let meta = KeyMeta {
            id: id.to_string(),
            created: key.created(),
        };
        self.insert_meta(&meta, key);
    }

    fn insert_meta(&self, meta: &KeyMeta, key: Arc<CryptoKey>) {
        let mut map = self.by_meta.lock();
        let entry = CacheEntry {
            key,
            loaded_at: Instant::now(),
            last_access: self.next_access(),
            freq: 1,
            segment: Segment::Probationary,
        };
        map.insert((meta.id.clone(), meta.created), entry);
        {
            let mut latest = self.latest.lock();
            if let Some(existing) = latest.get(&meta.id) {
                if existing.created < meta.created {
                    latest.insert(meta.id.clone(), meta.clone());
                }
            } else {
                latest.insert(meta.id.clone(), meta.clone());
            }
        }
        self.evict_if_needed(&mut map);
    }

    fn evict_if_needed(&self, map: &mut MetaCacheInner) {
        if self.policy == CachePolicy::Simple || self.max == 0 {
            return;
        }
        while map.len() > self.max {
            self.evict_one(map);
        }
    }

    fn evict_one(&self, map: &mut MetaCacheInner) {
        match self.policy {
            CachePolicy::Lru => {
                if let Some((k, _)) = map
                    .iter()
                    .min_by_key(|(_, v)| v.last_access)
                    .map(|(k, v)| (k.clone(), v.last_access))
                {
                    map.remove(&k);
                }
            }
            CachePolicy::Lfu => {
                if let Some((k, _)) = map
                    .iter()
                    .min_by_key(|(_, v)| (v.freq, v.last_access))
                    .map(|(k, v)| (k.clone(), v.freq))
                {
                    map.remove(&k);
                }
            }
            CachePolicy::TinyLfu => {
                self.decay_if_needed(map);
                if let Some((k, _)) = map
                    .iter()
                    .min_by_key(|(_, v)| (v.freq, v.last_access))
                    .map(|(k, v)| (k.clone(), v.freq))
                {
                    map.remove(&k);
                }
            }
            CachePolicy::Slru => {
                self.slru_rebalance(map);
                if let Some((k, _)) = map
                    .iter()
                    .filter(|(_, v)| v.segment == Segment::Probationary)
                    .min_by_key(|(_, v)| v.last_access)
                    .map(|(k, v)| (k.clone(), v.last_access))
                {
                    map.remove(&k);
                    return;
                }
                if let Some((k, _)) = map
                    .iter()
                    .filter(|(_, v)| v.segment == Segment::Protected)
                    .min_by_key(|(_, v)| v.last_access)
                    .map(|(k, v)| (k.clone(), v.last_access))
                {
                    map.remove(&k);
                }
            }
            CachePolicy::Simple => {}
        }
    }

    fn slru_rebalance(&self, map: &mut MetaCacheInner) {
        if self.max == 0 {
            return;
        }
        let protected_cap = std::cmp::max(1, self.max / 2);
        let protected_count = map
            .values()
            .filter(|v| v.segment == Segment::Protected)
            .count();
        if protected_count > protected_cap {
            if let Some((k, _)) = map
                .iter()
                .filter(|(_, v)| v.segment == Segment::Protected)
                .min_by_key(|(_, v)| v.last_access)
                .map(|(k, v)| (k.clone(), v.last_access))
            {
                if let Some(e) = map.get_mut(&k) {
                    e.segment = Segment::Probationary;
                }
            }
        }
    }

    fn decay_if_needed(&self, map: &mut MetaCacheInner) {
        if self.max == 0 {
            return;
        }
        let threshold = std::cmp::max(1, self.max as u64 * 10);
        let n = self.decay_ctr.fetch_add(1, Ordering::Relaxed) + 1;
        if n % threshold == 0 {
            for v in map.values_mut() {
                v.freq = std::cmp::max(1, v.freq / 2);
            }
        }
    }
}
