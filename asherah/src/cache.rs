use crate::internal::CryptoKey;
use crate::types::KeyMeta;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

type MetaCacheInner = HashMap<(String, i64), (Arc<CryptoKey>, std::time::Instant)>;
type LatestCacheInner = HashMap<String, (Arc<CryptoKey>, std::time::Instant)>;

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
    latest: Mutex<LatestCacheInner>,
    ttl: std::time::Duration,
}

impl SimpleKeyCache {
    pub fn new_with_ttl(ttl_s: i64) -> Self {
        Self {
            by_meta: Mutex::new(HashMap::new()),
            latest: Mutex::new(HashMap::new()),
            ttl: std::time::Duration::from_secs(ttl_s as u64),
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
        let mut map = self.latest.lock();
        if let Some((v, t)) = map.get(id) {
            if t.elapsed() < self.ttl {
                crate::metrics::record_cache_hit("latest");
                return Ok(v.clone());
            }
        }
        crate::metrics::record_cache_miss("latest");
        let v = loader()?;
        map.insert(id.to_string(), (v.clone(), std::time::Instant::now()));
        Ok(v)
    }
    fn get_or_load(
        &self,
        meta: &KeyMeta,
        loader: &mut dyn FnMut() -> anyhow::Result<Arc<CryptoKey>>,
    ) -> anyhow::Result<Arc<CryptoKey>> {
        let key = (meta.id.clone(), meta.created);
        let mut map = self.by_meta.lock();
        if let Some((v, t)) = map.get(&key) {
            if t.elapsed() < self.ttl {
                crate::metrics::record_cache_hit("meta");
                return Ok(v.clone());
            }
        }
        crate::metrics::record_cache_miss("meta");
        let v = loader()?;
        map.insert(key, (v.clone(), std::time::Instant::now()));
        Ok(v)
    }
}
