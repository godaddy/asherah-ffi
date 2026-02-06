use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cache::CachePolicy;
use crate::session::PublicSession;
use crate::traits::{KeyManagementService, Metastore, AEAD};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Segment {
    Probationary,
    Protected,
}

struct SessionEntry<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone> {
    sess: Arc<PublicSession<A, K, M>>,
    ts: Instant,
    last_access: u64,
    freq: u64,
    segment: Segment,
}

#[allow(missing_debug_implementations)]
pub struct SessionCache<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone> {
    map: Mutex<HashMap<String, SessionEntry<A, K, M>>>,
    max: usize,
    ttl: Duration,
    policy: CachePolicy,
    access_ctr: AtomicU64,
    decay_ctr: AtomicU64,
}

impl<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone> SessionCache<A, K, M> {
    pub fn new(max: usize, ttl_s: i64, policy: CachePolicy) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            max,
            ttl: if ttl_s <= 0 {
                Duration::from_secs(0)
            } else {
                Duration::from_secs(ttl_s as u64)
            },
            policy,
            access_ctr: AtomicU64::new(0),
            decay_ctr: AtomicU64::new(0),
        }
    }

    pub fn get_or_create(
        &self,
        id: &str,
        create: impl FnOnce() -> PublicSession<A, K, M>,
    ) -> Arc<PublicSession<A, K, M>> {
        let mut map = self.map.lock();
        if let Some(entry) = map.get_mut(id) {
            if self.ttl != Duration::from_secs(0) && entry.ts.elapsed() < self.ttl {
                let (sess, promote) = {
                    entry.ts = Instant::now();
                    entry.last_access = self.next_access();
                    entry.freq = entry.freq.saturating_add(1);
                    let promote =
                        self.policy == CachePolicy::Slru && entry.segment == Segment::Probationary;
                    if promote {
                        entry.segment = Segment::Protected;
                    }
                    (entry.sess.clone(), promote)
                };
                if promote {
                    self.slru_rebalance(&mut map);
                }
                return sess;
            }
        }
        let s = Arc::new(create());
        let entry = SessionEntry {
            sess: s.clone(),
            ts: Instant::now(),
            last_access: self.next_access(),
            freq: 1,
            segment: Segment::Probationary,
        };
        map.insert(id.to_string(), entry);
        self.evict_if_needed(&mut map);
        s
    }

    pub fn close(&self) {
        self.map.lock().clear();
    }

    fn next_access(&self) -> u64 {
        self.access_ctr.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn evict_if_needed(&self, map: &mut HashMap<String, SessionEntry<A, K, M>>) {
        if self.policy == CachePolicy::Simple || self.max == 0 {
            return;
        }
        while map.len() > self.max {
            self.evict_one(map);
        }
    }

    fn evict_one(&self, map: &mut HashMap<String, SessionEntry<A, K, M>>) {
        match self.policy {
            CachePolicy::Lru => {
                if let Some(k) = map
                    .iter()
                    .min_by_key(|(_, v)| v.last_access)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&k);
                }
            }
            CachePolicy::Lfu => {
                if let Some(k) = map
                    .iter()
                    .min_by_key(|(_, v)| (v.freq, v.last_access))
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&k);
                }
            }
            CachePolicy::TinyLfu => {
                self.decay_if_needed(map);
                if let Some(k) = map
                    .iter()
                    .min_by_key(|(_, v)| (v.freq, v.last_access))
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&k);
                }
            }
            CachePolicy::Slru => {
                self.slru_rebalance(map);
                if let Some(k) = map
                    .iter()
                    .filter(|(_, v)| v.segment == Segment::Probationary)
                    .min_by_key(|(_, v)| v.last_access)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&k);
                    return;
                }
                if let Some(k) = map
                    .iter()
                    .filter(|(_, v)| v.segment == Segment::Protected)
                    .min_by_key(|(_, v)| v.last_access)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&k);
                }
            }
            CachePolicy::Simple => {}
        }
    }

    fn slru_rebalance(&self, map: &mut HashMap<String, SessionEntry<A, K, M>>) {
        if self.max == 0 {
            return;
        }
        let protected_cap = std::cmp::max(1, self.max / 2);
        let protected_count = map
            .values()
            .filter(|v| v.segment == Segment::Protected)
            .count();
        if protected_count > protected_cap {
            if let Some(k) = map
                .iter()
                .filter(|(_, v)| v.segment == Segment::Protected)
                .min_by_key(|(_, v)| v.last_access)
                .map(|(k, _)| k.clone())
            {
                if let Some(e) = map.get_mut(&k) {
                    e.segment = Segment::Probationary;
                }
            }
        }
    }

    fn decay_if_needed(&self, map: &mut HashMap<String, SessionEntry<A, K, M>>) {
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
