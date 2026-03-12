use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cache::CachePolicy;
use crate::session::PublicSession;
use crate::traits::{KeyManagementService, Metastore, AEAD};

const SEG_PROBATIONARY: u8 = 0;
const SEG_PROTECTED: u8 = 1;

struct SessionEntry<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone> {
    sess: Arc<PublicSession<A, K, M>>,
    ts: Instant,
    last_access: AtomicU64,
    freq: AtomicU64,
    segment: AtomicU8,
}

#[allow(missing_debug_implementations)]
pub struct SessionCache<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone> {
    map: scc::HashMap<String, SessionEntry<A, K, M>>,
    max: usize,
    ttl: Duration,
    policy: CachePolicy,
    access_ctr: AtomicU64,
    decay_ctr: AtomicU64,
}

impl<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone> SessionCache<A, K, M> {
    pub fn new(max: usize, ttl_s: i64, policy: CachePolicy) -> Self {
        Self {
            map: scc::HashMap::new(),
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
        // read() takes a shared lock — atomics let us update metadata without exclusive access
        if let Some(Some((sess, promote))) = self.map.read(id, |_, entry| {
            if self.ttl != Duration::from_secs(0) && entry.ts.elapsed() < self.ttl {
                entry
                    .last_access
                    .store(self.next_access(), Ordering::Relaxed);
                entry.freq.fetch_add(1, Ordering::Relaxed);
                let seg = entry.segment.load(Ordering::Relaxed);
                let promote = self.policy == CachePolicy::Slru && seg == SEG_PROBATIONARY;
                if promote {
                    entry.segment.store(SEG_PROTECTED, Ordering::Relaxed);
                }
                Some((entry.sess.clone(), promote))
            } else {
                None
            }
        }) {
            if promote {
                self.slru_rebalance();
            }
            return sess;
        }

        // Cache miss or expired — create new session
        let s = Arc::new(create());
        let entry = SessionEntry {
            sess: s.clone(),
            ts: Instant::now(),
            last_access: AtomicU64::new(self.next_access()),
            freq: AtomicU64::new(1),
            segment: AtomicU8::new(SEG_PROBATIONARY),
        };
        drop(self.map.remove(id));
        drop(self.map.insert(id.to_string(), entry));
        self.evict_if_needed();
        s
    }

    pub fn close(&self) {
        self.map.retain(|_, _| false);
    }

    fn next_access(&self) -> u64 {
        self.access_ctr.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn evict_if_needed(&self) {
        if self.policy == CachePolicy::Simple || self.max == 0 {
            return;
        }
        while self.map.len() > self.max {
            self.evict_one();
        }
    }

    fn evict_one(&self) {
        match self.policy {
            CachePolicy::Lru => {
                let mut victim: Option<(String, u64)> = None;
                self.map.scan(|k, v| {
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
                    self.map.remove(&k);
                }
            }
            CachePolicy::Lfu => {
                let mut victim: Option<(String, (u64, u64))> = None;
                self.map.scan(|k, v| {
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
                    self.map.remove(&k);
                }
            }
            CachePolicy::TinyLfu => {
                self.decay_if_needed();
                let mut victim: Option<(String, (u64, u64))> = None;
                self.map.scan(|k, v| {
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
                    self.map.remove(&k);
                }
            }
            CachePolicy::Slru => {
                self.slru_rebalance();
                let mut victim: Option<(String, u64)> = None;
                self.map.scan(|k, v| {
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
                    self.map.remove(&k);
                    return;
                }
                let mut victim: Option<(String, u64)> = None;
                self.map.scan(|k, v| {
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
                    self.map.remove(&k);
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
        let mut victim: Option<(String, u64)> = None;
        self.map.scan(|k, v| {
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
                self.map.read(&k, |_, v| {
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
            self.map.scan(|_, v| {
                let old = v.freq.load(Ordering::Relaxed);
                v.freq.store(std::cmp::max(1, old / 2), Ordering::Relaxed);
            });
        }
    }
}
