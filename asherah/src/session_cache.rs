use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::session::PublicSession;
use crate::traits::{KeyManagementService, Metastore, AEAD};

type SessionEntry<A, K, M> = (Arc<PublicSession<A, K, M>>, Instant);

#[allow(missing_debug_implementations)]
pub struct SessionCache<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone> {
    map: Mutex<HashMap<String, SessionEntry<A, K, M>>>,
    max: usize,
    ttl: Duration,
}

impl<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone> SessionCache<A, K, M> {
    pub fn new(max: usize, ttl_s: i64) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            max,
            ttl: Duration::from_secs(ttl_s as u64),
        }
    }

    pub fn get_or_create(
        &self,
        id: &str,
        create: impl FnOnce() -> PublicSession<A, K, M>,
    ) -> Arc<PublicSession<A, K, M>> {
        let mut map = self.map.lock();
        if let Some((sess, ts)) = map.get_mut(id) {
            if ts.elapsed() < self.ttl {
                *ts = Instant::now();
                return sess.clone();
            }
        }
        let s = Arc::new(create());
        map.insert(id.to_string(), (s.clone(), Instant::now()));
        if map.len() > self.max {
            // evict oldest
            if let Some((old_key, _)) = map
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, v)| (k.clone(), v.clone()))
            {
                map.remove(&old_key);
            }
        }
        s
    }

    pub fn close(&self) {
        self.map.lock().clear();
    }
}
