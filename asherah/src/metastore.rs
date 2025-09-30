use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct InMemoryMetastore {
    inner: Arc<Mutex<HashMap<(String, i64), EnvelopeKeyRecord>>>,
}

impl InMemoryMetastore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn mark_revoked(&self, id: &str, created: i64) {
        let mut m = self.inner.lock();
        if let Some(rec) = m.get_mut(&(id.to_string(), created)) {
            rec.revoked = Some(true);
        }
    }
}

impl Default for InMemoryMetastore {
    fn default() -> Self {
        Self::new()
    }
}

impl Metastore for InMemoryMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        Ok(self.inner.lock().get(&(id.to_string(), created)).cloned())
    }
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let m = self.inner.lock();
        let mut best: Option<&EnvelopeKeyRecord> = None;
        for ((k, _), v) in m.iter() {
            if k == id {
                best = match best {
                    None => Some(v),
                    Some(b) => {
                        if v.created > b.created {
                            Some(v)
                        } else {
                            Some(b)
                        }
                    }
                };
            }
        }
        Ok(best.cloned())
    }
    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        let mut m = self.inner.lock();
        let key = (id.to_string(), created);
        if m.contains_key(&key) {
            return Ok(false);
        }
        m.insert(key, ekr.clone());
        Ok(true)
    }
    fn region_suffix(&self) -> Option<String> {
        None
    }
}
