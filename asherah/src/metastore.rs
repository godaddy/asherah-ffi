use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;
use std::sync::Arc;

type MetastoreKey = (Arc<str>, i64);

#[derive(Clone)]
pub struct InMemoryMetastore {
    by_key: Arc<scc::HashMap<MetastoreKey, EnvelopeKeyRecord>>,
    latest: Arc<scc::HashMap<Arc<str>, i64>>,
}

impl std::fmt::Debug for InMemoryMetastore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryMetastore")
            .field("len", &self.by_key.len())
            .finish()
    }
}

impl InMemoryMetastore {
    pub fn new() -> Self {
        Self {
            by_key: Arc::new(scc::HashMap::new()),
            latest: Arc::new(scc::HashMap::new()),
        }
    }

    pub fn mark_revoked(&self, id: &str, created: i64) {
        let key: Arc<str> = Arc::from(id);
        self.by_key.update(&(key, created), |_, rec| {
            rec.revoked = Some(true);
        });
    }
}

impl Default for InMemoryMetastore {
    fn default() -> Self {
        Self::new()
    }
}

impl Metastore for InMemoryMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let key: Arc<str> = Arc::from(id);
        Ok(self.by_key.read(&(key, created), |_, v| v.clone()))
    }
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let interned: Arc<str> = Arc::from(id);
        let created = match self.latest.read(&interned, |_, &v| v) {
            Some(c) => c,
            None => return Ok(None),
        };
        Ok(self.by_key.read(&(interned, created), |_, v| v.clone()))
    }
    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        let interned: Arc<str> = Arc::from(id);
        let key = (interned.clone(), created);
        // Update the latest pointer BEFORE inserting into by_key. This ensures
        // that when a concurrent insert returns Err (duplicate), the winning
        // thread's latest pointer is already visible to load_latest.
        let should_update = self
            .latest
            .read(&interned, |_, &existing| existing < created)
            .unwrap_or(true);
        if should_update {
            let _ = self.latest.upsert(interned, created);
        }
        match self.by_key.insert(key, ekr.clone()) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // Key already exists
        }
    }
    fn region_suffix(&self) -> Option<String> {
        None
    }
}
