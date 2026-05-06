use async_trait::async_trait;

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

#[async_trait]
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
        // Insert the row *before* advancing the latest pointer. A
        // concurrent `load_latest` reads `latest` and then reads
        // `by_key[(id, latest)]`; if we advanced the pointer first, a
        // reader could observe a `created` that points at a row that
        // hasn't been inserted yet and incorrectly conclude no row
        // exists. By inserting first, any reader that observes the
        // new pointer is guaranteed to find the row.
        match self.by_key.insert(key, ekr.clone()) {
            Ok(_) => {}
            Err(_) => return Ok(false), // (id, created) already exists
        }
        // Atomically advance the latest pointer for `id` to `created`,
        // but only when it's an actual advance. The previous read+upsert
        // pattern was racy: a slower writer with a smaller `created`
        // could overwrite a faster writer's larger value.
        //
        // `scc::HashMap::update` runs the closure under the bucket lock,
        // so the conditional advance is atomic. If the entry is missing
        // we try `insert` (which fails if someone else just inserted)
        // and retry the update path on collision. The loop terminates
        // because either an `update` succeeds or an `insert` succeeds.
        loop {
            if self
                .latest
                .update(&interned, |_, existing| {
                    if *existing < created {
                        *existing = created;
                    }
                })
                .is_some()
            {
                break;
            }
            if self.latest.insert(interned.clone(), created).is_ok() {
                break;
            }
            // Another writer raced ahead of our insert; loop to update.
        }
        Ok(true)
    }
    fn region_suffix(&self) -> Option<String> {
        None
    }
}
