use crate::traits::{Loader, Storer};
use crate::types::DataRowRecord;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
pub struct InMemoryStore {
    map: Mutex<HashMap<serde_json::Value, DataRowRecord>>,
    counter: AtomicU64,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(0),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Loader for InMemoryStore {
    fn load(&self, key: &serde_json::Value) -> Result<Option<DataRowRecord>, anyhow::Error> {
        Ok(self.map.lock().get(key).cloned())
    }
}

impl Storer for InMemoryStore {
    fn store(&self, d: &DataRowRecord) -> Result<serde_json::Value, anyhow::Error> {
        // Per-store unique key. The previous `{Created, Len}` shape
        // collided whenever two distinct DataRowRecords happened to share
        // the same `Created` second and the same ciphertext length —
        // e.g. two records produced inside the same wall-clock second.
        // The second `store` would overwrite the first silently, and the
        // caller had no way to recover the lost record. Use a monotonic
        // counter so each call gets a unique key. T-finding "InMemoryStore
        // key collision on {Created, Len}" in
        // `docs/review-2026-05-05-findings.md`.
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let key = serde_json::json!({
            "Created": d.key.as_ref().map(|k| k.created),
            "Len": d.data.len(),
            "Seq": n,
        });
        self.map.lock().insert(key.clone(), d.clone());
        Ok(key)
    }
}

impl crate::traits::LoaderCtx for InMemoryStore {
    fn load_ctx(
        &self,
        _ctx: &(),
        key: &serde_json::Value,
    ) -> Result<Option<DataRowRecord>, anyhow::Error> {
        self.load(key)
    }
}

impl crate::traits::StorerCtx for InMemoryStore {
    fn store_ctx(&self, _ctx: &(), d: &DataRowRecord) -> Result<serde_json::Value, anyhow::Error> {
        self.store(d)
    }
}
