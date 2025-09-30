use crate::traits::{Loader, Storer};
use crate::types::DataRowRecord;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct InMemoryStore {
    map: Mutex<HashMap<serde_json::Value, DataRowRecord>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
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
        Ok(self.map.lock().unwrap().get(key).cloned())
    }
}

impl Storer for InMemoryStore {
    fn store(&self, d: &DataRowRecord) -> Result<serde_json::Value, anyhow::Error> {
        // Use Created + hash of data as key example; real impl likely uses DB key
        let key =
            serde_json::json!({"Created": d.key.as_ref().map(|k| k.created), "Len": d.data.len()});
        self.map.lock().unwrap().insert(key.clone(), d.clone());
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
