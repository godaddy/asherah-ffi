use std::sync::Arc;

use crate::traits::Metastore;
use crate::types::EnvelopeKeyRecord;

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct RegionSuffixMetastore<M: Metastore + ?Sized> {
    inner: Arc<M>,
    suffix: String,
}

impl<M: Metastore + ?Sized> RegionSuffixMetastore<M> {
    pub fn new(inner: Arc<M>, suffix: impl Into<String>) -> Self {
        Self {
            inner,
            suffix: suffix.into(),
        }
    }
}

impl<M: Metastore + ?Sized> Metastore for RegionSuffixMetastore<M> {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        self.inner.load(id, created)
    }
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        self.inner.load_latest(id)
    }
    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        self.inner.store(id, created, ekr)
    }
    fn region_suffix(&self) -> Option<String> {
        Some(self.suffix.clone())
    }
}
