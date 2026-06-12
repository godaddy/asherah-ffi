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
        self.by_key.update_sync(&(key, created), |_, rec| {
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
        Ok(self.by_key.read_sync(&(key, created), |_, v| v.clone()))
    }
    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        let interned: Arc<str> = Arc::from(id);
        let created = match self.latest.read_sync(&interned, |_, &v| v) {
            Some(c) => c,
            None => return Ok(None),
        };
        Ok(self
            .by_key
            .read_sync(&(interned, created), |_, v| v.clone()))
    }
    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        let interned: Arc<str> = Arc::from(id);
        let key = (interned.clone(), created);

        // Insert into by_key FIRST, before updating latest. This ensures
        // that load_latest() can never observe a `created` timestamp in
        // the `latest` map that doesn't yet exist in `by_key`. The original
        // order (latest-then-by_key) created a data race where concurrent
        // load_latest could read the new timestamp but fail to find the
        // corresponding key.
        //
        // Race scenario with wrong order (latest-first):
        //   T1: store(k, 100): update latest[k] = 100
        //   T2: load_latest(k): read latest[k] → 100
        //   T2: load(k, 100): lookup by_key[(k,100)] → None (not inserted yet!)
        //   T1: insert by_key[(k,100)] ← too late
        //
        // Correct order (by_key-first):
        //   T1: insert by_key[(k,100)]
        //   T1: update latest[k] = 100
        //   T2: load_latest(k): read latest[k] → 100
        //   T2: load(k, 100): lookup by_key[(k,100)] → Some(...) ✓
        let insert_result = self.by_key.insert_sync(key, ekr.clone());

        // Atomically advance the latest pointer for `id` to `created`,
        // but only when it's an actual advance. The previous read+upsert
        // pattern was racy: a slower writer with a smaller `created`
        // could overwrite a faster writer's larger value (T-finding
        // "InMemoryMetastore::store race on latest pointer" in
        // docs/review-2026-05-05-findings.md).
        //
        // `scc::HashMap::update_sync` runs the closure under the bucket lock,
        // so the conditional advance is atomic. If the entry is missing
        // we try `insert_sync` (which fails if someone else just inserted)
        // and retry the update path on collision. The loop terminates
        // because either an `update_sync` succeeds or an `insert_sync` succeeds.
        loop {
            if self
                .latest
                .update_sync(&interned, |_, existing| {
                    if *existing < created {
                        *existing = created;
                    }
                })
                .is_some()
            {
                break;
            }
            if self.latest.insert_sync(interned.clone(), created).is_ok() {
                break;
            }
            // Another writer raced ahead of our insert; loop to update.
        }

        match insert_result {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // Key already exists
        }
    }

    fn upsert_config_drift_guard(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<(), anyhow::Error> {
        let interned: Arc<str> = Arc::from(id);
        let key = (interned.clone(), created);
        let _old = self.by_key.upsert_sync(key, ekr.clone());
        let _old_latest = self.latest.upsert_sync(interned, created);
        Ok(())
    }

    fn region_suffix(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::traits::Metastore;
    use crate::types::EnvelopeKeyRecord;
    use std::sync::Arc;
    use std::thread;

    fn ekr(created: i64) -> EnvelopeKeyRecord {
        EnvelopeKeyRecord {
            id: "k".into(),
            created,
            encrypted_key: vec![0; 32],
            revoked: None,
            parent_key_meta: None,
        }
    }

    /// Regression for the store/load_latest race: a successful store must
    /// be visible via `load_latest` immediately. With the previous order
    /// (advance `latest` first, then insert into `by_key`) a concurrent
    /// `load_latest` could observe the new pointer but a missing row.
    #[test]
    fn load_latest_sees_row_immediately_after_store() {
        let m = InMemoryMetastore::new();
        assert!(m.store("k", 100, &ekr(100)).unwrap());
        let got = m.load_latest("k").unwrap().expect("load_latest must hit");
        assert_eq!(got.created, 100);
    }

    /// Stress: many concurrent stores at increasing `created` against
    /// concurrent `load_latest` readers. After the writers finish, the
    /// final `load_latest` must reflect the highest stored `created`,
    /// and no reader during the run may have observed a `latest` that
    /// pointed at a missing row.
    #[test]
    fn concurrent_store_load_latest_invariant() {
        let m = Arc::new(InMemoryMetastore::new());
        let writers = 8;
        let writes_per_writer = 200;

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Reader threads: spin reading load_latest. If load_latest returns
        // Some(rec), then re-loading the same row by exact key must also
        // return Some. (Equivalent to: the latest pointer never points at
        // a row that's missing from by_key.)
        let mut reader_handles = Vec::new();
        for _ in 0..4 {
            let m = Arc::clone(&m);
            let stop = Arc::clone(&stop);
            reader_handles.push(thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Some(rec) = m.load_latest("k").unwrap() {
                        assert!(
                            m.load("k", rec.created).unwrap().is_some(),
                            "load_latest returned a row whose (id, created) is \
                             missing from by_key"
                        );
                    }
                }
            }));
        }

        let mut writer_handles = Vec::new();
        for w in 0..writers {
            let m = Arc::clone(&m);
            writer_handles.push(thread::spawn(move || {
                for i in 0..writes_per_writer {
                    let created = (w as i64 * writes_per_writer as i64) + i as i64 + 1;
                    let _ = m.store("k", created, &ekr(created)).unwrap();
                }
            }));
        }
        for h in writer_handles {
            h.join().unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for h in reader_handles {
            h.join().unwrap();
        }

        let max_created = (writers as i64) * (writes_per_writer as i64);
        let latest = m.load_latest("k").unwrap().expect("must hit after writers");
        assert_eq!(latest.created, max_created);
    }
}
