use crate::cache::{KeyCacher, NeverCache, SimpleKeyCache};
use crate::config::Config;
use crate::internal::crypto_key::{generate_key, is_key_expired};
use crate::internal::CryptoKey;
use crate::metrics;
use crate::partition::DefaultPartition;
use crate::policy::CryptoPolicy;
use crate::session_cache::SessionCache;
use crate::traits::{KeyManagementService, Metastore, Partition, AEAD};
use crate::types::{EnvelopeKeyRecord, KeyMeta};
use std::sync::Arc;

#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct SessionFactory<
    A: AEAD + Clone,
    K: KeyManagementService + Clone,
    M: Metastore + Clone,
    P: Partition + Clone,
> {
    pub metastore: Arc<M>,
    pub kms: Arc<K>,
    pub policy: CryptoPolicy,
    pub crypto: Arc<A>,
    pub partition: Arc<P>,
}

impl<
        A: AEAD + Clone,
        K: KeyManagementService + Clone,
        M: Metastore + Clone,
        P: Partition + Clone,
    > SessionFactory<A, K, M, P>
{
    pub fn new(
        metastore: Arc<M>,
        kms: Arc<K>,
        policy: CryptoPolicy,
        crypto: Arc<A>,
        partition: Arc<P>,
    ) -> Self {
        Self {
            metastore,
            kms,
            policy,
            crypto,
            partition,
        }
    }

    pub fn session(&self) -> Session<A, K, M, P> {
        Session { f: self.clone() }
    }
}

impl<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone>
    SessionFactory<A, K, M, DefaultPartition>
{
    pub fn from_config(cfg: Config, metastore: Arc<M>, kms: Arc<K>, crypto: Arc<A>) -> Self {
        let part = match cfg.region_suffix.clone() {
            Some(s) => DefaultPartition::new_suffixed(
                String::new(),
                cfg.service.clone(),
                cfg.product.clone(),
                s,
            ),
            None => DefaultPartition::new(String::new(), cfg.service.clone(), cfg.product.clone()),
        };
        SessionFactory::new(metastore, kms, cfg.policy.clone(), crypto, Arc::new(part))
    }
}

#[allow(missing_debug_implementations)]
pub struct Session<
    A: AEAD + Clone,
    K: KeyManagementService + Clone,
    M: Metastore + Clone,
    P: Partition + Clone,
> {
    f: SessionFactory<A, K, M, P>,
}

impl<
        A: AEAD + Clone,
        K: KeyManagementService + Clone,
        M: Metastore + Clone,
        P: Partition + Clone,
    > Session<A, K, M, P>
{
    fn new_key_timestamp(&self) -> i64 {
        now_s() / self.f.policy.create_date_precision_s * self.f.policy.create_date_precision_s
    }

    fn system_key_id(&self) -> String {
        self.f.partition.system_key_id()
    }

    fn load_system_key(&self, meta: KeyMeta) -> anyhow::Result<CryptoKey> {
        let ekr = self
            .f
            .metastore
            .load(&meta.id, meta.created)?
            .ok_or_else(|| anyhow::anyhow!("system key not found"))?;
        self.system_key_from_ekr(&ekr)
    }

    fn system_key_from_ekr(&self, ekr: &EnvelopeKeyRecord) -> anyhow::Result<CryptoKey> {
        let bytes = self.f.kms.decrypt_key(&(), &ekr.encrypted_key)?;
        CryptoKey::new(ekr.created, ekr.revoked.unwrap_or(false), bytes)
    }

    fn intermediate_key_from_ekr(
        &self,
        sk: &CryptoKey,
        ekr: &EnvelopeKeyRecord,
    ) -> anyhow::Result<CryptoKey> {
        if let Some(pk) = &ekr.parent_key_meta {
            if sk.created() != pk.created {
                // load correct SK and use that for decryption
                let sk_loaded = self.get_or_load_system_key(pk.clone())?;
                let ik_bytes = sk_loaded.with_key_func(|sk_bytes| {
                    self.f.crypto.decrypt(&ekr.encrypted_key, sk_bytes)
                })??;
                return CryptoKey::new(
                    ekr.created,
                    ekr.revoked.unwrap_or(false),
                    ik_bytes,
                );
            }
        }
        let ik_bytes =
            sk.with_key_func(|sk_bytes| self.f.crypto.decrypt(&ekr.encrypted_key, sk_bytes))??;
        CryptoKey::new(ekr.created, ekr.revoked.unwrap_or(false), ik_bytes)
    }

    fn get_or_load_system_key(&self, meta: KeyMeta) -> anyhow::Result<CryptoKey> {
        self.load_system_key(meta)
    }

    fn load_latest_or_create_system_key(&self) -> anyhow::Result<CryptoKey> {
        if let Some(ekr) = self.f.metastore.load_latest(&self.system_key_id())? {
            if !self.is_envelope_invalid(&ekr) {
                return self.system_key_from_ekr(&ekr);
            }
        }
        // create new SK
        let sk = self.generate_key()?;
        let (success, enc_err) = self.try_store_system_key(&sk);
        if success {
            return Ok(sk);
        }
        // discard and fetch latest if store failed
        if let Some(e) = enc_err {
            return Err(e);
        }
        let ekr = self.must_load_latest(&self.system_key_id())?;
        self.system_key_from_ekr(&ekr)
    }

    fn try_store_system_key(&self, sk: &CryptoKey) -> (bool, Option<anyhow::Error>) {
        let enc = match sk.with_key_func(|k| self.f.kms.encrypt_key(&(), k)) {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return (false, Some(e)),
            Err(e) => return (false, Some(anyhow::anyhow!(format!("{:?}", e)))),
        };
        let ekr = EnvelopeKeyRecord {
            revoked: None,
            id: self.system_key_id(),
            created: sk.created(),
            encrypted_key: enc,
            parent_key_meta: None,
        };
        match self.f.metastore.store(&ekr.id, ekr.created, &ekr) {
            Ok(s) => (s, None),
            Err(_) => (false, None),
        }
    }

    fn generate_key(&self) -> anyhow::Result<CryptoKey> {
        generate_key(self.new_key_timestamp())
    }

    fn must_load_latest(&self, id: &str) -> anyhow::Result<EnvelopeKeyRecord> {
        let ekr = self
            .f
            .metastore
            .load_latest(id)?
            .ok_or_else(|| anyhow::anyhow!("latest not found"))?;
        Ok(ekr)
    }

    fn is_envelope_invalid(&self, ekr: &EnvelopeKeyRecord) -> bool {
        let expired = is_key_expired(ekr.created, self.f.policy.expire_key_after_s, now_s());
        let revoked = ekr.revoked.unwrap_or(false);
        expired || revoked
    }
}

fn now_s() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(_) => 0,
    }
}

// Public API compatible with Go shapes
impl<
        A: AEAD + Clone,
        K: KeyManagementService + Clone,
        M: Metastore + Clone,
        P: Partition + Clone,
    > Session<A, K, M, P>
{
    pub fn encrypt(&self, data: &[u8]) -> anyhow::Result<crate::types::DataRowRecord> {
        // Load or create IK
        let ik_ekr = self
            .f
            .metastore
            .load_latest(&self.f.partition.intermediate_key_id())?;
        let ik = match ik_ekr {
            Some(ekr) if !self.is_envelope_invalid(&ekr) => {
                // ensure SK validity and decrypt IK
                let sk = self.load_system_key(KeyMeta {
                    id: self.f.partition.system_key_id(),
                    created: ekr.parent_key_meta.as_ref().map(|m| m.created).unwrap_or(0),
                })?;
                self.intermediate_key_from_ekr(&sk, &ekr)?
            }
            _ => {
                // create path: get or create SK
                let sk = self.load_latest_or_create_system_key()?;
                let ik = generate_key(self.new_key_timestamp())?;
                // store IK encrypted under SK
                let enc_ik = ik.with_key_func(|ikb| {
                    sk.with_key_func(|skb| self.f.crypto.encrypt(ikb, skb))
                })??;
                let ekr = EnvelopeKeyRecord {
                    id: self.f.partition.intermediate_key_id(),
                    created: ik.created(),
                    encrypted_key: enc_ik?,
                    revoked: None,
                    parent_key_meta: Some(KeyMeta {
                        id: self.f.partition.system_key_id(),
                        created: sk.created(),
                    }),
                };
                self.f.metastore.store(&ekr.id, ekr.created, &ekr)?;
                ik
            }
        };
        // DRK and encrypt
        let drk = generate_key(now_s())?;
        let enc_data = drk.with_key_func(|k| self.f.crypto.encrypt(data, k))??;
        let enc_drk =
            ik.with_key_func(|ikb| drk.with_key_func(|drkb| self.f.crypto.encrypt(drkb, ikb)))??;
        Ok(crate::types::DataRowRecord {
            key: Some(EnvelopeKeyRecord {
                id: String::new(),
                created: drk.created(),
                encrypted_key: enc_drk?,
                revoked: None,
                parent_key_meta: Some(KeyMeta {
                    id: self.f.partition.intermediate_key_id(),
                    created: ik.created(),
                }),
            }),
            data: enc_data,
        })
    }

    pub fn decrypt(&self, drr: crate::types::DataRowRecord) -> anyhow::Result<Vec<u8>> {
        let key = drr.key.ok_or_else(|| anyhow::anyhow!("missing key"))?;
        let pmeta = key
            .parent_key_meta
            .ok_or_else(|| anyhow::anyhow!("missing parent key"))?;
        if !self.f.partition.is_valid_intermediate_key_id(&pmeta.id) {
            return Err(anyhow::anyhow!("invalid IK id"));
        }
        // load IK
        let ik_ekr = self
            .f
            .metastore
            .load(&pmeta.id, pmeta.created)?
            .ok_or_else(|| anyhow::anyhow!("ik not found"))?;
        let sk = self.load_system_key(KeyMeta {
            id: self.f.partition.system_key_id(),
            created: ik_ekr
                .parent_key_meta
                .as_ref()
                .map(|m| m.created)
                .unwrap_or(0),
        })?;
        let ik = self.intermediate_key_from_ekr(&sk, &ik_ekr)?;
        // decrypt DRK then data
        let mut drk = ik.with_key_func(|ikb| self.f.crypto.decrypt(&key.encrypted_key, ikb))??;
        let pt = self.f.crypto.decrypt(&drr.data, &drk)?;
        // wipe DRK bytes after use (practical parity with Go's MemClr)
        drk.fill(0);
        Ok(pt)
    }
}

// High-level helpers akin to Go API
impl<
        A: AEAD + Clone,
        K: KeyManagementService + Clone,
        M: Metastore + Clone,
        P: Partition + Clone,
    > Session<A, K, M, P>
{
    pub fn store<T: crate::traits::Storer>(
        &self,
        payload: &[u8],
        storer: &T,
    ) -> anyhow::Result<serde_json::Value> {
        let start = std::time::Instant::now();
        let drr = self.encrypt(payload)?;
        let res = storer.store(&drr);
        metrics::record_store(start);
        res
    }
    pub fn load<T: crate::traits::Loader>(
        &self,
        key: &serde_json::Value,
        loader: &T,
    ) -> anyhow::Result<Vec<u8>> {
        let start = std::time::Instant::now();
        let drr = loader
            .load(key)?
            .ok_or_else(|| anyhow::anyhow!("not found"))?;
        let res = self.decrypt(drr);
        metrics::record_load(start);
        res
    }
}

// Public factory and session that mirror Go API surface (non-generic entrypoints)
#[allow(missing_debug_implementations)]
pub struct PublicFactory<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone> {
    cfg: Config,
    metastore: Arc<M>,
    kms: Arc<K>,
    crypto: Arc<A>,
    shared_ik_cache: Option<Arc<dyn KeyCacher>>, // optional shared IK cache
    session_cache: Option<SessionCache<A, K, M>>,
    metrics_enabled: bool,
}

impl<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone>
    PublicFactory<A, K, M>
{
    pub fn new(cfg: Config, metastore: Arc<M>, kms: Arc<K>, crypto: Arc<A>) -> Self {
        let shared = if cfg.policy.shared_intermediate_key_cache {
            let cache: Arc<dyn KeyCacher> = Arc::new(SimpleKeyCache::new_with_ttl(
                cfg.policy.revoke_check_interval_s,
            ));
            Some(cache)
        } else {
            None
        };
        let sess_cache = if cfg.policy.cache_sessions {
            Some(SessionCache::new(
                cfg.policy.session_cache_max_size,
                cfg.policy.session_cache_ttl_s,
            ))
        } else {
            None
        };
        Self {
            cfg,
            metastore,
            kms,
            crypto,
            shared_ik_cache: shared,
            session_cache: sess_cache,
            metrics_enabled: true,
        }
    }

    pub fn with_metrics(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }
    pub fn get_session(&self, id: &str) -> PublicSession<A, K, M> {
        let suffix = self
            .metastore
            .region_suffix()
            .or(self.cfg.region_suffix.clone());
        let part = match suffix {
            Some(s) if !s.is_empty() => DefaultPartition::new_suffixed(
                id.to_string(),
                self.cfg.service.clone(),
                self.cfg.product.clone(),
                s,
            ),
            _ => DefaultPartition::new(
                id.to_string(),
                self.cfg.service.clone(),
                self.cfg.product.clone(),
            ),
        };
        let construct = || {
            let inner = SessionFactory::new(
                self.metastore.clone(),
                self.kms.clone(),
                self.cfg.policy.clone(),
                self.crypto.clone(),
                Arc::new(part),
            )
            .session();
            let sk_cache: Arc<dyn KeyCacher> = if self.cfg.policy.cache_system_keys {
                Arc::new(SimpleKeyCache::new_with_ttl(
                    self.cfg.policy.revoke_check_interval_s,
                ))
            } else {
                Arc::new(NeverCache)
            };
            let ik_cache: Arc<dyn KeyCacher> = match &self.shared_ik_cache {
                Some(shared) => shared.clone(),
                None => {
                    if self.cfg.policy.cache_intermediate_keys {
                        Arc::new(SimpleKeyCache::new_with_ttl(
                            self.cfg.policy.revoke_check_interval_s,
                        ))
                    } else {
                        Arc::new(NeverCache)
                    }
                }
            };
            PublicSession {
                inner,
                metastore: self.metastore.clone(),
                kms: self.kms.clone(),
                crypto: self.crypto.clone(),
                sk_cache,
                ik_cache,
                metrics_enabled: self.metrics_enabled,
            }
        };
        if let Some(cache) = &self.session_cache {
            let arc = cache.get_or_create(id, construct);
            // clone out the Arc contents by cloning fields (PublicSession is not Clone). Here, just deref copy
            Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone_for_return())
        } else {
            construct()
        }
    }

    pub fn close(&self) -> anyhow::Result<()> {
        if let Some(c) = &self.session_cache {
            c.close();
        }
        Ok(())
    }
}

#[allow(missing_debug_implementations)]
pub struct PublicSession<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone> {
    inner: Session<A, K, M, DefaultPartition>,
    metastore: Arc<M>,
    kms: Arc<K>,
    crypto: Arc<A>,
    sk_cache: Arc<dyn KeyCacher>,
    ik_cache: Arc<dyn KeyCacher>,
    metrics_enabled: bool,
}

impl<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone>
    PublicSession<A, K, M>
{
    fn clone_for_return(&self) -> Self {
        PublicSession {
            inner: Session {
                f: self.inner.f.clone(),
            },
            metastore: self.metastore.clone(),
            kms: self.kms.clone(),
            crypto: self.crypto.clone(),
            sk_cache: self.sk_cache.clone(),
            ik_cache: self.ik_cache.clone(),
            metrics_enabled: self.metrics_enabled,
        }
    }
}

#[allow(clippy::same_name_method)]
impl<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone>
    PublicSession<A, K, M>
{
    fn get_or_load_system_key(&self, meta: KeyMeta) -> anyhow::Result<Arc<CryptoKey>> {
        if meta.created == 0 {
            let id = self.inner.f.partition.system_key_id();
            let mut loader_latest = || -> anyhow::Result<Arc<CryptoKey>> {
                Ok(Arc::new(self.inner.load_latest_or_create_system_key()?))
            };
            self.sk_cache.get_or_load_latest(&id, &mut loader_latest)
        } else {
            let mut loader = || -> anyhow::Result<Arc<CryptoKey>> {
                Ok(Arc::new(self.inner.load_system_key(meta.clone())?))
            };
            self.sk_cache.get_or_load(&meta, &mut loader)
        }
    }

    fn create_intermediate_key(&self) -> anyhow::Result<Arc<CryptoKey>> {
        let sk_meta = KeyMeta {
            id: self.inner.f.partition.system_key_id(),
            created: 0,
        };
        let sk = self.get_or_load_system_key(sk_meta)?;
        let ik = generate_key(self.inner.new_key_timestamp())?;
        let enc_ik =
            ik.with_key_func(|ikb| sk.with_key_func(|skb| self.crypto.encrypt(ikb, skb)))??;
        let ekr = EnvelopeKeyRecord {
            id: self.inner.f.partition.intermediate_key_id(),
            created: ik.created(),
            encrypted_key: enc_ik?,
            revoked: None,
            parent_key_meta: Some(KeyMeta {
                id: self.inner.f.partition.system_key_id(),
                created: sk.created(),
            }),
        };
        let stored = self
            .metastore
            .store(&ekr.id, ekr.created, &ekr)
            .unwrap_or(false);
        if stored {
            return Ok(Arc::new(ik));
        }
        // Fallback: assume duplicate/newer IK exists; load latest and return that one
        if let Some(latest) = self
            .metastore
            .load_latest(&self.inner.f.partition.intermediate_key_id())?
        {
            if !self.inner.is_envelope_invalid(&latest) {
                let sk_meta = latest.parent_key_meta.clone().unwrap_or(KeyMeta {
                    id: self.inner.f.partition.system_key_id(),
                    created: 0,
                });
                let sk2 = self.get_or_load_system_key(sk_meta)?;
                let ik2 = self.inner.intermediate_key_from_ekr(&sk2, &latest)?;
                return Ok(Arc::new(ik2));
            }
        }
        // If latest missing/invalid, still return newly generated IK (cache will hold it for this process)
        Ok(Arc::new(ik))
    }

    fn load_latest_or_create_intermediate_key(&self) -> anyhow::Result<Arc<CryptoKey>> {
        if let Some(ekr) = self
            .metastore
            .load_latest(&self.inner.f.partition.intermediate_key_id())?
        {
            if !self.inner.is_envelope_invalid(&ekr) {
                // decrypt under SK
                let sk_meta = ekr.parent_key_meta.clone().unwrap_or(KeyMeta {
                    id: self.inner.f.partition.system_key_id(),
                    created: 0,
                });
                let sk = self.get_or_load_system_key(sk_meta)?;
                let ik = self.inner.intermediate_key_from_ekr(&sk, &ekr)?;
                return Ok(Arc::new(ik));
            }
        }
        self.create_intermediate_key()
    }

    fn load_intermediate_key(&self, meta: KeyMeta) -> anyhow::Result<Arc<CryptoKey>> {
        let ekr = self
            .metastore
            .load(&meta.id, meta.created)?
            .ok_or_else(|| anyhow::anyhow!("ik missing"))?;
        let sk_meta = ekr.parent_key_meta.clone().unwrap_or(KeyMeta {
            id: self.inner.f.partition.system_key_id(),
            created: 0,
        });
        let sk = self.get_or_load_system_key(sk_meta)?;
        let ik = self.inner.intermediate_key_from_ekr(&sk, &ekr)?;
        Ok(Arc::new(ik))
    }

    pub fn encrypt(&self, data: &[u8]) -> anyhow::Result<crate::types::DataRowRecord> {
        let start = std::time::Instant::now();
        let mut loader = || self.load_latest_or_create_intermediate_key();
        let ik = self
            .ik_cache
            .get_or_load_latest(&self.inner.f.partition.intermediate_key_id(), &mut loader)?;
        // Fast DRK path: avoid memguard for ephemeral data-row key
        let created = now_s();
        let mut drk = vec![0_u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut drk);
        let enc_data = self.crypto.encrypt(data, &drk)?;
        let enc_drk = ik.with_key_func(|ikb| self.crypto.encrypt(&drk, ikb))??;
        // wipe drk
        drk.fill(0);
        let result = crate::types::DataRowRecord {
            key: Some(EnvelopeKeyRecord {
                id: String::new(),
                created,
                encrypted_key: enc_drk,
                revoked: None,
                parent_key_meta: Some(KeyMeta {
                    id: self.inner.f.partition.intermediate_key_id(),
                    created: ik.created(),
                }),
            }),
            data: enc_data,
        };
        if self.metrics_enabled {
            metrics::record_encrypt(start);
        }
        Ok(result)
    }

    pub fn decrypt(&self, drr: crate::types::DataRowRecord) -> anyhow::Result<Vec<u8>> {
        let start = std::time::Instant::now();
        let key = drr.key.ok_or_else(|| anyhow::anyhow!("missing key"))?;
        let pmeta = key
            .parent_key_meta
            .ok_or_else(|| anyhow::anyhow!("missing parent key"))?;
        if !self
            .inner
            .f
            .partition
            .is_valid_intermediate_key_id(&pmeta.id)
        {
            return Err(anyhow::anyhow!("invalid IK id"));
        }
        let mut loader = || self.load_intermediate_key(pmeta.clone());
        let ik = self.ik_cache.get_or_load(&pmeta, &mut loader)?;
        let mut drk = ik.with_key_func(|ikb| self.crypto.decrypt(&key.encrypted_key, ikb))??;
        let pt = self.crypto.decrypt(&drr.data, &drk)?;
        drk.fill(0);
        if self.metrics_enabled {
            metrics::record_decrypt(start);
        }
        Ok(pt)
    }
    pub fn store<T: crate::traits::Storer>(
        &self,
        payload: &[u8],
        storer: &T,
    ) -> anyhow::Result<serde_json::Value> {
        self.inner.store(payload, storer)
    }
    pub fn load<T: crate::traits::Loader>(
        &self,
        key: &serde_json::Value,
        loader: &T,
    ) -> anyhow::Result<Vec<u8>> {
        self.inner.load(key, loader)
    }
    pub fn close(&self) -> anyhow::Result<()> {
        Ok(())
    }

    // Context-aware wrappers to mirror Go's API signatures (context is unused placeholder)
    pub fn encrypt_ctx(
        &self,
        _ctx: &(),
        data: &[u8],
    ) -> anyhow::Result<crate::types::DataRowRecord> {
        self.encrypt(data)
    }
    pub fn decrypt_ctx(
        &self,
        _ctx: &(),
        drr: crate::types::DataRowRecord,
    ) -> anyhow::Result<Vec<u8>> {
        self.decrypt(drr)
    }
    pub fn store_ctx<T: crate::traits::StorerCtx>(
        &self,
        ctx: &(),
        payload: &[u8],
        storer: &T,
    ) -> anyhow::Result<serde_json::Value> {
        let drr = self.encrypt(payload)?;
        storer.store_ctx(ctx, &drr)
    }
    pub fn load_ctx<T: crate::traits::LoaderCtx>(
        &self,
        ctx: &(),
        key: &serde_json::Value,
        loader: &T,
    ) -> anyhow::Result<Vec<u8>> {
        let drr = loader
            .load_ctx(ctx, key)?
            .ok_or_else(|| anyhow::anyhow!("not found"))?;
        self.decrypt_ctx(ctx, drr)
    }
}
