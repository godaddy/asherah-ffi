use crate::cache::{CacheCheck, CachePolicy, KeyCacher, NeverCache, SimpleKeyCache};
use crate::config::Config;
use crate::internal::crypto_key::{generate_key, is_key_expired};
use crate::internal::CryptoKey;
use crate::metrics;
use crate::partition::DefaultPartition;
use crate::policy::CryptoPolicy;
use crate::session_cache::SessionCache;
use crate::traits::{KeyManagementService, Metastore, Partition, AEAD};
use crate::types::{EnvelopeKeyRecord, KeyMeta};
use anyhow::Context;
use std::sync::Arc;
use zeroize::Zeroize as _;

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
        // We own `cfg` by value — destructure to move every field out
        // exactly once, no per-field `.clone()`. T-finding "from_config
        // clones every field" in
        // `docs/review-2026-05-05-findings.md`.
        // The legacy generic SessionFactory does not implement decrypt recovery
        // (bindings use PublicSession), so `recovery_region_suffixes` is dropped
        // via `..`; the remaining fields are still moved out exactly once.
        let Config {
            service,
            product,
            policy,
            region_suffix,
            ..
        } = cfg;
        let part = match region_suffix {
            Some(s) => DefaultPartition::new_suffixed(String::new(), service, product, s),
            None => DefaultPartition::new(String::new(), service, product),
        };
        SessionFactory::new(metastore, kms, policy, crypto, Arc::new(part))
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
        if self.f.policy.create_date_precision_s <= 0 {
            return now_s();
        }
        now_s() / self.f.policy.create_date_precision_s * self.f.policy.create_date_precision_s
    }

    fn system_key_id(&self) -> String {
        self.f.partition.system_key_id()
    }

    fn load_system_key(&self, meta: KeyMeta) -> anyhow::Result<CryptoKey> {
        log::debug!("load_system_key: id={} created={}", meta.id, meta.created);
        let ekr = self
            .f
            .metastore
            .load(&meta.id, meta.created)
            .context(format!(
                "failed to load system key id={} created={}",
                meta.id, meta.created
            ))?
            .ok_or_else(|| {
                log::error!(
                    "system key not found: id={} created={}",
                    meta.id,
                    meta.created
                );
                anyhow::anyhow!(
                    "system key not found: id={} created={}",
                    meta.id,
                    meta.created
                )
            })?;
        self.system_key_from_ekr(&ekr)
            .context(format!("failed to decrypt system key id={}", meta.id))
    }

    fn system_key_from_ekr(&self, ekr: &EnvelopeKeyRecord) -> anyhow::Result<CryptoKey> {
        let bytes = self
            .f
            .kms
            .decrypt_key(&(), &ekr.encrypted_key)
            .context(format!(
                "KMS failed to decrypt system key id={} created={}",
                ekr.id, ekr.created
            ))?;
        CryptoKey::new(ekr.created, ekr.revoked.unwrap_or(false), bytes)
    }

    fn intermediate_key_from_ekr(
        &self,
        sk: &CryptoKey,
        ekr: &EnvelopeKeyRecord,
    ) -> anyhow::Result<CryptoKey> {
        if let Some(pk) = &ekr.parent_key_meta {
            if sk.created() != pk.created {
                log::debug!(
                    "IK parent SK mismatch: have created={}, need created={}, loading correct SK",
                    sk.created(),
                    pk.created
                );
                let sk_loaded = self.get_or_load_system_key(pk.clone())?;
                let ik_bytes = sk_loaded.with_key_func(|sk_bytes| {
                    self.f.crypto.decrypt(&ekr.encrypted_key, sk_bytes)
                })??;
                return CryptoKey::new(ekr.created, ekr.revoked.unwrap_or(false), ik_bytes);
            }
        }
        let ik_bytes = sk
            .with_key_func(|sk_bytes| self.f.crypto.decrypt(&ekr.encrypted_key, sk_bytes))
            .context(format!(
                "failed to decrypt intermediate key id={} created={}",
                ekr.id, ekr.created
            ))??;
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
            Ok(Err(e)) => {
                log::error!("try_store_system_key: KMS encrypt_key failed: {e:#}");
                return (false, Some(e));
            }
            Err(e) => {
                log::error!("try_store_system_key: key enclave open failed: {e:#}");
                return (
                    false,
                    Some(anyhow::anyhow!("key enclave open failed: {e:#}")),
                );
            }
        };
        let ekr = EnvelopeKeyRecord {
            revoked: None,
            id: self.system_key_id(),
            created: sk.created(),
            encrypted_key: enc,
            parent_key_meta: None,
        };
        match self.f.metastore.store(&ekr.id, ekr.created, &ekr) {
            Ok(s) => {
                if !s {
                    log::debug!(
                        "try_store_system_key: store returned false (duplicate) for id={}",
                        ekr.id
                    );
                }
                (s, None)
            }
            Err(e) => {
                log::warn!(
                    "try_store_system_key: metastore store failed for id={}: {e:#}",
                    ekr.id
                );
                (false, None)
            }
        }
    }

    fn generate_key(&self) -> anyhow::Result<CryptoKey> {
        generate_key(self.new_key_timestamp())
    }

    fn must_load_latest(&self, id: &str) -> anyhow::Result<EnvelopeKeyRecord> {
        let ekr = self
            .f
            .metastore
            .load_latest(id)
            .context(format!("failed to load latest key for id={id}"))?
            .ok_or_else(|| {
                log::error!("latest key not found for id={id}");
                anyhow::anyhow!("latest key not found for id={id}")
            })?;
        Ok(ekr)
    }

    fn is_envelope_invalid(&self, ekr: &EnvelopeKeyRecord) -> bool {
        let expired = is_key_expired(ekr.created, self.f.policy.expire_key_after_s, now_s());
        let revoked = ekr.revoked.unwrap_or(false);
        expired || revoked
    }

    // Public API compatible with Go shapes

    pub fn encrypt(&self, data: &[u8]) -> anyhow::Result<crate::types::DataRowRecord> {
        let ik_id = self.f.partition.intermediate_key_id();
        log::debug!("encrypt: loading IK id={ik_id}");
        // Load or create IK
        let ik_ekr = self
            .f
            .metastore
            .load_latest(&ik_id)
            .context(format!("encrypt: failed to load latest IK id={ik_id}"))?;
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
                log::debug!("encrypt: no valid IK found, creating new key hierarchy");
                // create path: get or create SK
                let sk = self
                    .load_latest_or_create_system_key()
                    .context("encrypt: failed to load or create system key")?;
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
                // Match the modern `create_intermediate_key` race-loss
                // recovery: if our store loses to another encrypter that
                // created the IK first, reload the winner's IK rather
                // than surfacing a misleading "store failed" error.
                // T-finding "Legacy Session::encrypt doesn't reload
                // load_latest on race-loss" in
                // `docs/review-2026-05-05-findings.md`.
                let stored =
                    self.f
                        .metastore
                        .store(&ekr.id, ekr.created, &ekr)
                        .context(format!(
                            "encrypt: failed to store intermediate key id={}",
                            ekr.id
                        ))?;
                if stored {
                    ik
                } else {
                    log::debug!(
                        "encrypt: IK store returned false, loading latest for id={}",
                        ekr.id
                    );
                    let latest = self
                        .f
                        .metastore
                        .load_latest(&ekr.id)
                        .context("encrypt: race-loss fallback load_latest failed")?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "encrypt: store returned false for id={} but load_latest \
                                 returned None — metastore may be inconsistent",
                                ekr.id
                            )
                        })?;
                    let sk_meta = latest.parent_key_meta.clone().unwrap_or(KeyMeta {
                        id: self.f.partition.system_key_id(),
                        created: 0,
                    });
                    let sk2 = self.load_system_key(sk_meta)?;
                    self.intermediate_key_from_ekr(&sk2, &latest)?
                }
            }
        };
        // DRK and encrypt
        let drk = generate_key(now_s())?;
        let enc_data = drk
            .with_key_func(|k| self.f.crypto.encrypt(data, k))
            .context("encrypt: failed to encrypt data with DRK")??;
        let enc_drk = ik
            .with_key_func(|ikb| drk.with_key_func(|drkb| self.f.crypto.encrypt(drkb, ikb)))
            .context("encrypt: failed to encrypt DRK with IK")??;
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
        let key = drr
            .key
            .ok_or_else(|| anyhow::anyhow!("decrypt: DRR missing key envelope"))?;
        let pmeta = key
            .parent_key_meta
            .ok_or_else(|| anyhow::anyhow!("decrypt: DRR key missing parent_key_meta"))?;
        if !self.f.partition.is_valid_intermediate_key_id(&pmeta.id) {
            return Err(anyhow::anyhow!(
                "decrypt: invalid IK id={} for partition (expected {})",
                pmeta.id,
                self.f.partition.intermediate_key_id()
            ));
        }
        log::debug!(
            "decrypt: loading IK id={} created={}",
            pmeta.id,
            pmeta.created
        );
        // load IK
        let ik_ekr = self
            .f
            .metastore
            .load(&pmeta.id, pmeta.created)
            .context(format!(
                "decrypt: failed to load IK id={} created={}",
                pmeta.id, pmeta.created
            ))?
            .ok_or_else(|| {
                log::error!(
                    "decrypt: IK not found id={} created={}",
                    pmeta.id,
                    pmeta.created
                );
                anyhow::anyhow!(
                    "decrypt: intermediate key not found id={} created={}",
                    pmeta.id,
                    pmeta.created
                )
            })?;
        let sk = self.load_system_key(KeyMeta {
            id: self.f.partition.system_key_id(),
            created: ik_ekr
                .parent_key_meta
                .as_ref()
                .map(|m| m.created)
                .unwrap_or(0),
        })?;
        let ik = self.intermediate_key_from_ekr(&sk, &ik_ekr)?;
        // decrypt DRK then data. The DRK is wrapped in `Zeroizing` so
        // it is volatile-wiped on every exit path — including the
        // AEAD-decrypt error case below. The async/`PublicSession`
        // paths use a stack-allocated `DrkGuard([u8; 32])`; here the
        // DRK starts life as a `Vec<u8>` from `crypto.decrypt`, so
        // wrapping in `Zeroizing<Vec<u8>>` is the equivalent shape.
        // T-finding "Legacy decrypt doesn't wipe drk when AEAD fails"
        // in `docs/review-2026-05-05-findings.md`. The previous
        // implementation defined an inline `DrkWipe<'drk>` borrow-
        // guard struct that drifted from the canonical `DrkGuard`;
        // unified by switching to the `Zeroizing` wrapper.
        let drk: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(
            ik.with_key_func(|ikb| self.f.crypto.decrypt(&key.encrypted_key, ikb))
                .context("decrypt: failed to decrypt DRK with IK")??,
        );
        let pt = self
            .f
            .crypto
            .decrypt(&drr.data, &drk)
            .context("decrypt: failed to decrypt data with DRK")?;
        // `drk` Zeroizing wrapper drops at end of function → wipes.
        // pt is the decrypted plaintext; the FFI layers (asherah_buffer_free,
        // asherah-cobhan Decrypt/DecryptFromJson) are responsible for zeroing
        // it before deallocation.
        Ok(pt)
    }

    // High-level helpers akin to Go API

    pub fn store<T: crate::traits::Storer>(
        &self,
        payload: &[u8],
        storer: &T,
    ) -> anyhow::Result<serde_json::Value> {
        let start = if metrics::is_enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let drr = self.encrypt(payload)?;
        let res = storer.store(&drr);
        if let Some(start) = start {
            metrics::record_store(start);
        }
        res
    }
    pub fn load<T: crate::traits::Loader>(
        &self,
        key: &serde_json::Value,
        loader: &T,
    ) -> anyhow::Result<Vec<u8>> {
        let start = if metrics::is_enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let drr = loader.load(key)?.ok_or_else(|| {
            anyhow::anyhow!("record not found in persistence store for the given key")
        })?;
        let res = self.decrypt(drr);
        if let Some(start) = start {
            metrics::record_load(start);
        }
        res
    }
}

#[inline(always)]
pub(crate) fn now_s() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // `duration_since` returns `Err` when the system clock is set
    // before 1970 — only realistic on a freshly-imaged machine where
    // NTP hasn't run yet. The previous implementation collapsed that
    // error to `0`, which silently mapped the entire pre-epoch window
    // onto epoch 0 and would make every "is_expired" check decide
    // against the current time of `0`. Use the absolute-value form
    // (`UNIX_EPOCH - now`) and negate, so the returned timestamp at
    // least preserves the relative ordering across negative values.
    // T-finding "now_s returns 0 if SystemTime::now < UNIX_EPOCH" in
    // `docs/review-2026-05-05-findings.md`.
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

// Public factory and session that mirror Go API surface (non-generic entrypoints)
#[allow(missing_debug_implementations)]
pub struct PublicFactory<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone> {
    cfg: Config,
    metastore: Arc<M>,
    kms: Arc<K>,
    crypto: Arc<A>,
    shared_sk_cache: Arc<dyn KeyCacher>, // factory-level system key cache (shared by all sessions)
    shared_ik_cache: Option<Arc<dyn KeyCacher>>, // optional shared IK cache
    session_cache: Option<SessionCache<A, K, M>>,
    metrics_enabled: bool,
}

impl<A: AEAD + Clone, K: KeyManagementService + Clone, M: Metastore + Clone>
    PublicFactory<A, K, M>
{
    pub fn new(cfg: Config, metastore: Arc<M>, kms: Arc<K>, crypto: Arc<A>) -> Self {
        // IK cache: optionally shared across sessions
        let shared =
            if cfg.policy.shared_intermediate_key_cache && cfg.policy.cache_intermediate_keys {
                let policy = CachePolicy::parse(
                    &cfg.policy.intermediate_key_cache_eviction_policy,
                    CachePolicy::Simple,
                );
                let cache: Arc<dyn KeyCacher> = Arc::new(SimpleKeyCache::new_with_policy(
                    cfg.policy.revoke_check_interval_s,
                    cfg.policy.intermediate_key_cache_max_size,
                    policy,
                    cfg.policy.expire_key_after_s,
                ));
                Some(cache)
            } else {
                None
            };
        // SK cache: shared at factory level (NeverCache if explicitly disabled for tests)
        let shared_sk: Arc<dyn KeyCacher> = if cfg.policy.cache_system_keys {
            let policy = CachePolicy::parse(
                &cfg.policy.system_key_cache_eviction_policy,
                CachePolicy::Simple,
            );
            Arc::new(SimpleKeyCache::new_with_policy(
                cfg.policy.revoke_check_interval_s,
                cfg.policy.system_key_cache_max_size,
                policy,
                cfg.policy.expire_key_after_s,
            ))
        } else {
            Arc::new(NeverCache)
        };
        // Session cache (None if explicitly disabled for tests)
        let sess_cache = if cfg.policy.cache_sessions {
            Some(SessionCache::new(
                cfg.policy.session_cache_max_size,
                cfg.policy.session_cache_ttl_s,
                CachePolicy::parse(&cfg.policy.session_cache_eviction_policy, CachePolicy::Slru),
            ))
        } else {
            None
        };
        Self {
            cfg,
            metastore,
            kms,
            crypto,
            shared_sk_cache: shared_sk,
            shared_ik_cache: shared,
            session_cache: sess_cache,
            metrics_enabled: false,
        }
    }

    /// Opt the factory's sessions in to metrics observation. The actual
    /// timing work (`Instant::now()` in the encrypt/decrypt hot path) only
    /// runs when both this per-factory flag AND the global metrics gate are
    /// enabled. The global gate is owned by the hook-installation API
    /// (`asherah_set_metrics_hook` and the per-binding equivalents) and
    /// flips on/off as hooks come and go — that way a factory that simply
    /// declares "I want to be observable if anyone is listening" doesn't
    /// pay any overhead when nothing is hooked.
    pub fn with_metrics(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }

    /// Approximate count of distinct intermediate-key entries currently
    /// held in the shared IK cache. Returns `0` when the IK cache is
    /// disabled or `shared_intermediate_key_cache` is `false` (per-
    /// session caches aren't aggregated here). The value is racy under
    /// concurrent encrypts; callers should use it for assertion-style
    /// bounds checks only.
    pub fn ik_cache_entry_count(&self) -> usize {
        self.shared_ik_cache
            .as_ref()
            .map(|c| c.entry_count())
            .unwrap_or(0)
    }
    pub fn get_session(&self, id: &str) -> PublicSession<A, K, M> {
        let mut suffix = self.metastore.region_suffix();
        if suffix.as_deref().unwrap_or("").is_empty() {
            suffix = self.cfg.region_suffix.clone();
        }
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
        let invalid_partition = id.is_empty();
        let construct = || {
            let inner = SessionFactory::new(
                self.metastore.clone(),
                self.kms.clone(),
                self.cfg.policy.clone(),
                self.crypto.clone(),
                Arc::new(part),
            )
            .session();
            let sk_cache = self.shared_sk_cache.clone();
            // IK cache: use shared factory cache, create per-session, or NeverCache
            let ik_cache: Arc<dyn KeyCacher> = match &self.shared_ik_cache {
                Some(shared) => shared.clone(),
                None => {
                    if self.cfg.policy.cache_intermediate_keys {
                        let policy = CachePolicy::parse(
                            &self.cfg.policy.intermediate_key_cache_eviction_policy,
                            CachePolicy::Simple,
                        );
                        Arc::new(SimpleKeyCache::new_with_policy(
                            self.cfg.policy.revoke_check_interval_s,
                            self.cfg.policy.intermediate_key_cache_max_size,
                            policy,
                            self.cfg.policy.expire_key_after_s,
                        ))
                    } else {
                        Arc::new(NeverCache)
                    }
                }
            };
            let cached_ik_id = inner.f.partition.intermediate_key_id();
            let cached_ik_prefix = inner.f.partition.ik_validation_prefix();
            let recovery_suffixes: Arc<[String]> =
                Arc::from(self.cfg.recovery_region_suffixes.clone());
            let self_heal = self.cfg.self_heal_recovered_keys;
            PublicSession {
                inner,
                metastore: self.metastore.clone(),
                kms: self.kms.clone(),
                crypto: self.crypto.clone(),
                sk_cache,
                ik_cache,
                metrics_enabled: self.metrics_enabled,
                invalid_partition,
                cached_ik_id,
                cached_ik_prefix,
                recovery_suffixes,
                self_heal,
            }
        };
        if let Some(cache) = &self.session_cache {
            let arc = cache.get_or_create(id, construct);
            // Always go through `clone_for_return` (a manual deref-clone)
            // so the cache keeps its entry. The previous
            // `Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone_for_return())`
            // dropped the cache's entry whenever this thread happened to
            // be the only Arc holder — undermining the bounded
            // session-cache LRU semantics on every contended call.
            // T-finding "Arc::try_unwrap causes the cache to lose the
            // entry on every contended call" in
            // `docs/review-2026-05-05-findings.md`.
            (*arc).clone_for_return()
        } else {
            construct()
        }
    }

    pub fn close(&self) -> anyhow::Result<()> {
        if let Some(c) = &self.session_cache {
            c.close();
        }
        // Surface IK-cache close failures rather than silently dropping them
        // — the caller has no other channel for noticing zeroize/unlock
        // errors. T-finding "PublicFactory::close swallows c.close() errors
        // via drop(...)" in docs/review-2026-05-05-findings.md.
        if let Some(c) = &self.shared_ik_cache {
            c.close()
                .context("PublicFactory::close: failed to close shared IK cache")?;
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
    invalid_partition: bool,
    /// Pre-computed intermediate key id (avoids format! allocation per encrypt)
    cached_ik_id: String,
    /// Pre-computed IK id prefix for suffix validation (avoids format! allocation per decrypt)
    cached_ik_prefix: Option<String>,
    /// Region suffixes to try (in order) when a decrypt would otherwise fail,
    /// before falling back to the empty suffix. Read only on the cold recovery
    /// path; never touched on the encrypt/decrypt hot path. Stored as `Arc<[_]>`
    /// so per-session clones from the session cache are cheap.
    recovery_suffixes: Arc<[String]>,
    /// When true, a successful recovery writes a copy of the recovered key back
    /// under the id/created the row references (best-effort) so future reads
    /// fast-path. Read only on the cold recovery path.
    self_heal: bool,
}

#[allow(clippy::same_name_method)]
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
            invalid_partition: self.invalid_partition,
            cached_ik_id: self.cached_ik_id.clone(),
            cached_ik_prefix: self.cached_ik_prefix.clone(),
            recovery_suffixes: self.recovery_suffixes.clone(),
            self_heal: self.self_heal,
        }
    }

    #[inline(always)]
    fn ensure_valid_partition(&self) -> anyhow::Result<()> {
        if self.invalid_partition {
            return Err(anyhow::anyhow!("partition id cannot be empty"));
        }
        Ok(())
    }

    /// Decrypt-gate predicate: may this session load the IK named by a row?
    /// Accepts the session's exact id, any same-core suffixed id (a different
    /// region's key for the same partition, resolvable from a shared/replicated
    /// metastore), and — for suffixed sessions — the bare unsuffixed core
    /// (data written before/without region suffixing; same partition identity).
    /// All accepted ids share the partition's id core, so this never crosses the
    /// partition/service/product isolation boundary. Hot path: the common exact
    /// match returns immediately.
    #[inline(always)]
    fn ik_id_accepted_by_gate(&self, id: &str) -> bool {
        if id == self.cached_ik_id {
            return true;
        }
        match &self.cached_ik_prefix {
            Some(prefix) => {
                id.starts_with(prefix.as_str())
                    || prefix.strip_suffix('_').is_some_and(|core| id == core)
            }
            None => false,
        }
    }
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
        let ik_id = self.inner.f.partition.intermediate_key_id();
        log::debug!("create_intermediate_key: id={ik_id}");
        let sk_meta = KeyMeta {
            id: self.inner.f.partition.system_key_id(),
            created: 0,
        };
        // Bounded create-or-load retry. Under a tight `expire_key_after_s`
        // (≈ `create_date_precision_s`), a concurrent first-encrypt burst can
        // straddle the expiry boundary: a thread that loses the store race may
        // then load_latest an IK that has *just* expired. Rather than surfacing
        // a spurious "after retry" error, regenerate at the now-current
        // timestamp — time has advanced past the window, so the fresh key is
        // valid and this is simply the next rotation. Converges in <=2 attempts;
        // the bound is a safety net (the `enforce_minimums` precision<=expire
        // clamp guarantees a freshly minted key is not instantly expired).
        const MAX_ATTEMPTS: usize = 5;
        for _ in 0..MAX_ATTEMPTS {
            let sk = self
                .get_or_load_system_key(sk_meta.clone())
                .context("create_intermediate_key: failed to get/load system key")?;
            let ik = generate_key(self.inner.new_key_timestamp())?;
            let enc_ik = ik
                .with_key_func(|ikb| sk.with_key_func(|skb| self.crypto.encrypt(ikb, skb)))
                .context("create_intermediate_key: failed to encrypt IK under SK")??;
            let ekr = EnvelopeKeyRecord {
                id: ik_id.clone(),
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
                .unwrap_or_else(|e| {
                    log::warn!(
                        "create_intermediate_key: store failed for id={ik_id} (will retry load): {e:#}"
                    );
                    false
                });
            if stored {
                return Ok(Arc::new(ik));
            }
            log::debug!(
                "create_intermediate_key: store returned false, loading latest for id={ik_id}"
            );
            // Fallback: assume duplicate/newer IK exists; load latest and return that one.
            if let Some(latest) = self.metastore.load_latest(&ik_id).context(format!(
                "create_intermediate_key: fallback load_latest failed for id={ik_id}"
            ))? {
                if !self.inner.is_envelope_invalid(&latest) {
                    let sk_meta = latest.parent_key_meta.clone().unwrap_or(KeyMeta {
                        id: self.inner.f.partition.system_key_id(),
                        created: 0,
                    });
                    let sk2 = self.get_or_load_system_key(sk_meta)?;
                    let ik2 = self.inner.intermediate_key_from_ekr(&sk2, &latest)?;
                    return Ok(Arc::new(ik2));
                }
                // We lost the store race to an IK that has already expired
                // (tight expiry + precision boundary). Loop to mint a fresh IK
                // at the advanced timestamp.
                log::debug!(
                    "create_intermediate_key: latest IK for id={ik_id} expired during race; regenerating"
                );
            }
        }
        log::error!("create_intermediate_key: failed to store or load IK for id={ik_id}");
        Err(anyhow::anyhow!(
            "failed to create or load intermediate key id={ik_id} after retry"
        ))
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
        log::debug!(
            "load_intermediate_key: id={} created={}",
            meta.id,
            meta.created
        );
        let ekr = self
            .metastore
            .load(&meta.id, meta.created)
            .context(format!(
                "failed to load intermediate key id={} created={}",
                meta.id, meta.created
            ))?
            .ok_or_else(|| {
                log::error!(
                    "intermediate key not found: id={} created={}",
                    meta.id,
                    meta.created
                );
                anyhow::anyhow!(
                    "intermediate key not found: id={} created={}",
                    meta.id,
                    meta.created
                )
            })?;
        let sk_meta = ekr.parent_key_meta.clone().unwrap_or(KeyMeta {
            id: self.inner.f.partition.system_key_id(),
            created: 0,
        });
        let sk = self.get_or_load_system_key(sk_meta)?;
        let ik = self.inner.intermediate_key_from_ekr(&sk, &ekr)?;
        Ok(Arc::new(ik))
    }

    pub fn encrypt(&self, data: &[u8]) -> anyhow::Result<crate::types::DataRowRecord> {
        self.ensure_valid_partition()?;
        // Per-session AND global gate: only call Instant::now() when both
        // are true. Per-session is set at factory construction; the global
        // gate flips on/off when a metrics hook is installed/cleared.
        // Without the global check, every encrypt on a `with_metrics(true)`
        // factory pays Instant::now() (~50ns) even when nothing is hooked.
        let start = if self.metrics_enabled && metrics::is_enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        log::debug!(
            "PublicSession::encrypt: loading IK id={}",
            self.cached_ik_id
        );
        let mut loader = || self.load_latest_or_create_intermediate_key();
        let ik = self
            .ik_cache
            .get_or_load_latest(&self.cached_ik_id, &mut loader)
            .context("encrypt: failed to get or create intermediate key")?;
        let created = now_s();
        // Stack-allocated DRK filled from thread-local ChaCha20Rng (no syscall).
        // Wrapped in a guard that wipes on drop so early returns via ? don't leak key material.
        struct DrkGuard([u8; 32]);
        impl Drop for DrkGuard {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
        let mut drk = DrkGuard([0_u8; 32]);
        crate::aead::fast_random_bytes(&mut drk.0)?;
        // Create DRK LessSafeKey once, use for both data + DRK encryption
        let drk_lsk = crate::aead::make_lsk(&drk.0).context("encrypt: failed to create DRK key")?;
        let enc_data = crate::aead::encrypt_with_lsk(data, &drk_lsk)
            .context("encrypt: failed to encrypt data with DRK")?;
        // Encrypt DRK under IK: use cached LessSafeKey if available (no Enclave::open)
        let enc_drk = if let Some(ik_lsk) = ik.less_safe_key() {
            crate::aead::encrypt_with_lsk(&drk.0, ik_lsk)
                .context("encrypt: failed to encrypt DRK with IK")?
        } else {
            ik.with_key_func(|ikb| self.crypto.encrypt(&drk.0, ikb))
                .context("encrypt: failed to encrypt DRK with IK")??
        };
        drop(drk); // explicit wipe via Drop
        let result = crate::types::DataRowRecord {
            key: Some(EnvelopeKeyRecord {
                id: String::new(),
                created,
                encrypted_key: enc_drk,
                revoked: None,
                parent_key_meta: Some(KeyMeta {
                    id: self.cached_ik_id.clone(),
                    created: ik.created(),
                }),
            }),
            data: enc_data,
        };
        if let Some(start) = start {
            metrics::record_encrypt(start);
        }
        Ok(result)
    }

    // ─── Best-effort cross-region decrypt recovery ──────────────────────────
    //
    // When the normal decrypt path fails — the row's IK id does not match this
    // session's partition, the IK is not found at the recorded (id, created),
    // or the AEAD tag is rejected — we do NOT give up. A row's key chain is
    // self-describing (the IK record names its own parent SK, which the local
    // KMS can unwrap in a properly configured multi-region setup), and AES-GCM
    // authenticates every decrypt, so trying additional candidate keys can
    // never yield wrong plaintext: a wrong key fails the tag. We therefore try
    // the IK under the partition's suffix-independent id core with each
    // configured recovery suffix, the empty suffix, this session's own id, and
    // the row's verbatim id. This recovers data written under a different
    // region's suffix or before region suffixing was toggled — the same
    // misconfiguration family that bit upstream Asherah (godaddy/asherah
    // #1696/#1698). Recovery is treated as an error condition and logged loudly
    // at every step regardless of outcome, because reaching it at all means
    // something upstream is misconfigured and must be fixed.

    /// Build the ordered, deduplicated list of candidate IK ids to try during
    /// recovery. Every candidate shares the partition's id core
    /// (`_IK_{id}_{service}_{product}`), so recovery never crosses the
    /// partition/service/product isolation boundary — only the region suffix
    /// varies.
    fn recovery_candidate_ids(&self, row_id: &str) -> Vec<String> {
        let core = self.inner.f.partition.ik_id_core();
        let mut out: Vec<String> = Vec::with_capacity(self.recovery_suffixes.len() + 3);
        // 1. configured recovery suffixes, in listed order
        for s in self.recovery_suffixes.iter() {
            let cand = format!("{core}_{s}");
            if !out.contains(&cand) {
                out.push(cand);
            }
        }
        // 2. empty suffix (the bare core)
        if !out.contains(&core) {
            out.push(core.clone());
        }
        // 3. this session's own partition id
        if !out.contains(&self.cached_ik_id) {
            out.push(self.cached_ik_id.clone());
        }
        // 4. the row's embedded id verbatim — ONLY when it shares this
        //    partition's id core (bare core or core + "_<suffix>"). This honors
        //    the row's own claim about where its key lives while guaranteeing
        //    recovery never crosses the partition/service/product boundary: a
        //    row referencing a different core is left to fail.
        let row = row_id.to_string();
        let shares_core = row == core
            || row
                .strip_prefix(&core)
                .is_some_and(|rest| rest.starts_with('_'));
        if shares_core && !out.contains(&row) {
            out.push(row);
        }
        out
    }

    /// Extract the region suffix from an IK id relative to this partition's id
    /// core: `""` for the bare core (unsuffixed), or the trailing `<suffix>`.
    /// Returns `None` if `id` does not share the core (shouldn't happen for
    /// recovery candidates, which are core-constrained).
    fn suffix_of(&self, core: &str, id: &str) -> Option<String> {
        if id == core {
            return Some(String::new());
        }
        id.strip_prefix(core)
            .and_then(|rest| rest.strip_prefix('_'))
            .map(str::to_string)
    }

    /// Human-readable classification of a successful recovery, naming exactly
    /// which suffix mismatch was resolved so the operator can fix the root
    /// cause. `via` is "exact" or "load_latest".
    fn recovery_success_detail(&self, found_id: &str, found_created: i64, via: &str) -> String {
        let core = self.inner.f.partition.ik_id_core();
        let expected = self
            .suffix_of(&core, &self.cached_ik_id)
            .unwrap_or_default();
        let found = self.suffix_of(&core, found_id).unwrap_or_default();
        let classification = match (expected.as_str(), found.as_str()) {
            (exp, "") if !exp.is_empty() => format!(
                "found and decrypted with an UNSUFFIXED key (this session expects region suffix '{exp}'). \
                 The row was written before region suffixing was enabled, or during a window with it disabled."
            ),
            (exp, fnd) if !exp.is_empty() && !fnd.is_empty() && exp != fnd => format!(
                "expected the key under region suffix '{exp}' but found the matching key under region suffix '{fnd}' (cross-region data)."
            ),
            ("", fnd) if !fnd.is_empty() => format!(
                "this session is UNSUFFIXED but the matching key is under region suffix '{fnd}'."
            ),
            _ => "resolved a same-partition key (likely a created-timestamp mismatch)".to_string(),
        };
        format!(
            "{classification} Recovered with IK id={found_id} created={found_created} (via {via}). \
             FIX THE MISCONFIGURATION that produced this key mismatch."
        )
    }

    /// Derive an IK from an already-loaded EKR, following the EKR's own parent
    /// SK meta (cross-region safe). Shared by the sync recovery loaders.
    fn ik_from_ekr_for_recovery(&self, ekr: &EnvelopeKeyRecord) -> anyhow::Result<Arc<CryptoKey>> {
        let sk_meta = ekr.parent_key_meta.clone().unwrap_or(KeyMeta {
            id: self.inner.f.partition.system_key_id(),
            created: 0,
        });
        let sk = self.get_or_load_system_key(sk_meta)?;
        let ik = self.inner.intermediate_key_from_ekr(&sk, ekr)?;
        Ok(Arc::new(ik))
    }

    /// Build the self-heal copy: the recovered key's wrapped bytes and parent SK
    /// meta, relabeled to the id/created the row references. The wrapped IK bytes
    /// (and thus the derived key) are identical regardless of the id/created
    /// label, and the AEAD tag already proved this key decrypts the row — so the
    /// copy is provably the correct key for `(pmeta.id, pmeta.created)`.
    fn self_heal_record(pmeta: &KeyMeta, found: &EnvelopeKeyRecord) -> EnvelopeKeyRecord {
        EnvelopeKeyRecord {
            id: pmeta.id.clone(),
            created: pmeta.created,
            encrypted_key: found.encrypted_key.clone(),
            revoked: found.revoked,
            parent_key_meta: found.parent_key_meta.clone(),
        }
    }

    /// Best-effort self-heal: write a copy of the recovered key under the
    /// `(id, created)` the row references so future reads fast-path. Stored
    /// insert-if-absent with the row's `created` (so it can never win key
    /// rotation). A failed or denied write NEVER fails the decrypt — it has
    /// already succeeded. No-op when disabled or when the key already lives at
    /// the row's coordinates.
    fn self_heal_copy(&self, pmeta: &KeyMeta, found_id: &str, found: &EnvelopeKeyRecord) {
        if !self.self_heal || (found_id == pmeta.id && found.created == pmeta.created) {
            return;
        }
        let copy = Self::self_heal_record(pmeta, found);
        match self.metastore.store(&pmeta.id, pmeta.created, &copy) {
            Ok(true) => log::error!(
                "decrypt recovery: SELF-HEAL wrote recovered key copy to id={} created={} (source id={} created={}); future reads will fast-path.",
                pmeta.id, pmeta.created, found_id, found.created
            ),
            Ok(false) => log::debug!(
                "decrypt recovery: self-heal no-op, key already present at id={} created={}",
                pmeta.id, pmeta.created
            ),
            Err(e) => log::warn!(
                "decrypt recovery: self-heal write to id={} created={} failed (decrypt already succeeded): {e:#}",
                pmeta.id, pmeta.created
            ),
        }
    }

    /// Unwrap the DRK with `ik` and decrypt `data`. Returns `Err` (with the DRK
    /// wiped) when the AEAD tag is rejected — that is the success oracle the
    /// recovery loops rely on. Used only on the recovery path; the hot path
    /// keeps its own inline copy.
    fn try_decrypt_with_ik(
        &self,
        ik: &CryptoKey,
        enc_drk: &[u8],
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut drk = if let Some(ik_lsk) = ik.less_safe_key() {
            crate::aead::decrypt_with_lsk(enc_drk, ik_lsk)?
        } else {
            ik.with_key_func(|ikb| self.crypto.decrypt(enc_drk, ikb))??
        };
        let drk_lsk = match crate::aead::make_lsk(&drk) {
            Ok(k) => k,
            Err(e) => {
                drk.zeroize();
                return Err(e);
            }
        };
        let pt = crate::aead::decrypt_with_lsk(data, &drk_lsk);
        drk.zeroize();
        pt
    }

    /// Synchronous best-effort recovery. Returns the recovered plaintext on the
    /// first candidate whose key authenticates, or `None` when every candidate
    /// is exhausted. Logs loudly at `error` level on entry, per attempt, on
    /// success, and on exhaustion.
    fn recover_decrypt(&self, enc_drk: &[u8], data: &[u8], pmeta: &KeyMeta) -> Option<Vec<u8>> {
        let candidates = self.recovery_candidate_ids(&pmeta.id);
        log::error!(
            "decrypt recovery: ENTERING best-effort cross-region recovery for row IK id={} created={} (session partition={}). This indicates a region-suffix/partition misconfiguration and is an ERROR regardless of outcome. Trying {} candidate key id(s).",
            pmeta.id,
            pmeta.created,
            self.cached_ik_id,
            candidates.len()
        );
        // Pass A: exact (candidate id, row's created).
        for id in &candidates {
            log::error!(
                "decrypt recovery: trying candidate IK id={id} created={} (exact)",
                pmeta.created
            );
            match self.metastore.load(id, pmeta.created) {
                Ok(Some(ekr)) => match self.ik_from_ekr_for_recovery(&ekr) {
                    Ok(ik) => match self.try_decrypt_with_ik(&ik, enc_drk, data) {
                        Ok(pt) => {
                            log::error!(
                                "decrypt recovery: SUCCEEDED for row tagged id={} created={} — {}",
                                pmeta.id,
                                pmeta.created,
                                self.recovery_success_detail(id, pmeta.created, "exact")
                            );
                            self.self_heal_copy(pmeta, id, &ekr);
                            metrics::record_decrypt_recovery(true);
                            return Some(pt);
                        }
                        Err(e) => log::error!(
                            "decrypt recovery: candidate IK id={id} created={} loaded but AEAD tag rejected it for this row: {e:#}",
                            pmeta.created
                        ),
                    },
                    Err(e) => log::error!(
                        "decrypt recovery: candidate IK id={id} created={} key derivation failed: {e:#}",
                        pmeta.created
                    ),
                },
                Ok(None) => log::error!(
                    "decrypt recovery: candidate IK id={id} created={} not found in metastore",
                    pmeta.created
                ),
                Err(e) => log::error!(
                    "decrypt recovery: candidate IK id={id} created={} load error: {e:#}",
                    pmeta.created
                ),
            }
        }
        // Pass B: load_latest per candidate (covers rows whose recorded
        // `created` is also wrong, not just the suffix).
        for id in &candidates {
            log::error!("decrypt recovery: trying candidate IK id={id} (load_latest)");
            match self.metastore.load_latest(id) {
                Ok(Some(ekr)) => {
                    let found_created = ekr.created;
                    match self.ik_from_ekr_for_recovery(&ekr) {
                        Ok(ik) => match self.try_decrypt_with_ik(&ik, enc_drk, data) {
                            Ok(pt) => {
                                log::error!(
                                    "decrypt recovery: SUCCEEDED for row tagged id={} created={} — {}",
                                    pmeta.id,
                                    pmeta.created,
                                    self.recovery_success_detail(id, found_created, "load_latest")
                                );
                                self.self_heal_copy(pmeta, id, &ekr);
                                metrics::record_decrypt_recovery(true);
                                return Some(pt);
                            }
                            Err(e) => log::error!(
                                "decrypt recovery: latest IK id={id} created={found_created} AEAD tag rejected it for this row: {e:#}"
                            ),
                        },
                        Err(e) => log::error!(
                            "decrypt recovery: latest IK id={id} created={found_created} key derivation failed: {e:#}"
                        ),
                    }
                }
                Ok(None) => {
                    log::error!(
                        "decrypt recovery: no key found for candidate IK id={id} (load_latest)"
                    )
                }
                Err(e) => {
                    log::error!("decrypt recovery: candidate IK id={id} load_latest error: {e:#}")
                }
            }
        }
        log::error!(
            "decrypt recovery: EXHAUSTED all {} candidate key id(s) for row IK id={} created={}; data is UNRECOVERABLE with the configured recovery suffixes.",
            candidates.len(),
            pmeta.id,
            pmeta.created
        );
        metrics::record_decrypt_recovery(false);
        None
    }

    async fn ik_from_ekr_for_recovery_async(
        &self,
        ekr: &EnvelopeKeyRecord,
    ) -> anyhow::Result<Arc<CryptoKey>>
    where
        A: 'static,
        K: 'static,
        M: 'static,
    {
        let sk_meta = ekr.parent_key_meta.clone().unwrap_or(KeyMeta {
            id: self.inner.f.partition.system_key_id(),
            created: 0,
        });
        let sk = self.get_or_load_system_key_async(sk_meta).await?;
        let ik = self.inner.intermediate_key_from_ekr(&sk, ekr)?;
        Ok(Arc::new(ik))
    }

    /// Async counterpart to [`Self::self_heal_copy`].
    async fn self_heal_copy_async(&self, pmeta: &KeyMeta, found_id: &str, found: &EnvelopeKeyRecord)
    where
        A: 'static,
        K: 'static,
        M: 'static,
    {
        if !self.self_heal || (found_id == pmeta.id && found.created == pmeta.created) {
            return;
        }
        let copy = Self::self_heal_record(pmeta, found);
        match self.metastore.store_async(&pmeta.id, pmeta.created, &copy).await {
            Ok(true) => log::error!(
                "decrypt_async recovery: SELF-HEAL wrote recovered key copy to id={} created={} (source id={} created={}); future reads will fast-path.",
                pmeta.id, pmeta.created, found_id, found.created
            ),
            Ok(false) => log::debug!(
                "decrypt_async recovery: self-heal no-op, key already present at id={} created={}",
                pmeta.id, pmeta.created
            ),
            Err(e) => log::warn!(
                "decrypt_async recovery: self-heal write to id={} created={} failed (decrypt already succeeded): {e:#}",
                pmeta.id, pmeta.created
            ),
        }
    }

    /// Async counterpart to [`Self::recover_decrypt`]. Mirrors the sync logic
    /// using the async metastore methods.
    async fn recover_decrypt_async(
        &self,
        enc_drk: &[u8],
        data: &[u8],
        pmeta: &KeyMeta,
    ) -> Option<Vec<u8>>
    where
        A: 'static,
        K: 'static,
        M: 'static,
    {
        let candidates = self.recovery_candidate_ids(&pmeta.id);
        log::error!(
            "decrypt_async recovery: ENTERING best-effort cross-region recovery for row IK id={} created={} (session partition={}). This indicates a region-suffix/partition misconfiguration and is an ERROR regardless of outcome. Trying {} candidate key id(s).",
            pmeta.id,
            pmeta.created,
            self.cached_ik_id,
            candidates.len()
        );
        for id in &candidates {
            log::error!(
                "decrypt_async recovery: trying candidate IK id={id} created={} (exact)",
                pmeta.created
            );
            match self.metastore.load_async(id, pmeta.created).await {
                Ok(Some(ekr)) => match self.ik_from_ekr_for_recovery_async(&ekr).await {
                    Ok(ik) => match self.try_decrypt_with_ik(&ik, enc_drk, data) {
                        Ok(pt) => {
                            log::error!(
                                "decrypt_async recovery: SUCCEEDED for row tagged id={} created={} — {}",
                                pmeta.id,
                                pmeta.created,
                                self.recovery_success_detail(id, pmeta.created, "exact")
                            );
                            self.self_heal_copy_async(pmeta, id, &ekr).await;
                            metrics::record_decrypt_recovery(true);
                            return Some(pt);
                        }
                        Err(e) => log::error!(
                            "decrypt_async recovery: candidate IK id={id} created={} loaded but AEAD tag rejected it: {e:#}",
                            pmeta.created
                        ),
                    },
                    Err(e) => log::error!(
                        "decrypt_async recovery: candidate IK id={id} created={} key derivation failed: {e:#}",
                        pmeta.created
                    ),
                },
                Ok(None) => log::error!(
                    "decrypt_async recovery: candidate IK id={id} created={} not found in metastore",
                    pmeta.created
                ),
                Err(e) => log::error!(
                    "decrypt_async recovery: candidate IK id={id} created={} load error: {e:#}",
                    pmeta.created
                ),
            }
        }
        for id in &candidates {
            log::error!("decrypt_async recovery: trying candidate IK id={id} (load_latest)");
            match self.metastore.load_latest_async(id).await {
                Ok(Some(ekr)) => {
                    let found_created = ekr.created;
                    match self.ik_from_ekr_for_recovery_async(&ekr).await {
                        Ok(ik) => match self.try_decrypt_with_ik(&ik, enc_drk, data) {
                            Ok(pt) => {
                                log::error!(
                                    "decrypt_async recovery: SUCCEEDED for row tagged id={} created={} — {}",
                                    pmeta.id,
                                    pmeta.created,
                                    self.recovery_success_detail(id, found_created, "load_latest")
                                );
                                self.self_heal_copy_async(pmeta, id, &ekr).await;
                                metrics::record_decrypt_recovery(true);
                                return Some(pt);
                            }
                            Err(e) => log::error!(
                                "decrypt_async recovery: latest IK id={id} created={found_created} AEAD tag rejected it: {e:#}"
                            ),
                        },
                        Err(e) => log::error!(
                            "decrypt_async recovery: candidate IK id={id} (load_latest) key derivation failed: {e:#}"
                        ),
                    }
                }
                Ok(None) => log::error!(
                    "decrypt_async recovery: no key found for candidate IK id={id} (load_latest)"
                ),
                Err(e) => log::error!(
                    "decrypt_async recovery: candidate IK id={id} load_latest error: {e:#}"
                ),
            }
        }
        log::error!(
            "decrypt_async recovery: EXHAUSTED all {} candidate key id(s) for row IK id={} created={}; data is UNRECOVERABLE with the configured recovery suffixes.",
            candidates.len(),
            pmeta.id,
            pmeta.created
        );
        metrics::record_decrypt_recovery(false);
        None
    }

    pub fn decrypt(&self, drr: crate::types::DataRowRecord) -> anyhow::Result<Vec<u8>> {
        self.ensure_valid_partition()?;
        // Per-session AND global gate: only call Instant::now() when both
        // are true. Per-session is set at factory construction; the global
        // gate flips on/off when a metrics hook is installed/cleared.
        // Without the global check, every encrypt on a `with_metrics(true)`
        // factory pays Instant::now() (~50ns) even when nothing is hooked.
        let start = if self.metrics_enabled && metrics::is_enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let key = drr
            .key
            .ok_or_else(|| anyhow::anyhow!("decrypt: DRR missing key envelope"))?;
        let pmeta = key
            .parent_key_meta
            .ok_or_else(|| anyhow::anyhow!("decrypt: DRR key missing parent_key_meta"))?;
        // Fast path: the row's IK id matches this session's partition. Kept
        // inline and unchanged so the hot path pays no extra cost; any failure
        // here (validation reject, IK-not-found, or AEAD tag failure) drops to
        // the best-effort recovery path below.
        let fast: anyhow::Result<Vec<u8>> = (|| {
            if !self.ik_id_accepted_by_gate(&pmeta.id) {
                return Err(anyhow::anyhow!(
                    "decrypt: invalid IK id={} for partition (session partition expected {})",
                    pmeta.id,
                    self.cached_ik_id
                ));
            }
            log::debug!(
                "PublicSession::decrypt: loading IK id={} created={}",
                pmeta.id,
                pmeta.created
            );
            let mut loader = || self.load_intermediate_key(pmeta.clone());
            let ik = self
                .ik_cache
                .get_or_load(&pmeta, &mut loader)
                .with_context(|| {
                    format!(
                        "decrypt: failed to load IK id={} created={}",
                        pmeta.id, pmeta.created
                    )
                })?;
            // Decrypt DRK under IK: use cached LessSafeKey if available (no Enclave::open)
            let mut drk = if let Some(ik_lsk) = ik.less_safe_key() {
                crate::aead::decrypt_with_lsk(&key.encrypted_key, ik_lsk)
                    .context("decrypt: failed to decrypt DRK with IK")?
            } else {
                ik.with_key_func(|ikb| self.crypto.decrypt(&key.encrypted_key, ikb))
                    .context("decrypt: failed to decrypt DRK with IK")??
            };
            // Create DRK LessSafeKey once for data decryption
            let drk_lsk =
                crate::aead::make_lsk(&drk).context("decrypt: failed to create DRK key")?;
            let pt = crate::aead::decrypt_with_lsk(&drr.data, &drk_lsk)
                .context("decrypt: failed to decrypt data with DRK");
            drk.zeroize();
            pt
        })();
        let pt = match fast {
            Ok(pt) => pt,
            Err(fast_err) => {
                log::error!("decrypt: normal path failed, attempting recovery: {fast_err:#}");
                match self.recover_decrypt(&key.encrypted_key, &drr.data, &pmeta) {
                    Some(pt) => pt,
                    None => return Err(fast_err).context(
                        "decrypt failed and best-effort cross-region recovery found no usable key",
                    ),
                }
            }
        };
        if let Some(start) = start {
            metrics::record_decrypt(start);
        }
        Ok(pt)
    }
    pub fn store<T: crate::traits::Storer>(
        &self,
        payload: &[u8],
        storer: &T,
    ) -> anyhow::Result<serde_json::Value> {
        self.ensure_valid_partition()?;
        self.inner.store(payload, storer)
    }
    pub fn load<T: crate::traits::Loader>(
        &self,
        key: &serde_json::Value,
        loader: &T,
    ) -> anyhow::Result<Vec<u8>> {
        self.ensure_valid_partition()?;
        self.inner.load(key, loader)
    }
    pub fn close(&self) -> anyhow::Result<()> {
        if !self.inner.f.policy.shared_intermediate_key_cache {
            drop(self.ik_cache.close());
        }
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
        let drr = loader.load_ctx(ctx, key)?.ok_or_else(|| {
            anyhow::anyhow!("record not found in persistence store for the given key")
        })?;
        self.decrypt_ctx(ctx, drr)
    }
}

// ── Async methods for PublicSession ──────────────────────────────────
// These use async metastore/KMS methods and the cache check+insert pattern
// so they never need spawn_blocking or block_on.
#[allow(clippy::same_name_method, clippy::multiple_inherent_impl)]
impl<
        A: AEAD + Clone + 'static,
        K: KeyManagementService + Clone + 'static,
        M: Metastore + Clone + 'static,
    > PublicSession<A, K, M>
{
    async fn get_or_load_system_key_async(&self, meta: KeyMeta) -> anyhow::Result<Arc<CryptoKey>> {
        // SK load/create calls sync metastore methods which may internally call
        // block_on (e.g. the Postgres crate). Use cache check + the tokio
        // blocking pool for the loader to avoid panicking from a tokio
        // runtime context. The previous implementation spawned a fresh
        // OS thread per call (`std::thread::spawn`) which is unbounded and
        // can exhaust the process's thread quota under load —
        // `tokio::task::spawn_blocking` uses a bounded pool (default 512)
        // and applies backpressure via the JoinHandle. T-finding "Async
        // SK loaders use std::thread::spawn per call" in
        // `docs/review-2026-05-05-findings.md`.
        if meta.created == 0 {
            let id = self.inner.f.partition.system_key_id();
            match self.sk_cache.check_latest(&id) {
                CacheCheck::Hit(v) | CacheCheck::StaleOther(v) => Ok(v),
                CacheCheck::StaleReload(stale) => {
                    let inner = self.inner.f.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        let session = Session { f: inner };
                        session.load_latest_or_create_system_key().map(Arc::new)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("SK load task failed: {e}"))?;
                    match result {
                        Ok(key) => {
                            self.sk_cache.insert_latest_key(&id, key.clone());
                            Ok(key)
                        }
                        Err(_) => Ok(stale),
                    }
                }
                CacheCheck::Miss => {
                    let inner = self.inner.f.clone();
                    let key = tokio::task::spawn_blocking(move || {
                        let session = Session { f: inner };
                        session.load_latest_or_create_system_key().map(Arc::new)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("SK load task failed: {e}"))??;
                    self.sk_cache.insert_latest_key(&id, key.clone());
                    Ok(key)
                }
            }
        } else {
            match self.sk_cache.check_meta(&meta) {
                CacheCheck::Hit(v) | CacheCheck::StaleOther(v) | CacheCheck::StaleReload(v) => {
                    Ok(v)
                }
                CacheCheck::Miss => {
                    let inner = self.inner.f.clone();
                    let meta_clone = meta.clone();
                    let key = tokio::task::spawn_blocking(move || {
                        let session = Session { f: inner };
                        session.load_system_key(meta_clone).map(Arc::new)
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!("SK load task failed: {e}"))??;
                    self.sk_cache.insert_meta_key(&meta, key.clone());
                    Ok(key)
                }
            }
        }
    }

    async fn load_intermediate_key_async(&self, meta: KeyMeta) -> anyhow::Result<Arc<CryptoKey>> {
        log::debug!(
            "load_intermediate_key_async: id={} created={}",
            meta.id,
            meta.created
        );
        let ekr = self
            .metastore
            .load_async(&meta.id, meta.created)
            .await
            .context(format!(
                "failed to load intermediate key id={} created={}",
                meta.id, meta.created
            ))?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "intermediate key not found: id={} created={}",
                    meta.id,
                    meta.created
                )
            })?;
        let sk_meta = ekr.parent_key_meta.clone().unwrap_or(KeyMeta {
            id: self.inner.f.partition.system_key_id(),
            created: 0,
        });
        let sk = self.get_or_load_system_key_async(sk_meta).await?;
        let ik = self.inner.intermediate_key_from_ekr(&sk, &ekr)?;
        Ok(Arc::new(ik))
    }

    async fn load_latest_or_create_intermediate_key_async(&self) -> anyhow::Result<Arc<CryptoKey>> {
        if let Some(ekr) = self
            .metastore
            .load_latest_async(&self.inner.f.partition.intermediate_key_id())
            .await?
        {
            if !self.inner.is_envelope_invalid(&ekr) {
                let sk_meta = ekr.parent_key_meta.clone().unwrap_or(KeyMeta {
                    id: self.inner.f.partition.system_key_id(),
                    created: 0,
                });
                let sk = self.get_or_load_system_key_async(sk_meta).await?;
                let ik = self.inner.intermediate_key_from_ekr(&sk, &ekr)?;
                return Ok(Arc::new(ik));
            }
        }
        self.create_intermediate_key_async().await
    }

    async fn create_intermediate_key_async(&self) -> anyhow::Result<Arc<CryptoKey>> {
        let ik_id = self.inner.f.partition.intermediate_key_id();
        log::debug!("create_intermediate_key_async: id={ik_id}");
        let sk_meta = KeyMeta {
            id: self.inner.f.partition.system_key_id(),
            created: 0,
        };
        // Bounded create-or-load retry — see `create_intermediate_key` (sync)
        // for the boundary-race rationale. Regenerate at the advanced timestamp
        // when we lose the store race to an IK that has already expired.
        const MAX_ATTEMPTS: usize = 5;
        for _ in 0..MAX_ATTEMPTS {
            let sk = self
                .get_or_load_system_key_async(sk_meta.clone())
                .await
                .context("create_intermediate_key_async: failed to get/load system key")?;
            let ik = generate_key(self.inner.new_key_timestamp())?;
            let enc_ik = ik
                .with_key_func(|ikb| sk.with_key_func(|skb| self.crypto.encrypt(ikb, skb)))
                .context("create_intermediate_key_async: failed to encrypt IK under SK")??;
            let ekr = EnvelopeKeyRecord {
                id: ik_id.clone(),
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
                .store_async(&ekr.id, ekr.created, &ekr)
                .await
                .unwrap_or_else(|e| {
                    log::warn!("create_intermediate_key_async: store failed for id={ik_id}: {e:#}");
                    false
                });
            if stored {
                return Ok(Arc::new(ik));
            }
            log::debug!(
                "create_intermediate_key_async: store returned false, loading latest for id={ik_id}"
            );
            if let Some(latest) =
                self.metastore
                    .load_latest_async(&ik_id)
                    .await
                    .context(format!(
                        "create_intermediate_key_async: fallback load_latest failed for id={ik_id}"
                    ))?
            {
                if !self.inner.is_envelope_invalid(&latest) {
                    let sk_meta = latest.parent_key_meta.clone().unwrap_or(KeyMeta {
                        id: self.inner.f.partition.system_key_id(),
                        created: 0,
                    });
                    let sk2 = self.get_or_load_system_key_async(sk_meta).await?;
                    let ik2 = self.inner.intermediate_key_from_ekr(&sk2, &latest)?;
                    return Ok(Arc::new(ik2));
                }
                log::debug!(
                    "create_intermediate_key_async: latest IK for id={ik_id} expired during race; regenerating"
                );
            }
        }
        Err(anyhow::anyhow!(
            "failed to create or load intermediate key id={ik_id} after retry"
        ))
    }

    /// Async encrypt — uses async metastore methods, no spawn_blocking needed.
    pub async fn encrypt_async(&self, data: &[u8]) -> anyhow::Result<crate::types::DataRowRecord> {
        self.ensure_valid_partition()?;
        // Per-session AND global gate: only call Instant::now() when both
        // are true. Per-session is set at factory construction; the global
        // gate flips on/off when a metrics hook is installed/cleared.
        // Without the global check, every encrypt on a `with_metrics(true)`
        // factory pays Instant::now() (~50ns) even when nothing is hooked.
        let start = if self.metrics_enabled && metrics::is_enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        log::debug!(
            "PublicSession::encrypt_async: loading IK id={}",
            self.cached_ik_id
        );
        let ik = match self.ik_cache.check_latest(&self.cached_ik_id) {
            CacheCheck::Hit(v) | CacheCheck::StaleOther(v) => v,
            CacheCheck::StaleReload(stale) => {
                match self.load_latest_or_create_intermediate_key_async().await {
                    Ok(new) => {
                        self.ik_cache
                            .insert_latest_key(&self.cached_ik_id, new.clone());
                        new
                    }
                    Err(_) => stale,
                }
            }
            CacheCheck::Miss => {
                let v = self
                    .load_latest_or_create_intermediate_key_async()
                    .await
                    .context("encrypt_async: failed to get or create intermediate key")?;
                self.ik_cache
                    .insert_latest_key(&self.cached_ik_id, v.clone());
                v
            }
        };
        // DRK and encrypt — all CPU, no async needed
        let created = now_s();
        struct DrkGuard([u8; 32]);
        impl Drop for DrkGuard {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
        let mut drk = DrkGuard([0_u8; 32]);
        crate::aead::fast_random_bytes(&mut drk.0)?;
        let drk_lsk =
            crate::aead::make_lsk(&drk.0).context("encrypt_async: failed to create DRK key")?;
        let enc_data = crate::aead::encrypt_with_lsk(data, &drk_lsk)
            .context("encrypt_async: failed to encrypt data with DRK")?;
        let enc_drk = if let Some(ik_lsk) = ik.less_safe_key() {
            crate::aead::encrypt_with_lsk(&drk.0, ik_lsk)
                .context("encrypt_async: failed to encrypt DRK with IK")?
        } else {
            ik.with_key_func(|ikb| self.crypto.encrypt(&drk.0, ikb))
                .context("encrypt_async: failed to encrypt DRK with IK")??
        };
        drop(drk);
        let result = crate::types::DataRowRecord {
            key: Some(EnvelopeKeyRecord {
                id: String::new(),
                created,
                encrypted_key: enc_drk,
                revoked: None,
                parent_key_meta: Some(KeyMeta {
                    id: self.cached_ik_id.clone(),
                    created: ik.created(),
                }),
            }),
            data: enc_data,
        };
        if let Some(start) = start {
            metrics::record_encrypt(start);
        }
        Ok(result)
    }

    /// Async decrypt — uses async metastore methods, no spawn_blocking needed.
    pub async fn decrypt_async(&self, drr: crate::types::DataRowRecord) -> anyhow::Result<Vec<u8>> {
        self.ensure_valid_partition()?;
        // Per-session AND global gate: only call Instant::now() when both
        // are true. Per-session is set at factory construction; the global
        // gate flips on/off when a metrics hook is installed/cleared.
        // Without the global check, every encrypt on a `with_metrics(true)`
        // factory pays Instant::now() (~50ns) even when nothing is hooked.
        let start = if self.metrics_enabled && metrics::is_enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let key = drr
            .key
            .ok_or_else(|| anyhow::anyhow!("decrypt_async: DRR missing key envelope"))?;
        let pmeta = key
            .parent_key_meta
            .ok_or_else(|| anyhow::anyhow!("decrypt_async: DRR key missing parent_key_meta"))?;
        // Fast path (see sync `decrypt` for rationale). Any failure drops to the
        // best-effort recovery path below.
        let fast: anyhow::Result<Vec<u8>> = async {
            if !self.ik_id_accepted_by_gate(&pmeta.id) {
                return Err(anyhow::anyhow!(
                    "decrypt_async: invalid IK id={} for partition (session partition expected {})",
                    pmeta.id,
                    self.cached_ik_id
                ));
            }
            log::debug!(
                "PublicSession::decrypt_async: loading IK id={} created={}",
                pmeta.id,
                pmeta.created
            );
            let ik = match self.ik_cache.check_meta(&pmeta) {
                CacheCheck::Hit(v) | CacheCheck::StaleOther(v) | CacheCheck::StaleReload(v) => v,
                CacheCheck::Miss => {
                    let v = self
                        .load_intermediate_key_async(pmeta.clone())
                        .await
                        .with_context(|| {
                            format!(
                                "decrypt_async: failed to load IK id={} created={}",
                                pmeta.id, pmeta.created
                            )
                        })?;
                    self.ik_cache.insert_meta_key(&pmeta, v.clone());
                    v
                }
            };
            // Decrypt DRK under IK, then decrypt data — all CPU
            let mut drk = if let Some(ik_lsk) = ik.less_safe_key() {
                crate::aead::decrypt_with_lsk(&key.encrypted_key, ik_lsk)
                    .context("decrypt_async: failed to decrypt DRK with IK")?
            } else {
                ik.with_key_func(|ikb| self.crypto.decrypt(&key.encrypted_key, ikb))
                    .context("decrypt_async: failed to decrypt DRK with IK")??
            };
            let drk_lsk =
                crate::aead::make_lsk(&drk).context("decrypt_async: failed to create DRK key")?;
            let pt = crate::aead::decrypt_with_lsk(&drr.data, &drk_lsk)
                .context("decrypt_async: failed to decrypt data with DRK");
            drk.zeroize();
            pt
        }
        .await;
        let pt = match fast {
            Ok(pt) => pt,
            Err(fast_err) => {
                log::error!("decrypt_async: normal path failed, attempting recovery: {fast_err:#}");
                match self
                    .recover_decrypt_async(&key.encrypted_key, &drr.data, &pmeta)
                    .await
                {
                    Some(pt) => pt,
                    None => return Err(fast_err).context(
                        "decrypt failed and best-effort cross-region recovery found no usable key",
                    ),
                }
            }
        };
        if let Some(start) = start {
            metrics::record_decrypt(start);
        }
        Ok(pt)
    }

    /// Async counterpart to [`Self::store`]: encrypt `payload` via
    /// [`Self::encrypt_async`] (async metastore/KMS) and hand the resulting
    /// [`crate::types::DataRowRecord`] to an async [`crate::traits::StorerAsync`].
    /// Nothing blocks the executor.
    pub async fn store_async<T: crate::traits::StorerAsync>(
        &self,
        payload: &[u8],
        storer: &T,
    ) -> anyhow::Result<serde_json::Value> {
        self.ensure_valid_partition()?;
        // Record the store-wrapper timing, mirroring the sync `Session::store`
        // path so the async path has the same observability.
        let start = if metrics::is_enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let drr = self.encrypt_async(payload).await?;
        let res = storer.store_async(&drr).await;
        if let Some(start) = start {
            metrics::record_store(start);
        }
        res
    }

    /// Async counterpart to [`Self::load`]: fetch the record via an async
    /// [`crate::traits::LoaderAsync`], then decrypt it with
    /// [`Self::decrypt_async`].
    pub async fn load_async<T: crate::traits::LoaderAsync>(
        &self,
        key: &serde_json::Value,
        loader: &T,
    ) -> anyhow::Result<Vec<u8>> {
        self.ensure_valid_partition()?;
        let start = if metrics::is_enabled() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        let drr = loader.load_async(key).await?.ok_or_else(|| {
            anyhow::anyhow!("record not found in persistence store for the given key")
        })?;
        let res = self.decrypt_async(drr).await;
        if let Some(start) = start {
            metrics::record_load(start);
        }
        res
    }

    /// Async counterpart to [`Self::store_ctx`]. The context is an unused
    /// placeholder that mirrors Go's signatures.
    pub async fn store_ctx_async<T: crate::traits::StorerCtxAsync>(
        &self,
        ctx: &(),
        payload: &[u8],
        storer: &T,
    ) -> anyhow::Result<serde_json::Value> {
        let drr = self.encrypt_async(payload).await?;
        storer.store_ctx_async(ctx, &drr).await
    }

    /// Async counterpart to [`Self::load_ctx`].
    pub async fn load_ctx_async<T: crate::traits::LoaderCtxAsync>(
        &self,
        ctx: &(),
        key: &serde_json::Value,
        loader: &T,
    ) -> anyhow::Result<Vec<u8>> {
        let drr = loader.load_ctx_async(ctx, key).await?.ok_or_else(|| {
            anyhow::anyhow!("record not found in persistence store for the given key")
        })?;
        self.decrypt_async(drr).await
    }
}
