#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Error injection tests using FailableMetastore and FailableKms.
//!
//! These test doubles wrap real implementations and can be configured to fail
//! on specific operations, enabling coverage of error paths in session.rs that
//! are unreachable with well-behaved backends.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use asherah::aead::AES256GCM;
use asherah::kms::StaticKMS;
use asherah::metastore::InMemoryMetastore;
use asherah::traits::{KeyManagementService, Metastore, AEAD};
use asherah::types::{DataRowRecord, EnvelopeKeyRecord, KeyMeta};

// ──────────────────────────── FailableMetastore ────────────────────────────

/// A metastore wrapper that can be told to fail on load, load_latest, or store.
#[derive(Clone, Debug)]
struct FailableMetastore {
    inner: InMemoryMetastore,
    fail_load: Arc<AtomicBool>,
    fail_load_latest: Arc<AtomicBool>,
    fail_store: Arc<AtomicBool>,
    /// When true, load() returns Ok(None) instead of Err
    load_returns_none: Arc<AtomicBool>,
    /// When true, load_latest() returns Ok(None) instead of Err
    load_latest_returns_none: Arc<AtomicBool>,
    /// When true, store() returns Ok(false) without storing
    store_returns_false: Arc<AtomicBool>,
    /// Counts store calls (used to fail only on Nth call)
    store_call_count: Arc<AtomicU64>,
    /// If non-zero, only fail store when call_count == this value
    fail_store_on_call: Arc<AtomicU64>,
}

impl FailableMetastore {
    fn new() -> Self {
        Self {
            inner: InMemoryMetastore::new(),
            fail_load: Arc::new(AtomicBool::new(false)),
            fail_load_latest: Arc::new(AtomicBool::new(false)),
            fail_store: Arc::new(AtomicBool::new(false)),
            load_returns_none: Arc::new(AtomicBool::new(false)),
            load_latest_returns_none: Arc::new(AtomicBool::new(false)),
            store_returns_false: Arc::new(AtomicBool::new(false)),
            store_call_count: Arc::new(AtomicU64::new(0)),
            fail_store_on_call: Arc::new(AtomicU64::new(0)),
        }
    }

    fn set_fail_load(&self, fail: bool) {
        self.fail_load.store(fail, Ordering::SeqCst);
    }

    fn set_load_returns_none(&self, yes: bool) {
        self.load_returns_none.store(yes, Ordering::SeqCst);
    }

    fn set_fail_load_latest(&self, fail: bool) {
        self.fail_load_latest.store(fail, Ordering::SeqCst);
    }

    fn set_load_latest_returns_none(&self, yes: bool) {
        self.load_latest_returns_none.store(yes, Ordering::SeqCst);
    }

    fn set_fail_store(&self, fail: bool) {
        self.fail_store.store(fail, Ordering::SeqCst);
    }

    /// When true, store() returns Ok(false) without storing (simulates lost race).
    fn set_store_returns_false(&self, yes: bool) {
        self.store_returns_false.store(yes, Ordering::SeqCst);
    }

    /// Fail store only on the Nth call (1-indexed). 0 = disabled.
    fn set_fail_store_on_call(&self, n: u64) {
        self.fail_store_on_call.store(n, Ordering::SeqCst);
    }

    fn reset_store_count(&self) {
        self.store_call_count.store(0, Ordering::SeqCst);
    }
}

impl Metastore for FailableMetastore {
    fn load(&self, id: &str, created: i64) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        if self.load_returns_none.load(Ordering::SeqCst) {
            return Ok(None);
        }
        if self.fail_load.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("injected load failure"));
        }
        self.inner.load(id, created)
    }

    fn load_latest(&self, id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
        if self.load_latest_returns_none.load(Ordering::SeqCst) {
            return Ok(None);
        }
        if self.fail_load_latest.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("injected load_latest failure"));
        }
        self.inner.load_latest(id)
    }

    fn store(
        &self,
        id: &str,
        created: i64,
        ekr: &EnvelopeKeyRecord,
    ) -> Result<bool, anyhow::Error> {
        let count = self.store_call_count.fetch_add(1, Ordering::SeqCst) + 1;
        let fail_on = self.fail_store_on_call.load(Ordering::SeqCst);
        if fail_on > 0 && count == fail_on {
            return Err(anyhow::anyhow!("injected store failure on call {count}"));
        }
        if self.fail_store.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("injected store failure"));
        }
        if self.store_returns_false.load(Ordering::SeqCst) {
            return Ok(false);
        }
        self.inner.store(id, created, ekr)
    }

    fn region_suffix(&self) -> Option<String> {
        None
    }
}

// ──────────────────────────── FailableKms ────────────────────────────

/// A KMS wrapper that can be told to fail on decrypt_key.
#[derive(Clone)]
struct FailableKms<A: AEAD + Send + Sync + 'static> {
    inner: StaticKMS<A>,
    fail_decrypt: Arc<AtomicBool>,
    fail_encrypt: Arc<AtomicBool>,
}

impl<A: AEAD + Send + Sync + 'static> FailableKms<A> {
    fn new(aead: Arc<A>, master_key: Vec<u8>) -> anyhow::Result<Self> {
        Ok(Self {
            inner: StaticKMS::new(aead, master_key)?,
            fail_decrypt: Arc::new(AtomicBool::new(false)),
            fail_encrypt: Arc::new(AtomicBool::new(false)),
        })
    }

    fn set_fail_decrypt(&self, fail: bool) {
        self.fail_decrypt.store(fail, Ordering::SeqCst);
    }

    #[allow(dead_code)]
    fn set_fail_encrypt(&self, fail: bool) {
        self.fail_encrypt.store(fail, Ordering::SeqCst);
    }
}

impl<A: AEAD + Send + Sync + 'static> KeyManagementService for FailableKms<A> {
    fn encrypt_key(&self, ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        if self.fail_encrypt.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("injected encrypt_key failure"));
        }
        self.inner.encrypt_key(ctx, key_bytes)
    }

    fn decrypt_key(&self, ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        if self.fail_decrypt.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("injected decrypt_key failure"));
        }
        self.inner.decrypt_key(ctx, blob)
    }
}

// ──────────────────────────── Helpers ────────────────────────────

fn make_crypto() -> Arc<AES256GCM> {
    Arc::new(AES256GCM::new())
}

fn make_factory(
    metastore: Arc<FailableMetastore>,
    kms: Arc<FailableKms<AES256GCM>>,
) -> asherah::session::PublicFactory<AES256GCM, FailableKms<AES256GCM>, FailableMetastore> {
    let crypto = make_crypto();
    // Disable all caching so tests hit the metastore/KMS on every operation.
    // NoCache via PolicyOption is honored from the programmatic API.
    let cfg = asherah::Config::new("err-svc", "err-prod")
        .with_policy_options(&[asherah::policy::PolicyOption::NoCache]);
    asherah::api::new_session_factory(cfg, metastore, kms, crypto)
}

fn default_kms() -> Arc<FailableKms<AES256GCM>> {
    Arc::new(FailableKms::new(make_crypto(), vec![0xAB_u8; 32]).unwrap())
}

// ──────────────────────────── Error Path Tests ────────────────────────────

// Path 1: load_system_key() → metastore.load() returns None → "system key not found"
//
// During decrypt, the session loads the SK by (id, created). If the metastore
// returns None for that exact key, it should fail with "system key not found".

#[test]
fn decrypt_fails_when_system_key_not_found() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms.clone(), kms);
    let session = factory.get_session("p1");

    // Encrypt successfully (creates SK and IK in metastore)
    let drr = session.encrypt(b"test data").unwrap();

    // Now make load() return None for all keys (simulating SK missing)
    ms.set_load_returns_none(true);

    // Decrypt should fail because it can't find the SK
    let err = session.decrypt(drr).unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("not found") || msg.contains("missing") || msg.contains("failed to load"),
        "expected 'not found' error, got: {msg}"
    );
}

// Path 2: decrypt() → metastore.load() returns None for IK → "ik not found" / "ik missing"
//
// During decrypt, the session loads the IK by (id, created). If only the IK
// load returns None (SK still accessible), it should fail with IK not found.

#[test]
fn decrypt_fails_when_intermediate_key_not_found() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms.clone(), kms);
    let session = factory.get_session("p2");

    // Encrypt successfully
    let drr = session.encrypt(b"ik missing test").unwrap();

    // Extract the IK metadata from the DRR
    let ik_meta = drr.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    let ik_id = &ik_meta.id;
    let ik_created = ik_meta.created;

    // Verify the IK exists in metastore before we remove it
    assert!(
        ms.inner.load(ik_id, ik_created).unwrap().is_some(),
        "IK should exist"
    );

    // Now make load() return None — this affects both SK and IK loads.
    // But we specifically want to test IK-not-found. The IK load happens first
    // in PublicSession::decrypt, so the error should mention IK.
    ms.set_load_returns_none(true);

    let err = session.decrypt(drr).unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("missing") || msg.contains("not found") || msg.contains("failed to load"),
        "expected IK missing error, got: {msg}"
    );
}

// Path 3: try_store_system_key() → metastore.store() returns Err → (false, None)
//
// When creating a new SK, if metastore.store() fails, try_store_system_key
// returns (false, None). Then load_latest_or_create_system_key falls through
// to must_load_latest. If that also fails, the overall operation errors.

#[test]
fn encrypt_fails_when_store_and_load_latest_both_fail() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms.clone(), kms);
    let session = factory.get_session("p3");

    // Make store always fail — this prevents creating any keys
    ms.set_fail_store(true);
    // Also make load_latest return None — so fallback also fails
    ms.set_load_latest_returns_none(true);

    let err = session.encrypt(b"should fail").unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("not found")
            || msg.contains("error loading")
            || msg.contains("failed to get or create"),
        "expected fallback failure, got: {msg}"
    );
}

// Path 4: load_latest_or_create_system_key() → store fails → falls back to load_latest
//
// When store fails but load_latest succeeds (another process stored the SK),
// the system should recover by loading the existing SK.

#[test]
fn encrypt_recovers_when_store_fails_but_load_latest_succeeds() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms.clone(), kms);

    // Pre-populate: encrypt to create SK and IK in metastore
    let session = factory.get_session("p4s");
    let drr_seed = session.encrypt(b"seed").unwrap();

    // Now make store fail but load_latest still works.
    // When encrypt tries to create a new IK, store fails. But
    // create_intermediate_key falls back to load_latest and finds
    // the existing valid IK.
    ms.set_fail_store(true);

    let session_retry = factory.get_session("p4s");
    let result = session_retry.encrypt(b"recovery payload");
    assert!(
        result.is_ok(),
        "should recover via load_latest: {:?}",
        result.err()
    );

    // Verify decryption of the original data still works
    ms.set_fail_store(false);
    let pt = session_retry.decrypt(drr_seed).unwrap();
    assert_eq!(pt, b"seed");
}

// Path 5: system_key_from_ekr() → KMS decrypt_key failure
//
// When loading an existing SK, if KMS.decrypt_key fails, the session should
// return an error. This tests the path at line 111.

#[test]
fn decrypt_fails_when_kms_decrypt_key_fails() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = Arc::new(FailableKms::new(make_crypto(), vec![0xCD_u8; 32]).unwrap());
    let factory = make_factory(ms.clone(), kms.clone());
    let session = factory.get_session("p5");

    // Encrypt successfully
    let drr = session.encrypt(b"kms fail test").unwrap();

    // Now make KMS decrypt fail
    kms.set_fail_decrypt(true);

    // Decrypt should fail because it can't decrypt the SK
    let err = session.decrypt(drr).unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("injected decrypt_key failure"),
        "expected KMS decrypt failure, got: {msg}"
    );
}

// ──────────────────────────── Additional error path tests ────────────────────────────

#[test]
fn encrypt_fails_when_kms_encrypt_key_fails() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = Arc::new(FailableKms::new(make_crypto(), vec![0xEF_u8; 32]).unwrap());
    let factory = make_factory(ms.clone(), kms.clone());

    // Make KMS encrypt fail — cannot create SK
    kms.set_fail_encrypt(true);

    let session = factory.get_session("p6");
    let err = session.encrypt(b"should fail").unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("injected encrypt_key failure"),
        "expected KMS encrypt failure, got: {msg}"
    );
}

#[test]
fn decrypt_fails_when_metastore_load_errors() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms.clone(), kms);
    let session = factory.get_session("p7");

    let drr = session.encrypt(b"load error test").unwrap();

    // Make load return Err (not None)
    ms.set_fail_load(true);

    let err = session.decrypt(drr).unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("injected load failure"),
        "expected injected load failure, got: {msg}"
    );
}

#[test]
fn encrypt_fails_when_metastore_load_latest_errors() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms.clone(), kms);
    let session = factory.get_session("p8");

    // Make load_latest fail — encrypt can't find or create IK
    ms.set_fail_load_latest(true);

    let err = session.encrypt(b"should fail").unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("injected load_latest failure"),
        "expected load_latest failure, got: {msg}"
    );
}

#[test]
fn encrypt_succeeds_after_transient_store_failure() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms.clone(), kms);
    let session = factory.get_session("p9");

    // First encrypt: succeed (populates metastore)
    let drr1 = session.encrypt(b"first").unwrap();

    // Make store fail temporarily
    ms.set_fail_store(true);

    // Second encrypt: should still work because IK exists and is valid
    let drr2 = session.encrypt(b"second").unwrap();

    // Restore store
    ms.set_fail_store(false);

    // Both should decrypt fine
    let pt1 = session.decrypt(drr1).unwrap();
    let pt2 = session.decrypt(drr2).unwrap();
    assert_eq!(pt1, b"first");
    assert_eq!(pt2, b"second");
}

#[test]
fn decrypt_missing_key_field_fails() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms, kms);
    let session = factory.get_session("p10");

    let drr = DataRowRecord {
        key: None,
        data: vec![1, 2, 3],
    };

    let err = session.decrypt(drr).unwrap_err();
    assert!(
        err.to_string().contains("missing key"),
        "expected 'missing key', got: {}",
        err
    );
}

#[test]
fn decrypt_missing_parent_key_meta_fails() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms, kms);
    let session = factory.get_session("p11");

    let drr = DataRowRecord {
        key: Some(EnvelopeKeyRecord {
            id: String::new(),
            created: 1,
            encrypted_key: vec![1, 2, 3],
            revoked: None,
            parent_key_meta: None,
        }),
        data: vec![1, 2, 3],
    };

    let err = session.decrypt(drr).unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("missing parent") || msg.contains("parent_key_meta"),
        "expected 'missing parent key', got: {msg}",
    );
}

#[test]
fn decrypt_invalid_ik_id_fails() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms, kms);
    let session = factory.get_session("p12");

    let drr = DataRowRecord {
        key: Some(EnvelopeKeyRecord {
            id: String::new(),
            created: 1,
            encrypted_key: vec![1, 2, 3],
            revoked: None,
            parent_key_meta: Some(KeyMeta {
                id: "_IK_wrong_partition_svc_prod".into(),
                created: 1,
            }),
        }),
        data: vec![1, 2, 3],
    };

    let err = session.decrypt(drr).unwrap_err();
    assert!(
        err.to_string().contains("invalid IK id"),
        "expected 'invalid IK id', got: {}",
        err
    );
}

#[test]
fn empty_partition_id_fails() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms, kms);
    let session = factory.get_session(""); // empty partition

    let err = session.encrypt(b"should fail").unwrap_err();
    assert!(
        err.to_string().contains("partition id cannot be empty"),
        "expected partition error, got: {}",
        err
    );
}

// Path: store fails on IK creation → fallback to load_latest in create_intermediate_key
#[test]
fn create_ik_store_fails_falls_back_to_load_latest() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms.clone(), kms);

    // First, successfully create keys
    let session = factory.get_session("p13");
    let drr = session.encrypt(b"pre-populate").unwrap();

    // Now fail only on the 3rd store call (IK store for second encrypt).
    // Calls 1 and 2 were SK store and IK store from the first encrypt.
    // The next encrypt will try to store a new IK (call 3).
    // When that fails, create_intermediate_key should load_latest and find the existing IK.
    ms.reset_store_count();
    ms.set_fail_store_on_call(1); // fail on very next store

    // The second encrypt on same partition should still work because the existing
    // IK is still valid and load_latest will find it after the store fails
    let drr2 = session.encrypt(b"after store fail").unwrap();

    // Verify both decrypt correctly
    ms.set_fail_store_on_call(0); // disable targeted failure
    let pt = session.decrypt(drr).unwrap();
    assert_eq!(pt, b"pre-populate");
    let pt2 = session.decrypt(drr2).unwrap();
    assert_eq!(pt2, b"after store fail");
}

// ──────────────────────────── Gap Coverage Tests ────────────────────────────

fn make_factory_with_expire(
    metastore: Arc<FailableMetastore>,
    kms: Arc<FailableKms<AES256GCM>>,
    expire_s: i64,
) -> asherah::session::PublicFactory<AES256GCM, FailableKms<AES256GCM>, FailableMetastore> {
    let crypto = make_crypto();
    let mut cfg = asherah::Config::new("err-svc", "err-prod");
    cfg.policy.cache_system_keys = false;
    cfg.policy.cache_intermediate_keys = false;
    cfg.policy.cache_sessions = false;
    cfg.policy.expire_key_after_s = expire_s;
    cfg.policy.create_date_precision_s = 1; // 1 second precision to get different timestamps
    asherah::api::new_session_factory(cfg, metastore, kms, crypto)
}

// Gap #1: Decrypt DRR encrypted under an old SK after SK rotation.
//
// When an IK was encrypted under SK1 and then SK1 is revoked/expired,
// a new encrypt creates SK2 and IK2. Decrypting the original DRR (which
// references IK1 → SK1) should still succeed because the code loads the
// correct SK1 by its exact (id, created) metadata.
#[test]
fn decrypt_succeeds_after_system_key_rotation() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory_with_expire(ms.clone(), kms, 1);

    let session = factory.get_session("cross-sk");

    // Step 1: Encrypt DRR1 under SK1/IK1
    let drr1 = session.encrypt(b"old payload").unwrap();

    // Extract IK metadata from DRR1 so we can find the SK
    let ik_meta = drr1.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    let ik_id = &ik_meta.id;
    let ik_created = ik_meta.created;

    // Load the IK to find the SK metadata
    let ik_ekr = ms.inner.load(ik_id, ik_created).unwrap().unwrap();
    let sk_meta = ik_ekr.parent_key_meta.as_ref().unwrap();
    let sk_id = sk_meta.id.clone();
    let sk_created = sk_meta.created;

    // Step 2: Revoke SK1
    ms.inner.mark_revoked(&sk_id, sk_created);

    // Step 3: Wait for at least 1 second so the old SK is considered expired
    // (expire_key_after_s = 1) and a new timestamp is generated (precision = 1s)
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // Step 4: Encrypt again — old SK is revoked+expired, so a new SK2 is created
    let drr2 = session.encrypt(b"new payload").unwrap();

    // Verify a new SK was created (different IK with different parent SK created time)
    let ik2_meta = drr2.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    let ik2_ekr = ms
        .inner
        .load(&ik2_meta.id, ik2_meta.created)
        .unwrap()
        .unwrap();
    let sk2_created = ik2_ekr.parent_key_meta.as_ref().unwrap().created;
    assert_ne!(
        sk_created, sk2_created,
        "SK should have been rotated to a new timestamp"
    );

    // Step 5: Decrypt DRR1 — this must succeed by loading SK1 via its exact metadata
    let pt1 = session.decrypt(drr1).unwrap();
    assert_eq!(pt1, b"old payload");

    // Step 6: Decrypt DRR2 as well
    let pt2 = session.decrypt(drr2).unwrap();
    assert_eq!(pt2, b"new payload");
}

// Gap #2: create_intermediate_key full fallback → error.
//
// When store fails AND load_latest returns a revoked IK (invalid), the
// "error loading intermediate key from metastore after retry" error should
// be returned. This covers the final Err arm in create_intermediate_key.
#[test]
fn encrypt_fails_when_store_fails_and_latest_ik_is_revoked() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    // Use large expiration so revocation is the only reason for invalidity
    let factory = make_factory_with_expire(ms.clone(), kms, 86400);

    let session = factory.get_session("gap2");

    // Step 1: Encrypt to populate keys
    let drr = session.encrypt(b"seed data").unwrap();

    // Step 2: Extract IK metadata and revoke it
    let ik_meta = drr.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    ms.inner.mark_revoked(&ik_meta.id, ik_meta.created);

    // Step 3: Make store fail so create_intermediate_key can't store a new IK
    ms.set_fail_store(true);

    // Step 4: Encrypt should fail because:
    // - load_latest IK → revoked (invalid) → enters create path
    // - create_intermediate_key creates new IK → store fails
    // - fallback: load_latest IK → still revoked (invalid)
    // - returns "error loading intermediate key from metastore after retry"
    let err = session.encrypt(b"should fail").unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("error loading intermediate key")
            || msg.contains("failed to get or create intermediate key"),
        "expected IK retry failure, got: {msg}"
    );
}

// Gap #3: PublicFactory::close with session cache and shared IK cache.
//
// Create a factory with both session_cache and shared_intermediate_key_cache
// enabled, do some work, then call close(). Verify it doesn't panic and
// double close also succeeds.
#[test]
fn factory_close_with_caches() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let crypto = make_crypto();
    let mut cfg = asherah::Config::new("close-svc", "close-prod");
    cfg.policy.cache_sessions = true;
    cfg.policy.session_cache_max_size = 10;
    cfg.policy.session_cache_ttl_s = 3600;
    cfg.policy.shared_intermediate_key_cache = true;
    cfg.policy.cache_intermediate_keys = true;
    cfg.policy.cache_system_keys = true;
    let factory = asherah::api::new_session_factory(cfg, ms, kms, crypto);

    let s = factory.get_session("p1");
    let drr = s.encrypt(b"close test").unwrap();
    assert_eq!(s.decrypt(drr).unwrap(), b"close test");

    factory.close().unwrap();

    // Double close should also work
    factory.close().unwrap();
}

// ──────────────────────────── Gap A3: create_intermediate_key store returns Ok(false) ────────────────────────────

// When metastore.store() returns Ok(false) (lost race — another process stored first),
// create_intermediate_key should fall back to load_latest and use the existing IK.
// This differs from store returning Err (which also leads to fallback via unwrap_or(false)),
// because Ok(false) is the normal race condition case.
#[test]
fn create_ik_store_ok_false_falls_back_to_load_latest() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms.clone(), kms);

    // Pre-populate: encrypt to create SK and IK in metastore
    let session = factory.get_session("ok-false");
    let drr1 = session.encrypt(b"seed data").unwrap();

    // Make store return Ok(false) — simulates lost race
    ms.set_store_returns_false(true);

    // Second encrypt should still work: create_intermediate_key's store returns
    // Ok(false) → unwrap_or(false) → stored=false → fallback to load_latest
    // → finds existing valid IK
    let drr2 = session.encrypt(b"after ok-false").unwrap();

    // Restore normal store behavior for decrypt
    ms.set_store_returns_false(false);
    assert_eq!(session.decrypt(drr1).unwrap(), b"seed data");
    assert_eq!(session.decrypt(drr2).unwrap(), b"after ok-false");
}

// When store returns Ok(false) and load_latest returns None (shouldn't happen in
// production, but tests the final error arm in create_intermediate_key).
#[test]
fn create_ik_store_ok_false_and_no_latest_fails() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let factory = make_factory(ms.clone(), kms);

    // Make store return Ok(false) and load_latest return None
    ms.set_store_returns_false(true);
    ms.set_load_latest_returns_none(true);

    let session = factory.get_session("ok-false-none");
    let err = session.encrypt(b"should fail").unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("not found")
            || msg.contains("error loading")
            || msg.contains("failed to get or create"),
        "expected fallback failure, got: {msg}"
    );
}

// ──────────────────────────── Gap A5: zero/negative create_date_precision ────────────────────────────

// When create_date_precision_s <= 0, new_key_timestamp() returns now_s() directly
// (skips the rounding division). Verify encrypt/decrypt still works.
#[test]
fn encrypt_decrypt_with_zero_precision() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let crypto = make_crypto();
    let mut cfg = asherah::Config::new("prec-svc", "prec-prod");
    cfg.policy.cache_system_keys = false;
    cfg.policy.cache_intermediate_keys = false;
    cfg.policy.cache_sessions = false;
    cfg.policy.create_date_precision_s = 0;
    let factory = asherah::api::new_session_factory(cfg, ms, kms, crypto);

    let session = factory.get_session("p1");
    let drr = session.encrypt(b"zero precision").unwrap();
    assert_eq!(session.decrypt(drr).unwrap(), b"zero precision");
}

#[test]
fn encrypt_decrypt_with_negative_precision() {
    let ms = Arc::new(FailableMetastore::new());
    let kms = default_kms();
    let crypto = make_crypto();
    let mut cfg = asherah::Config::new("neg-prec-svc", "neg-prec-prod");
    cfg.policy.cache_system_keys = false;
    cfg.policy.cache_intermediate_keys = false;
    cfg.policy.cache_sessions = false;
    cfg.policy.create_date_precision_s = -1;
    let factory = asherah::api::new_session_factory(cfg, ms, kms, crypto);

    let session = factory.get_session("p1");
    let drr = session.encrypt(b"negative precision").unwrap();
    assert_eq!(session.decrypt(drr).unwrap(), b"negative precision");
}
