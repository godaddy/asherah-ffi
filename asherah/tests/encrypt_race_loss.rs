//! Regression tests for `Session::encrypt`'s IK store race-loss recovery
//! (commit 89792e2). When `metastore.store` returns `Ok(false)` — meaning
//! another encrypter beat us to inserting an IK at the same `(id, created)`
//! key — the legacy encrypt path must reload the winner's IK via
//! `load_latest` and continue, not surface a confusing "store failed" error.
//!
//! These tests use a `RaceLossMetastore` that wraps `InMemoryMetastore` and
//! deterministically simulates the race: the first time a store hits the IK
//! id, the wrapper inserts the row anyway (the "winner") and returns
//! `Ok(false)` to the caller (the "loser"). Subsequent stores delegate
//! unchanged.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use asherah as ael;
use asherah::traits::Metastore;
use asherah::types::EnvelopeKeyRecord;

#[derive(Clone)]
struct RaceLossMetastore {
    inner: Arc<ael::metastore::InMemoryMetastore>,
    armed: Arc<AtomicBool>,
}

impl RaceLossMetastore {
    fn new() -> Self {
        Self {
            inner: Arc::new(ael::metastore::InMemoryMetastore::new()),
            armed: Arc::new(AtomicBool::new(true)),
        }
    }

    fn was_triggered(&self) -> bool {
        !self.armed.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Metastore for RaceLossMetastore {
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
        // Only fire on IK ids (skip SK stores). Compare on the well-known
        // `_IK_` segment used by `DefaultPartition::intermediate_key_id`.
        if id.contains("_IK_") && self.armed.swap(false, Ordering::SeqCst) {
            // Simulate a winner who beat us to this `(id, created)`. We
            // reuse the caller's own EKR as the winner — semantically a
            // real race might produce a different EKR, but the recovery
            // path doesn't care: it loads via `load_latest` and decrypts
            // under the parent SK referenced by the loaded record.
            let _ = self.inner.store(id, created, ekr)?; // becomes the winner
            return Ok(false); // we're the loser
        }
        self.inner.store(id, created, ekr)
    }
}

fn build_session(
    store: Arc<RaceLossMetastore>,
) -> ael::session::Session<
    ael::aead::AES256GCM,
    ael::kms::StaticKMS<ael::aead::AES256GCM>,
    RaceLossMetastore,
    ael::partition::DefaultPartition,
> {
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![7_u8; 32]).unwrap());
    let partition = Arc::new(ael::partition::DefaultPartition::new(
        "p-race".into(),
        "svc".into(),
        "prod".into(),
    ));
    let policy = ael::policy::CryptoPolicy::default();
    ael::session::SessionFactory::new(store, kms, policy, crypto, partition).session()
}

#[test]
fn legacy_encrypt_recovers_on_ik_store_race_loss() {
    let store = Arc::new(RaceLossMetastore::new());
    let session = build_session(store.clone());

    // First encrypt: the IK doesn't exist yet, so encrypt() falls through
    // to the create+store path. The wrapper fires, inserting the EKR
    // ourselves and returning Ok(false). The recovery path must then
    // load_latest, decrypt the (identical) winner IK, and complete the
    // encrypt successfully.
    let drr = session
        .encrypt(b"hello")
        .expect("encrypt must recover from race loss");
    assert!(
        store.was_triggered(),
        "RaceLossMetastore arm should have fired during the IK store"
    );

    // The DRR should round-trip: decrypt yields the original plaintext.
    let pt = session.decrypt(drr).expect("decrypt must succeed");
    assert_eq!(pt, b"hello");

    // Subsequent encrypts must continue to work — the wrapper is now
    // disarmed and the IK is cached in the metastore.
    let drr2 = session
        .encrypt(b"world")
        .expect("subsequent encrypt must succeed");
    let pt2 = session
        .decrypt(drr2)
        .expect("subsequent decrypt must succeed");
    assert_eq!(pt2, b"world");
}

/// If the metastore returns Ok(false) but `load_latest` returns None
/// (an inconsistent metastore), the recovery must surface a clear error
/// rather than panic, hang, or silently retry forever.
#[test]
fn legacy_encrypt_surface_error_when_load_latest_inconsistent() {
    /// Wrapper that returns Ok(false) on the first IK store *and* keeps
    /// load_latest returning None — simulating a broken metastore.
    #[derive(Clone)]
    struct InconsistentMetastore {
        armed: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Metastore for InconsistentMetastore {
        fn load(
            &self,
            _id: &str,
            _created: i64,
        ) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
            Ok(None)
        }
        fn load_latest(&self, _id: &str) -> Result<Option<EnvelopeKeyRecord>, anyhow::Error> {
            Ok(None)
        }
        fn store(
            &self,
            id: &str,
            _created: i64,
            _ekr: &EnvelopeKeyRecord,
        ) -> Result<bool, anyhow::Error> {
            if id.contains("_IK_") && self.armed.swap(false, Ordering::SeqCst) {
                return Ok(false);
            }
            Ok(true)
        }
    }

    let store = Arc::new(InconsistentMetastore {
        armed: Arc::new(AtomicBool::new(true)),
    });
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![3_u8; 32]).unwrap());
    let partition = Arc::new(ael::partition::DefaultPartition::new(
        "p-incon".into(),
        "svc".into(),
        "prod".into(),
    ));
    let policy = ael::policy::CryptoPolicy::default();
    let session =
        ael::session::SessionFactory::new(store, kms, policy, crypto, partition).session();

    let err = session
        .encrypt(b"x")
        .expect_err("must error on inconsistent metastore");
    let chain = format!("{err:#}");
    assert!(
        chain.contains("metastore may be inconsistent") || chain.contains("store returned false"),
        "expected an inconsistent-metastore error, got: {chain}"
    );
}
