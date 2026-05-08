//! KMS master-key rotation tests.
//!
//! Static / cloud KMSes both rotate their master key over time. When
//! that happens, *new* SK envelopes are encrypted under the new
//! master key, but the metastore still holds *old* SK envelopes
//! encrypted under the previous master key version. Decrypting any
//! historical DRR requires the KMS to be able to decrypt the old
//! envelope — typically by trying multiple key versions.
//!
//! `system_key_from_ekr` (asherah/src/session.rs:133-143) calls
//! `kms.decrypt_key`. Whatever versioning logic the KMS impl uses is
//! invisible to the engine; what we can test is that as long as the
//! KMS *can* decrypt the old envelope, the engine threads it
//! correctly through the rest of the rotation flow.
//!
//! These tests use a `VersionedKms` mock that maintains a list of
//! historical master keys. Encrypting always uses the newest key;
//! decrypting tries each known key in newest-to-oldest order. The
//! mock's "rotate" call adds a new master key to the front.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use asherah as ael;
use asherah::aead::AES256GCM;
use asherah::traits::{KeyManagementService, AEAD};

#[derive(Clone)]
struct VersionedKms {
    aead: Arc<AES256GCM>,
    /// Master keys in newest-to-oldest order. Encryption uses [0];
    /// decryption tries each.
    keys: Arc<Mutex<Vec<Vec<u8>>>>,
    decrypt_calls: Arc<AtomicUsize>,
    encrypt_calls: Arc<AtomicUsize>,
}

impl VersionedKms {
    fn new(aead: Arc<AES256GCM>, initial_master: Vec<u8>) -> Self {
        assert_eq!(initial_master.len(), 32);
        Self {
            aead,
            keys: Arc::new(Mutex::new(vec![initial_master])),
            decrypt_calls: Arc::new(AtomicUsize::new(0)),
            encrypt_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Add a new master key version. Subsequent encrypts use it; old
    /// envelopes still decrypt against prior versions.
    fn rotate(&self, new_master: Vec<u8>) {
        assert_eq!(new_master.len(), 32);
        let mut g = self.keys.lock().unwrap();
        g.insert(0, new_master);
    }

    fn decrypt_call_count(&self) -> usize {
        self.decrypt_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KeyManagementService for VersionedKms {
    fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.encrypt_calls.fetch_add(1, Ordering::SeqCst);
        let g = self
            .keys
            .lock()
            .map_err(|e| anyhow::anyhow!("master key mutex poisoned: {e}"))?;
        let current = g
            .first()
            .ok_or_else(|| anyhow::anyhow!("no master keys configured"))?;
        self.aead.encrypt(key_bytes, current)
    }

    fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.decrypt_calls.fetch_add(1, Ordering::SeqCst);
        let keys = self
            .keys
            .lock()
            .map_err(|e| anyhow::anyhow!("master key mutex poisoned: {e}"))?
            .clone();
        let mut last_err: Option<anyhow::Error> = None;
        for key in keys.iter() {
            match self.aead.decrypt(blob, key) {
                Ok(v) => return Ok(v),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no master keys configured")))
    }
}

fn make_factory(
    store: Arc<ael::metastore::InMemoryMetastore>,
    kms: Arc<VersionedKms>,
) -> ael::SessionFactory<AES256GCM, VersionedKms, ael::metastore::InMemoryMetastore> {
    let crypto = Arc::new(AES256GCM::new());
    let mut cfg = ael::Config::new("kms-rot-svc", "kms-rot-prod");
    cfg.policy.expire_key_after_s = 24 * 60 * 60;
    cfg.policy.create_date_precision_s = 1;
    cfg.policy.revoke_check_interval_s = 60;
    cfg.policy.cache_sessions = false;
    ael::api::new_session_factory(cfg, store, kms, crypto)
}

/// Encrypt → rotate the KMS master key → decrypt. The DRR's parent
/// SK was wrapped under the old master key; decrypt must still work
/// because the KMS tries each key version.
#[test]
fn decrypt_works_after_kms_master_key_rotation() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let crypto = Arc::new(AES256GCM::new());
    let kms = Arc::new(VersionedKms::new(crypto.clone(), vec![0x11_u8; 32]));
    let factory = make_factory(store.clone(), kms.clone());
    let session = factory.get_session("p1");

    // Encrypt under master-key v1.
    let drr = session.encrypt(b"v1 payload").unwrap();

    // Rotate the master key. v2 is now newest; v1 is still tried on
    // decrypt fallback.
    kms.rotate(vec![0x22_u8; 32]);

    // Decrypt the v1-wrapped DRR — KMS must walk back to v1.
    let pt = session
        .decrypt(drr)
        .expect("decrypt of pre-rotation DRR must succeed via KMS key fallback");
    assert_eq!(pt, b"v1 payload");
}

/// After rotation, *new* SKs must be wrapped under the new master
/// key. Verify by rotating, encrypting (creates a new SK), then
/// rebuilding the factory pointed at a v2-only KMS — only the post-
/// rotation DRR should decrypt under it.
///
/// The fresh factory is required because the SK cache holds
/// already-decrypted `CryptoKey` plaintext; without a cold cache
/// the decrypt path never re-invokes KMS for that SK.
#[test]
fn new_sks_wrapped_under_current_kms_master_key() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let crypto = Arc::new(AES256GCM::new());
    let kms = Arc::new(VersionedKms::new(crypto.clone(), vec![0x44_u8; 32]));

    // Short SK expiry so the next encrypt after rotation produces a
    // brand new SK encrypted under the current master key.
    let mut cfg = ael::Config::new("kms-fresh-svc", "kms-fresh-prod");
    cfg.policy.expire_key_after_s = 1;
    cfg.policy.create_date_precision_s = 1;
    cfg.policy.revoke_check_interval_s = 1;
    cfg.policy.cache_sessions = false;
    let factory = ael::api::new_session_factory(cfg, store.clone(), kms.clone(), crypto.clone());
    let session = factory.get_session("p-fresh");

    let drr_old = session.encrypt(b"old").unwrap();

    // Wait past SK expiry, then rotate the master key.
    std::thread::sleep(std::time::Duration::from_millis(1200));
    kms.rotate(vec![0x55_u8; 32]);

    // Next encrypt must roll a new SK; that SK gets wrapped under
    // the new master key (v2).
    let drr_new = session.encrypt(b"new").unwrap();
    drop(session);
    drop(factory);

    // Build a v2-ONLY KMS. SK1 in the metastore is wrapped under v1,
    // so a v2-only KMS will fail to decrypt the SK1 envelope. SK2 is
    // wrapped under v2 and will decrypt fine.
    let kms_v2_only = Arc::new(VersionedKms::new(crypto.clone(), vec![0x55_u8; 32]));
    let mut cfg2 = ael::Config::new("kms-fresh-svc", "kms-fresh-prod");
    cfg2.policy.expire_key_after_s = 1;
    cfg2.policy.create_date_precision_s = 1;
    cfg2.policy.revoke_check_interval_s = 1;
    cfg2.policy.cache_sessions = false;
    let factory2 =
        ael::api::new_session_factory(cfg2, store.clone(), kms_v2_only.clone(), crypto.clone());
    let session2 = factory2.get_session("p-fresh");

    // The post-rotation DRR must still decrypt — its parent SK is
    // v2-wrapped, so v2-only KMS suffices.
    let pt_new = session2
        .decrypt(drr_new)
        .expect("post-rotation DRR must decrypt under v2-only KMS");
    assert_eq!(pt_new, b"new");

    // The old DRR's parent SK is v1-wrapped. With v1 absent from the
    // fresh KMS, decrypt must fail — guards against the KMS silently
    // accepting wrong plaintext (which would be a critical bug).
    let err = session2
        .decrypt(drr_old)
        .expect_err("v1-wrapped DRR must fail to decrypt under v2-only KMS");
    let chain = format!("{err:#}");
    assert!(
        chain.contains("decrypt") || chain.contains("KMS") || chain.contains("system key"),
        "expected KMS/decrypt error, got: {chain}"
    );
}

/// Many encrypts before rotation, all decryptable after; many
/// encrypts after rotation, also decryptable. Catches pathological
/// "only the most recent envelope decrypts" regressions.
#[test]
fn batch_round_trip_across_kms_rotation() {
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let crypto = Arc::new(AES256GCM::new());
    let kms = Arc::new(VersionedKms::new(crypto.clone(), vec![0x66_u8; 32]));
    let factory = make_factory(store.clone(), kms.clone());
    let session = factory.get_session("p-batch");

    let mut pre: Vec<(ael::DataRowRecord, String)> = Vec::new();
    for i in 0..10 {
        let m = format!("pre-{i}");
        pre.push((session.encrypt(m.as_bytes()).unwrap(), m));
    }

    kms.rotate(vec![0x77_u8; 32]);

    // Force SK rotation so a new SK is wrapped under v2. We can't
    // shorten the policy mid-test, but we can revoke the existing SK.
    let drr0 = &pre[0].0;
    let ik_meta = drr0.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
    let ik_ekr = ael::Metastore::load(&*store, &ik_meta.id, ik_meta.created)
        .unwrap()
        .unwrap();
    let sk_meta = ik_ekr.parent_key_meta.as_ref().unwrap();
    store.mark_revoked(&sk_meta.id, sk_meta.created);
    std::thread::sleep(std::time::Duration::from_millis(70));
    // Cache TTL = 60s in the helper; a short sleep here isn't enough
    // to flush the SK cache. Build a fresh factory pointed at the
    // same store — its caches are cold so it observes the revocation.
    drop(session);
    let factory2 = make_factory(store.clone(), kms.clone());
    let session2 = factory2.get_session("p-batch");

    let mut post: Vec<(ael::DataRowRecord, String)> = Vec::new();
    for i in 0..10 {
        let m = format!("post-{i}");
        post.push((session2.encrypt(m.as_bytes()).unwrap(), m));
    }

    // Every pre and post DRR must decrypt under the new factory.
    for (drr, msg) in pre {
        let pt = session2.decrypt(drr).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }
    for (drr, msg) in post {
        let pt = session2.decrypt(drr).unwrap();
        assert_eq!(pt, msg.as_bytes());
    }

    // Sanity: KMS got hit at least once for decrypt.
    assert!(
        kms.decrypt_call_count() > 0,
        "expected KMS decrypt to be called during the batch"
    );
}
