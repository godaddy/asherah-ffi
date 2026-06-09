#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Regression tests for best-effort cross-region / region-suffix decrypt
//! recovery (see `PublicSession::recover_decrypt`).
//!
//! Background: a row's intermediate-key id encodes the partition identity
//! `_IK_{id}_{service}_{product}` plus an optional region suffix. When a
//! decrypting session's identity differs only in the region suffix (data
//! written under another region, or before suffixing was toggled), the normal
//! path fails. Recovery tries the row's key under alternate suffixes, using the
//! AES-GCM tag as the success oracle, so a wrong key can never yield wrong
//! plaintext. This mirrors the upstream Asherah Java/C# defect family
//! (godaddy/asherah #1696/#1698).

use std::sync::Arc;

use asherah as ael;
use asherah::types::KeyMeta;

type Store = ael::metastore::InMemoryMetastore;
type Kms = ael::kms::StaticKMS<ael::aead::AES256GCM>;
type Factory = ael::SessionFactory<ael::aead::AES256GCM, Kms, Store>;

/// Shared crypto/KMS/metastore so multiple factories (each with a different
/// region-suffix configuration) read and write the same key store.
struct Shared {
    crypto: Arc<ael::aead::AES256GCM>,
    kms: Arc<Kms>,
    store: Arc<Store>,
}

impl Shared {
    fn new() -> Self {
        let crypto = Arc::new(ael::aead::AES256GCM::new());
        let kms = Arc::new(Kms::new(crypto.clone(), vec![7_u8; 32]).unwrap());
        let store = Arc::new(Store::new());
        Self { crypto, kms, store }
    }

    fn factory(&self, region_suffix: Option<&str>, recovery: &[&str]) -> Factory {
        self.factory_full(region_suffix, recovery, true)
    }

    fn factory_full(
        &self,
        region_suffix: Option<&str>,
        recovery: &[&str],
        self_heal: bool,
    ) -> Factory {
        let mut cfg = ael::Config::new("svc", "prod").with_self_heal_recovered_keys(self_heal);
        if let Some(s) = region_suffix {
            cfg = cfg.with_region_suffix(s);
        }
        if !recovery.is_empty() {
            cfg = cfg
                .with_recovery_region_suffixes(recovery.iter().map(|&s| s.to_string()).collect());
        }
        ael::api::new_session_factory(
            cfg,
            self.store.clone(),
            self.kms.clone(),
            self.crypto.clone(),
        )
    }

    fn key_exists(&self, id: &str, created: i64) -> bool {
        use asherah::traits::Metastore as _;
        self.store.load(id, created).unwrap().is_some()
    }
}

/// Christopher's case: data written by a NON-suffixed session, read by a
/// session with a region suffix enabled. Recovers via the always-tried empty
/// suffix candidate — no recovery config required.
#[test]
fn recovers_unsuffixed_row_with_suffixed_session_no_config() {
    let shared = Shared::new();

    // Write without a region suffix → row IK id = `_IK_p_svc_prod`.
    let writer = shared.factory(None, &[]).get_session("p");
    let drr = writer.encrypt(b"top secret").unwrap();
    assert_eq!(
        drr.key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .id,
        "_IK_p_svc_prod"
    );

    // Read with a region suffix enabled and NO recovery list configured.
    let reader = shared.factory(Some("us-west-2"), &[]).get_session("p");
    let pt = reader
        .decrypt(drr)
        .expect("suffixed session must recover unsuffixed row via empty-suffix candidate");
    assert_eq!(pt, b"top secret");
}

/// The exact upstream defect shape: a row tagged with the LOCAL suffix
/// (`us-west-2`) whose DRK was actually wrapped by the `us-east-1` IK, and
/// whose recorded `created` only exists under `us-east-1`. Recovery finds the
/// real key via the configured `us-east-1` suffix.
#[test]
fn recovers_cross_region_mismatched_suffix_row() {
    let shared = Shared::new();

    // Real data encrypted in us-east-1 (stores the us-east-1 IK + SK).
    let east = shared.factory(Some("us-east-1"), &[]).get_session("p");
    let mut drr = east.encrypt(b"cross region secret").unwrap();
    let east_meta = drr.key.as_ref().unwrap().parent_key_meta.clone().unwrap();
    assert_eq!(east_meta.id, "_IK_p_svc_prod_us-east-1");

    // Simulate the bug: rewrite the row's IK id to the LOCAL (us-west-2)
    // suffix, keeping the us-east-1 `created` and the us-east-1-wrapped DRK.
    drr.key.as_mut().unwrap().parent_key_meta = Some(KeyMeta {
        id: "_IK_p_svc_prod_us-west-2".into(),
        created: east_meta.created,
    });

    // Local session is us-west-2 with us-east-1 in its recovery list.
    let west = shared
        .factory(Some("us-west-2"), &["us-east-1"])
        .get_session("p");
    let pt = west
        .decrypt(drr)
        .expect("recovery must decrypt the mislabeled cross-region row");
    assert_eq!(pt, b"cross region secret");
}

/// Without the configured recovery suffix, the cross-region row is NOT
/// recoverable (the empty suffix alone cannot reach `us-east-1`). Proves the
/// configured list is load-bearing for non-empty-suffix recovery.
#[test]
fn cross_region_row_not_recovered_without_config() {
    let shared = Shared::new();

    let east = shared.factory(Some("us-east-1"), &[]).get_session("p");
    let mut drr = east.encrypt(b"cross region secret").unwrap();
    let created = drr
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;
    drr.key.as_mut().unwrap().parent_key_meta = Some(KeyMeta {
        id: "_IK_p_svc_prod_us-west-2".into(),
        created,
    });

    // us-west-2 session, EMPTY recovery list.
    let west = shared.factory(Some("us-west-2"), &[]).get_session("p");
    assert!(
        west.decrypt(drr).is_err(),
        "cross-region row must not be recoverable without the configured suffix"
    );
}

/// Tenant isolation: a session must never recover a row that belongs to a
/// DIFFERENT partition id, even when that partition's key is present and the
/// row is otherwise perfectly valid. Recovery only tries same-core candidates.
#[test]
fn does_not_recover_foreign_partition_row() {
    let shared = Shared::new();

    // Victim writes a fully valid row under partition "victim".
    let victim = shared.factory(None, &[]).get_session("victim");
    let drr = victim.encrypt(b"victim data").unwrap();

    // Attacker session (partition "attacker") with a permissive recovery list
    // must still fail — different id core.
    let attacker = shared
        .factory(None, &["us-east-1", "us-west-2"])
        .get_session("attacker");
    assert!(
        attacker.decrypt(drr).is_err(),
        "session must not decrypt another partition's row via recovery"
    );
}

/// The AES-GCM tag is the success oracle: a tampered ciphertext must NOT be
/// "recovered". Recovery may load several candidate keys, but none can produce
/// a valid tag for corrupted data.
#[test]
fn recovery_does_not_mask_tampering() {
    let shared = Shared::new();

    let west = shared
        .factory(Some("us-west-2"), &["us-east-1"])
        .get_session("p");
    let mut drr = west.encrypt(b"authentic").unwrap();
    // Corrupt the wrapped DRK.
    drr.key.as_mut().unwrap().encrypted_key[0] ^= 0xFF;

    assert!(
        west.decrypt(drr).is_err(),
        "tampered ciphertext must fail even with recovery enabled"
    );
}

/// Async path parity: the empty-suffix recovery also works through
/// `decrypt_async`.
#[tokio::test]
async fn recovers_unsuffixed_row_async() {
    let shared = Shared::new();

    let writer = shared.factory(None, &[]).get_session("p");
    let drr = writer.encrypt(b"async secret").unwrap();

    let reader = shared.factory(Some("us-west-2"), &[]).get_session("p");
    let pt = reader
        .decrypt_async(drr)
        .await
        .expect("async suffixed session must recover unsuffixed row");
    assert_eq!(pt, b"async secret");
}

/// Shape A (the upstream wrong-suffix defect): a row tagged `_..._us-west-2`
/// whose key only exists under `_..._us-east-1`. Recovery decrypts it, and
/// self-heal writes the key under the `(id, created)` the row references so the
/// SECOND read takes the fast path.
#[test]
fn self_heal_writes_copy_to_expected_coordinates() {
    let shared = Shared::new();

    let east = shared.factory(Some("us-east-1"), &[]).get_session("p");
    let mut drr = east.encrypt(b"heal me").unwrap();
    let created = drr
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;
    // Mislabel to the local suffix at the same created (Shape A): the id is
    // accepted by the gate, but no key exists at (_..._us-west-2, created).
    drr.key.as_mut().unwrap().parent_key_meta = Some(KeyMeta {
        id: "_IK_p_svc_prod_us-west-2".into(),
        created,
    });
    assert!(
        !shared.key_exists("_IK_p_svc_prod_us-west-2", created),
        "precondition: no us-west-2 key at that created"
    );

    let west = shared
        .factory_full(Some("us-west-2"), &["us-east-1"], true)
        .get_session("p");
    assert_eq!(west.decrypt(drr.clone()).unwrap(), b"heal me");

    // Self-heal wrote the recovered key where the row points.
    assert!(
        shared.key_exists("_IK_p_svc_prod_us-west-2", created),
        "self-heal must copy the recovered key to the row's coordinates"
    );
    // Second read decrypts again (now via the fast path against the copy).
    assert_eq!(west.decrypt(drr).unwrap(), b"heal me");
}

/// With self-heal disabled, recovery still decrypts but writes nothing.
#[test]
fn self_heal_disabled_writes_nothing() {
    let shared = Shared::new();

    let east = shared.factory(Some("us-east-1"), &[]).get_session("p");
    let mut drr = east.encrypt(b"no heal").unwrap();
    let created = drr
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;
    drr.key.as_mut().unwrap().parent_key_meta = Some(KeyMeta {
        id: "_IK_p_svc_prod_us-west-2".into(),
        created,
    });

    let west = shared
        .factory_full(Some("us-west-2"), &["us-east-1"], false)
        .get_session("p");
    assert_eq!(west.decrypt(drr).unwrap(), b"no heal");
    assert!(
        !shared.key_exists("_IK_p_svc_prod_us-west-2", created),
        "self-heal disabled must not write any key"
    );
}

/// Shape B (this incident): a suffixed session reads an unsuffixed-key row. The
/// gate now accepts the bare core, so it decrypts on the fast path and self-heal
/// does NOT fire (the key is already where the row points).
#[test]
fn unsuffixed_row_fast_paths_without_self_heal_write() {
    let shared = Shared::new();

    let writer = shared.factory(None, &[]).get_session("p");
    let drr = writer.encrypt(b"shape b").unwrap();
    assert_eq!(
        drr.key
            .as_ref()
            .unwrap()
            .parent_key_meta
            .as_ref()
            .unwrap()
            .id,
        "_IK_p_svc_prod"
    );
    let created = drr
        .key
        .as_ref()
        .unwrap()
        .parent_key_meta
        .as_ref()
        .unwrap()
        .created;

    let west = shared
        .factory_full(Some("us-west-2"), &[], true)
        .get_session("p");
    assert_eq!(west.decrypt(drr).unwrap(), b"shape b");
    // No copy under the suffixed id — the row references the bare core, which
    // already exists and is now accepted by the gate.
    assert!(!shared.key_exists("_IK_p_svc_prod_us-west-2", created));
}
