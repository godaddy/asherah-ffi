//! Property-based test for the central rotation invariant.
//!
//! Invariant: **every DRR ever returned by `encrypt()` must decrypt to
//! its original plaintext at any later point**, regardless of what
//! revocations / rotations / cache TTL events happened between encrypt
//! and decrypt.
//!
//! This is the single property that distinguishes a working envelope-
//! encryption library from a broken one. The hand-written tests in
//! `tests/revocation.rs`, `tests/rotation_expiration.rs`, and
//! `tests/concurrent_rotation.rs` exercise specific scripted sequences;
//! this test exercises **random** sequences and asserts the invariant
//! holds for every reachable state.
//!
//! `proptest`'s shrinking will minimize any failing case to the
//! shortest reproducer, so a regression that surfaces only in (e.g.)
//! "encrypt → revoke IK → sleep past TTL → encrypt → decrypt first DRR
//! → fails" gets reduced to exactly that 5-action trace.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use asherah as ael;
use proptest::prelude::*;

/// Actions the property test can apply. `Sleep` and `MarkIkRevoked` /
/// `MarkSkRevoked` reference indices into the per-trace history rather
/// than capturing live keys, so the action enum is value-only and can
/// be shrunk freely by proptest.
#[derive(Debug, Clone)]
enum Action {
    /// Encrypt a small plaintext (the byte itself becomes both the
    /// payload and an identity tag for assertion).
    Encrypt(u8),
    /// Mark the most-recently-encrypted IK revoked.
    /// No-op if no DRRs have been produced yet.
    RevokeLatestIk,
    /// Mark the most-recently-encrypted IK's parent SK revoked.
    /// No-op if no DRRs have been produced yet.
    RevokeLatestSk,
    /// Sleep for some number of 100ms ticks (capped to keep the
    /// total trace runtime bounded). 0 ticks is allowed because
    /// shrinking wants the option to drop the sleep.
    SleepTicks(u8),
    /// Throw away the current session and grab a fresh one from the
    /// factory; exercises the cache-cold path between encrypt
    /// operations.
    NewSession,
}

fn action_strategy() -> impl Strategy<Value = Action> {
    prop_oneof![
        4 => any::<u8>().prop_map(Action::Encrypt),
        1 => Just(Action::RevokeLatestIk),
        1 => Just(Action::RevokeLatestSk),
        // Cap sleep ticks at 15 (1.5s) per action; the total trace
        // budget is enforced separately so a bad shrinker can't run
        // away with the clock.
        2 => (0_u8..=15).prop_map(Action::SleepTicks),
        1 => Just(Action::NewSession),
    ]
}

/// Run a single trace and assert the invariant. Returns Err with a
/// human-readable diagnosis on the first failure so proptest can
/// shrink and the operator can read what happened.
fn run_trace(actions: &[Action]) -> Result<(), String> {
    // Short policy expiry + 1s revoke-check interval so sleeps in the
    // trace can plausibly cross both boundaries. Static KMS, in-memory
    // metastore — same shape as `tests/revocation.rs` and
    // `tests/rotation_expiration.rs`.
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let kms = Arc::new(
        ael::kms::StaticKMS::new(crypto.clone(), vec![0x77_u8; 32])
            .map_err(|e| format!("KMS init: {e:#}"))?,
    );
    let store = Arc::new(ael::metastore::InMemoryMetastore::new());
    let mut cfg = ael::Config::new("proptest-svc", "proptest-prod");
    cfg.policy.expire_key_after_s = 1;
    cfg.policy.create_date_precision_s = 1;
    cfg.policy.revoke_check_interval_s = 1;
    cfg.policy.cache_sessions = false;
    let factory = ael::api::new_session_factory(cfg, store.clone(), kms, crypto);

    // Single partition for the whole trace — exercises the same
    // SK / IK pair under varied operations.
    let mut session = factory.get_session("proptest-partition");

    // Bound total sleep across the trace so a degenerate case
    // (15 sleep actions × 1.5s each) can't run for half a minute.
    const MAX_TOTAL_SLEEP_MS: u64 = 4_500;
    let mut elapsed_sleep_ms: u64 = 0;

    // History of (plaintext_byte, DRR, IK meta, SK meta).
    // Plaintext is just the u8 wrapped to 32 bytes so the round-trip
    // test has something with structure.
    type Hist = (u8, ael::DataRowRecord, (String, i64), (String, i64));
    let mut history: Vec<Hist> = Vec::new();

    for (idx, action) in actions.iter().enumerate() {
        match action {
            Action::Encrypt(seed) => {
                let payload = vec![*seed; 32];
                let drr = session
                    .encrypt(&payload)
                    .map_err(|e| format!("step {idx}: encrypt failed: {e:#}"))?;
                let pkm = drr.key.as_ref().unwrap().parent_key_meta.as_ref().unwrap();
                let ik_meta = (pkm.id.clone(), pkm.created);
                let ik_ekr = ael::Metastore::load(&*store, &ik_meta.0, ik_meta.1)
                    .map_err(|e| format!("step {idx}: metastore load IK: {e:#}"))?
                    .ok_or_else(|| format!("step {idx}: IK row missing in metastore"))?;
                let parent = ik_ekr.parent_key_meta.as_ref().ok_or_else(|| {
                    format!("step {idx}: IK row missing parent_key_meta — schema corruption")
                })?;
                let sk_meta = (parent.id.clone(), parent.created);
                history.push((*seed, drr, ik_meta, sk_meta));
            }
            Action::RevokeLatestIk => {
                if let Some((_, _, (id, created), _)) = history.last() {
                    store.mark_revoked(id, *created);
                }
            }
            Action::RevokeLatestSk => {
                if let Some((_, _, _, (id, created))) = history.last() {
                    store.mark_revoked(id, *created);
                }
            }
            Action::SleepTicks(n) => {
                let want_ms = (*n as u64) * 100;
                let allowed = MAX_TOTAL_SLEEP_MS.saturating_sub(elapsed_sleep_ms);
                let actual = want_ms.min(allowed);
                if actual > 0 {
                    sleep(Duration::from_millis(actual));
                    elapsed_sleep_ms += actual;
                }
            }
            Action::NewSession => {
                session = factory.get_session("proptest-partition");
            }
        }

        // Invariant check: every DRR ever produced must still decrypt
        // to its original plaintext, on the *current* session.
        for (i, (seed, drr, _, _)) in history.iter().enumerate() {
            let pt = session.decrypt(drr.clone()).map_err(|e| {
                format!(
                    "after step {idx} ({:?}): historical DRR #{i} (seed={seed}) failed to decrypt: {e:#}",
                    actions[idx]
                )
            })?;
            let want = vec![*seed; 32];
            if pt != want {
                return Err(format!(
                    "after step {idx} ({:?}): historical DRR #{i} decrypted to {} bytes (expected {} of 0x{:02x})",
                    actions[idx],
                    pt.len(),
                    want.len(),
                    seed,
                ));
            }
        }
    }

    Ok(())
}

proptest! {
    // 32 cases keeps the test under a minute even with sleeps; bump
    // locally if you want more coverage. `fork = true` would isolate
    // each case in its own process (good for catching state leaks)
    // but slows things down; rely on the InMemoryMetastore and fresh
    // factory per `run_trace` for isolation instead.
    #![proptest_config(ProptestConfig {
        cases: 32,
        max_shrink_iters: 256,
        .. ProptestConfig::default()
    })]

    /// Random short trace (≤8 actions). Every DRR ever produced must
    /// decrypt to its plaintext at every later step.
    #[test]
    fn every_drr_decrypts_under_any_short_trace(
        actions in prop::collection::vec(action_strategy(), 1..=8)
    ) {
        run_trace(&actions).map_err(TestCaseError::fail)?;
    }
}

proptest! {
    // Longer traces, fewer cases, because each one is bigger and
    // includes more sleeps.
    #![proptest_config(ProptestConfig {
        cases: 16,
        max_shrink_iters: 128,
        .. ProptestConfig::default()
    })]

    /// Longer trace (≤16 actions). Catches state leaks and
    /// accumulated-cache-staleness bugs that a short trace would miss.
    #[test]
    fn every_drr_decrypts_under_any_longer_trace(
        actions in prop::collection::vec(action_strategy(), 8..=16)
    ) {
        run_trace(&actions).map_err(TestCaseError::fail)?;
    }
}

/// Sanity: explicit hand-written trace covering the most common shape
/// (encrypt, revoke, sleep, encrypt, decrypt all). Catches obvious
/// regressions even if proptest's shrinker can't get into a useful
/// case.
#[test]
fn explicit_trace_smoke() {
    let trace = vec![
        Action::Encrypt(0xAA),
        Action::RevokeLatestIk,
        Action::SleepTicks(12), // 1.2s — past expiry
        Action::Encrypt(0xBB),
        Action::RevokeLatestSk,
        Action::SleepTicks(12),
        Action::Encrypt(0xCC),
        Action::NewSession,
        Action::Encrypt(0xDD),
    ];
    run_trace(&trace).expect("explicit trace must satisfy the invariant");
}
