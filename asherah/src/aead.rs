use crate::traits::AEAD as AeadTrait;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;

// ---------------------------------------------------------------------------
// AEAD backend selection
// ---------------------------------------------------------------------------
//
// Asherah's AES-256-GCM is provided by one backend, chosen at compile time:
//
//   * `hardware-crypto` (DEFAULT) — `hardware-rust-crypto`. The crypto library
//     owns nonce generation: a per-instance 96-bit OS-drawn salt advanced by a
//     64-bit counter (`nonce = base + counter`, re-salted on fork). That
//     construction is *proven non-repeating* (Kani), which eliminates the
//     birthday-bound collision risk that random 96-bit nonces carry. There is
//     no caller-supplied-nonce path on this backend by design.
//
//   * `ring-crypto` (opt-in via `--no-default-features --features ring-crypto`)
//     — ring's `LessSafeKey`. ring has no nonce-generating API, so on this
//     backend Asherah generates a fresh 12-byte random nonce per encryption
//     from a ChaCha20 CSPRNG seeded from OS entropy. "Less safe" refers only to
//     ring not enforcing nonce uniqueness at the type level; uniqueness here is
//     a probabilistic property of the CSPRNG (birthday bound 2^-32 after 2^32
//     encryptions under one key) bounded operationally by the key-rotation
//     policy.
//
// To get ring you must disable the default: `--no-default-features --features
// ring-crypto`. If BOTH features end up enabled — e.g. via `--all-features` or
// Cargo feature unification across a workspace — **`hardware-crypto` takes
// precedence** (the safer backend wins; the ring module is `cfg`-ed out). We
// deliberately resolve this by precedence rather than a `compile_error!` so a
// downstream `--all-features` build never breaks.
//
// Both backends produce the identical envelope `ciphertext || tag(16) ||
// nonce(12)` over standard AES-256-GCM with **empty AAD** by default, so
// ciphertext is interchangeable between backends and remains binary-compatible
// with the Go `appencryption` reference implementation (which uses no AAD).
// The `Aes256GcmKey` methods accept an `aad: &[u8]` so an application can opt
// into associated data; every in-tree call site passes `&[]` to preserve that
// cross-language compatibility. Any non-empty AAD must be revved in lockstep on
// both sides and versioned in the envelope.

#[cfg(not(any(feature = "hardware-crypto", feature = "ring-crypto")))]
compile_error!("no AEAD backend enabled — enable `hardware-crypto` (default) or `ring-crypto`");

const GCM_NONCE_SIZE: usize = 12;

#[derive(Clone, Debug)]
pub struct AES256GCM;

impl AES256GCM {
    pub const NONCE_SIZE: usize = GCM_NONCE_SIZE;
    pub const TAG_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 16;
    pub const MAX_DATA_SIZE: usize = (((1_u64 << 32) - 2) as usize) * Self::BLOCK_SIZE;

    pub fn new() -> Self {
        Self
    }

    pub fn nonce_size(&self) -> usize {
        Self::NONCE_SIZE
    }

    pub fn tag_size(&self) -> usize {
        Self::TAG_SIZE
    }
}

impl Default for AES256GCM {
    fn default() -> Self {
        Self::new()
    }
}

// Thread-local ChaCha20Rng seeded from OsRng (avoids getrandom syscall per call).
// Initialized lazily on first use so that OsRng failure returns an error rather
// than panicking at thread-local initialization time.
//
// Used for data-row-key generation on every backend, and for nonce generation
// on the `ring-crypto` backend (the `hardware-crypto` backend generates its own
// nonces internally).
thread_local! {
    static FAST_RNG: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };
}

fn try_init_rng() -> Option<ChaCha20Rng> {
    use rand::SeedableRng;
    use rand::TryRngCore;
    use zeroize::Zeroizing;
    // Wrap the seed in Zeroizing so the stack copy is volatile-zeroed when
    // this frame returns. The seed is bootstrap material for the per-thread
    // CSPRNG; with it an attacker can reproduce every output of this
    // ChaCha20Rng instance.
    let mut seed: Zeroizing<<ChaCha20Rng as SeedableRng>::Seed> =
        Zeroizing::new(Default::default());
    rand::rngs::OsRng.try_fill_bytes(seed.as_mut()).ok()?;
    Some(ChaCha20Rng::from_seed(*seed))
}

/// Fill a buffer with random bytes using the thread-local CSPRNG.
/// Returns `Err` if the OS entropy source is unavailable rather than panicking.
#[inline(always)]
pub fn fast_random_bytes(buf: &mut [u8]) -> anyhow::Result<()> {
    use rand::TryRngCore;
    FAST_RNG.with(|cell| {
        let mut opt = cell.borrow_mut();
        // Retry init on every miss, not just the first one. The
        // previous implementation only ran `try_init_rng` while the
        // cell was `None`; once `Some(rng)` populated, a transient
        // OsRng failure returned by the rng itself fell through to
        // the bottom branch but never re-initialized. Calling
        // `try_init_rng` whenever the cell is empty (drop the bad
        // rng below) keeps this resilient. T-finding "fast_random_bytes
        // doesn't retry init after transient OsRng failure" in
        // `docs/review-2026-05-05-findings.md`.
        if opt.is_none() {
            *opt = try_init_rng();
        }
        match opt.as_mut() {
            Some(rng) => {
                rng.fill_bytes(buf);
                Ok(())
            }
            None => match rand::rngs::OsRng.try_fill_bytes(buf) {
                Ok(()) => Ok(()),
                Err(e) => {
                    // Drop the cached rng so the next call retries
                    // initialization rather than falling through to
                    // OsRng forever.
                    *opt = None;
                    Err(anyhow::anyhow!("OsRng failed: {e}"))
                }
            },
        }
    })
}

// ===========================================================================
// Backend: hardware-rust-crypto (default)
// ===========================================================================
#[cfg(feature = "hardware-crypto")]
mod backend {
    use super::GCM_NONCE_SIZE;
    use hardware_rust_crypto::aes_gcm::HardwareAes256GcmKeyState;
    use std::sync::Mutex;

    /// A pre-expanded AES-256-GCM key backed by `hardware-rust-crypto`.
    ///
    /// The key state bundles the AES key schedule with a stateful nonce
    /// generator; `encrypt` advances that generator and therefore needs
    /// `&mut`. Asherah caches this key behind a shared `&` reference (see
    /// `CryptoKey`), so the state lives behind a `Mutex`. The critical
    /// section is a single AES-GCM operation (nanoseconds).
    pub struct Aes256GcmKey {
        inner: Mutex<HardwareAes256GcmKeyState>,
    }

    impl Aes256GcmKey {
        pub fn new(key: &[u8]) -> anyhow::Result<Self> {
            let state = HardwareAes256GcmKeyState::new(key)
                .map_err(|e| anyhow::anyhow!("AES-256-GCM key init failed: {e}"))?;
            Ok(Self {
                inner: Mutex::new(state),
            })
        }

        /// Encrypt, returning `ciphertext || tag || nonce`. The nonce is
        /// generated by `hardware-rust-crypto` (counter over an OS salt,
        /// proven non-repeating).
        pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
            // Recover from a poisoned lock rather than propagating: the key
            // schedule is immutable and the nonce counter only ever moves
            // forward, so a panic in another thread cannot leave the state in
            // a value that would cause nonce reuse. Worst case a nonce value
            // is skipped, which is harmless.
            let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            state.encrypt(aad, plaintext).map_err(|e| {
                anyhow::anyhow!("AES-256-GCM seal failed (len={}): {e}", plaintext.len())
            })
        }

        /// Decrypt `ciphertext || tag || nonce`.
        pub fn decrypt(&self, aad: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
            if data.len() < GCM_NONCE_SIZE + super::AES256GCM::TAG_SIZE {
                return Err(anyhow::anyhow!("ciphertext too short"));
            }
            let state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            state.decrypt(aad, data).map_err(|e| {
                anyhow::anyhow!("AES-256-GCM decrypt failed (len={}): {e}", data.len())
            })
        }
    }

    impl std::fmt::Debug for Aes256GcmKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Aes256GcmKey")
                .field("backend", &"hardware-rust-crypto")
                .finish()
        }
    }
}

// ===========================================================================
// Backend: ring (opt-in: --no-default-features --features ring-crypto)
// ===========================================================================
// `not(hardware-crypto)` so that if both features are enabled (e.g.
// `--all-features` or feature unification) exactly one `backend` module exists
// and `hardware-crypto` wins — see the module-level note above.
#[cfg(all(feature = "ring-crypto", not(feature = "hardware-crypto")))]
mod backend {
    use super::{fast_random_bytes, GCM_NONCE_SIZE};
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

    /// A pre-expanded AES-256-GCM key backed by ring's `LessSafeKey`.
    pub struct Aes256GcmKey {
        inner: LessSafeKey,
    }

    impl Aes256GcmKey {
        pub fn new(key: &[u8]) -> anyhow::Result<Self> {
            let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| {
                anyhow::anyhow!(
                    "invalid AES-256-GCM key (expected 32 bytes, got {})",
                    key.len()
                )
            })?;
            Ok(Self {
                inner: LessSafeKey::new(unbound),
            })
        }

        /// Encrypt, returning `ciphertext || tag || nonce`. ring has no nonce
        /// generator, so Asherah draws a fresh 12-byte random nonce per call.
        pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
            let mut nonce = [0_u8; GCM_NONCE_SIZE];
            fast_random_bytes(&mut nonce)?;
            let nonce_obj = Nonce::assume_unique_for_key(nonce);
            let mut in_out =
                Vec::with_capacity(plaintext.len() + super::AES256GCM::TAG_SIZE + GCM_NONCE_SIZE);
            in_out.extend_from_slice(plaintext);
            self.inner
                .seal_in_place_append_tag(nonce_obj, Aad::from(aad), &mut in_out)
                .map_err(|_| {
                    anyhow::anyhow!("AES-256-GCM seal failed (len={})", plaintext.len())
                })?;
            in_out.extend_from_slice(&nonce);
            Ok(in_out)
        }

        /// Decrypt `ciphertext || tag || nonce`.
        pub fn decrypt(&self, aad: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
            if data.len() < GCM_NONCE_SIZE + super::AES256GCM::TAG_SIZE {
                return Err(anyhow::anyhow!("ciphertext too short"));
            }
            let nonce_pos = data.len() - GCM_NONCE_SIZE;
            let (ct_with_tag, nonce_bytes) = data.split_at(nonce_pos);
            let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| {
                anyhow::anyhow!(
                    "AES-256-GCM decrypt: invalid nonce (len={})",
                    nonce_bytes.len()
                )
            })?;
            let mut in_out = ct_with_tag.to_vec();
            let pt = self
                .inner
                .open_in_place(nonce, Aad::from(aad), &mut in_out)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "AES-256-GCM decrypt: authentication failed (len={})",
                        data.len()
                    )
                })?;
            let n = pt.len();
            in_out.truncate(n);
            Ok(in_out)
        }
    }

    impl std::fmt::Debug for Aes256GcmKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Aes256GcmKey")
                .field("backend", &"ring")
                .finish()
        }
    }
}

pub use backend::Aes256GcmKey;

impl AeadTrait for AES256GCM {
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        if key.len() != 32 {
            return Err(anyhow::anyhow!("invalid key size"));
        }
        if data.len() > Self::MAX_DATA_SIZE {
            return Err(anyhow::anyhow!("data length exceeds AES GCM limit"));
        }
        Aes256GcmKey::new(key)?.encrypt(&[], data)
    }

    fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        if key.len() != 32 {
            return Err(anyhow::anyhow!("invalid key size"));
        }
        if data.len() < Self::NONCE_SIZE + Self::TAG_SIZE {
            return Err(anyhow::anyhow!("ciphertext too short"));
        }
        Aes256GcmKey::new(key)?.decrypt(&[], data)
    }
}

/// Create a pre-expanded AES-256-GCM key from raw 32-byte key material.
#[inline(always)]
pub fn make_key(key: &[u8]) -> Result<Aes256GcmKey, anyhow::Error> {
    Aes256GcmKey::new(key)
}

// Helper for deriving a fixed-size pseudo-key from arbitrary bytes (dev placeholder)
pub fn xsalsa_key_from_bytes(input: &[u8]) -> [u8; 32] {
    use blake2::{Blake2b512, Digest};
    let mut h = Blake2b512::new();
    h.update(input);
    let out = h.finalize();
    let mut key = [0_u8; 32];
    key.copy_from_slice(&out[..32]);
    key
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Build the Asherah envelope `ciphertext || tag || nonce` from KAT parts.
    fn envelope(ct: &str, tag: &str, nonce: &str) -> Vec<u8> {
        let mut v = hex(ct);
        v.extend(hex(tag));
        v.extend(hex(nonce));
        v
    }

    // NIST CAVP AES-256-GCM known-answer vectors (AADlen=0, Taglen=128).
    //
    // These run against whichever backend is compiled (`hardware-crypto` by
    // default, `ring-crypto` under `--no-default-features --features
    // ring-crypto`). Because both backends implement standard AES-256-GCM and
    // emit the identical `ciphertext || tag(16) || nonce(12)` envelope with
    // empty AAD, a single fixed envelope must decrypt to the same plaintext on
    // BOTH — which is exactly the cross-backend (and Go cross-language) wire
    // compatibility guarantee, demonstrated by running this test under each
    // feature in CI.
    #[test]
    fn decrypts_nist_vector_empty_plaintext() {
        let key = make_key(&hex(
            "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
        ))
        .unwrap();
        let env = envelope(
            "",
            "bdc1ac884d332457a1d2664f168c76f0",
            "516c33929df5a3284ff463d7",
        );
        assert!(key.decrypt(&[], &env).unwrap().is_empty());
    }

    #[test]
    fn decrypts_nist_vector_128bit_plaintext() {
        let key = make_key(&hex(
            "31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22",
        ))
        .unwrap();
        let env = envelope(
            "fa4362189661d163fcd6a56d8bf0405a",
            "d636ac1bbedd5cc3ee727dc2ab4a9489",
            "0d18e06c7c725ac9e362e1ce",
        );
        assert_eq!(
            key.decrypt(&[], &env).unwrap(),
            hex("2db5168e932556f8089a0622981d017d")
        );
    }

    #[test]
    fn round_trip_empty_aad() {
        let key = make_key(&[7_u8; 32]).unwrap();
        let data = b"asherah envelope round-trip";
        let env = key.encrypt(&[], data).unwrap();
        // Envelope layout is [ciphertext][tag(16)][nonce(12)].
        assert_eq!(
            env.len(),
            data.len() + AES256GCM::TAG_SIZE + AES256GCM::NONCE_SIZE
        );
        assert_eq!(key.decrypt(&[], &env).unwrap(), data);
    }

    #[test]
    fn aad_is_bound_into_tag() {
        let key = make_key(&[9_u8; 32]).unwrap();
        let data = b"payload";
        let env = key.encrypt(b"tenant-42", data).unwrap();
        assert_eq!(key.decrypt(b"tenant-42", &env).unwrap(), data);
        // Wrong AAD must fail authentication...
        assert!(key.decrypt(b"tenant-43", &env).is_err());
        // ...as must the default empty-AAD path against an envelope sealed
        // WITH aad, confirming aad is authenticated.
        assert!(key.decrypt(&[], &env).is_err());
    }

    #[test]
    fn trait_round_trip() {
        let aead = AES256GCM::new();
        let key = [3_u8; 32];
        let env = aead.encrypt(b"hello", &key).unwrap();
        assert_eq!(aead.decrypt(&env, &key).unwrap(), b"hello");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = make_key(&[1_u8; 32]).unwrap();
        let mut env = key.encrypt(&[], b"secret").unwrap();
        env[0] ^= 0xff;
        assert!(key.decrypt(&[], &env).is_err());
    }

    #[test]
    fn rejects_short_ciphertext() {
        let key = make_key(&[2_u8; 32]).unwrap();
        assert!(key.decrypt(&[], &[0_u8; 8]).is_err());
    }
}
