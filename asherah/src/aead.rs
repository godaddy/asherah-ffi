use crate::traits::AEAD as AeadTrait;
// The selected AES-256-GCM backend exposes a reusable prepared-key state. That
// state is key-equivalent material, so callers should treat it with the same
// care as the raw 32-byte key. Our nonce strategy is safe within Asherah's
// rotation policy, but the math deserves a careful note:
//
// - Data encryption: generates a fresh 12-byte random nonce from a fast CSPRNG
//   seeded from OS entropy. The birthday bound
//   for 96-bit random nonces is `2^-32` collision probability after **2^32
//   encryptions under the same key**, NOT after 2^32 messages globally.
//   Asherah rotates intermediate keys per-partition on the policy's
//   `ExpireAfter` cadence (default 90 days), so the per-key counter sees the
//   traffic from one partition for one rotation window only. Operators who
//   exceed ~2^32 encrypts (~4.3e9) under the same IK should tighten the
//   rotation interval — at >540 enc/sec sustained for 90 days the bound
//   becomes non-negligible.
//
// - Enclave sealing (memguard.rs): uses a monotonic atomic counter prefixed
//   with a random 4-byte per-process value, which guarantees uniqueness
//   within a process and across rekey-coffer cycles even if the counter
//   restarts at 0.
//
use std::cell::RefCell;

#[cfg(not(any(feature = "crypto-hardware-rust", feature = "crypto-ring")))]
compile_error!("enable a crypto backend: `crypto-hardware-rust` or `crypto-ring`");

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

const GCM_NONCE_SIZE: usize = 12;

#[cfg(feature = "crypto-hardware-rust")]
mod backend {
    use hardware_rust_crypto::aes_gcm::HardwareAes256GcmKeyState;

    pub type PreparedAes256GcmKey = HardwareAes256GcmKeyState;

    #[inline(always)]
    pub fn prepare_key(key: &[u8]) -> Result<PreparedAes256GcmKey, anyhow::Error> {
        HardwareAes256GcmKeyState::new(key)
            .map_err(|e| anyhow::anyhow!("AES-256-GCM key prepare: {e}"))
    }

    #[inline(always)]
    pub fn encrypt_with_prepared_key(
        data: &[u8],
        key: &PreparedAes256GcmKey,
        nonce: &[u8; super::GCM_NONCE_SIZE],
    ) -> Result<Vec<u8>, anyhow::Error> {
        key.encrypt_nonce_appended(nonce, data)
            .map_err(|e| anyhow::anyhow!("AES-256-GCM seal failed (data_len={}): {e}", data.len()))
    }

    #[inline(always)]
    pub fn decrypt_with_prepared_key(
        data: &[u8],
        key: &PreparedAes256GcmKey,
    ) -> Result<Vec<u8>, anyhow::Error> {
        key.decrypt_nonce_appended(data).map_err(|e| {
            anyhow::anyhow!(
                "AES-256-GCM decrypt: authentication failed (ct_len={}): {e}",
                data.len()
            )
        })
    }

    pub const fn backend_name() -> &'static str {
        "hardware-rust-crypto"
    }

    pub const fn prepared_key_state_size() -> usize {
        HardwareAes256GcmKeyState::state_size()
    }
}

#[cfg(all(not(feature = "crypto-hardware-rust"), feature = "crypto-ring"))]
mod backend {
    use core::mem::size_of;
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

    pub type PreparedAes256GcmKey = LessSafeKey;

    #[inline(always)]
    pub fn prepare_key(key: &[u8]) -> Result<PreparedAes256GcmKey, anyhow::Error> {
        let unbound = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("invalid AES-256-GCM key"))?;
        Ok(LessSafeKey::new(unbound))
    }

    #[inline(always)]
    pub fn encrypt_with_prepared_key(
        data: &[u8],
        key: &PreparedAes256GcmKey,
        nonce: &[u8; super::GCM_NONCE_SIZE],
    ) -> Result<Vec<u8>, anyhow::Error> {
        let nonce_obj = Nonce::assume_unique_for_key(*nonce);
        let nonce_bytes = *nonce_obj.as_ref();
        let mut in_out =
            Vec::with_capacity(data.len() + super::AES256GCM::TAG_SIZE + super::GCM_NONCE_SIZE);
        in_out.extend_from_slice(data);
        key.seal_in_place_append_tag(nonce_obj, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow::anyhow!("AES-256-GCM seal failed (data_len={})", data.len()))?;
        in_out.extend_from_slice(&nonce_bytes);
        Ok(in_out)
    }

    #[inline(always)]
    pub fn decrypt_with_prepared_key(
        data: &[u8],
        key: &PreparedAes256GcmKey,
    ) -> Result<Vec<u8>, anyhow::Error> {
        if data.len() < super::GCM_NONCE_SIZE + super::AES256GCM::TAG_SIZE {
            return Err(anyhow::anyhow!("ciphertext too short"));
        }
        let nonce_pos = data.len() - super::GCM_NONCE_SIZE;
        let (ct_with_tag, nonce_bytes) = data.split_at(nonce_pos);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| {
            anyhow::anyhow!(
                "AES-256-GCM decrypt: invalid nonce (len={})",
                nonce_bytes.len()
            )
        })?;
        let mut in_out = ct_with_tag.to_vec();
        let pt = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| {
                anyhow::anyhow!(
                    "AES-256-GCM decrypt: authentication failed (ct_len={})",
                    data.len()
                )
            })?;
        let n = pt.len();
        in_out.truncate(n);
        Ok(in_out)
    }

    pub const fn backend_name() -> &'static str {
        "ring"
    }

    pub const fn prepared_key_state_size() -> usize {
        size_of::<LessSafeKey>()
    }
}

pub use backend::PreparedAes256GcmKey;

// Thread-local fast CSPRNG seeded from OS entropy (avoids getrandom syscall per
// call). Initialized lazily on first use so that entropy failure returns an
// error rather than panicking at thread-local initialization time.
#[cfg(all(not(feature = "crypto-hardware-rust"), feature = "crypto-ring"))]
thread_local! {
    static FAST_RNG: RefCell<Option<rand_chacha::ChaCha20Rng>> = const { RefCell::new(None) };
}

#[cfg(feature = "crypto-hardware-rust")]
thread_local! {
    static FAST_RNG: RefCell<Option<hardware_rust_crypto::random::AesCtrKeyGenerator>> =
        const { RefCell::new(None) };
}

#[cfg(all(not(feature = "crypto-hardware-rust"), feature = "crypto-ring"))]
fn try_init_rng() -> Option<rand_chacha::ChaCha20Rng> {
    use rand::SeedableRng;
    use rand::TryRngCore;
    use rand_chacha::ChaCha20Rng;
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

#[cfg(feature = "crypto-hardware-rust")]
fn try_init_rng() -> Option<hardware_rust_crypto::random::AesCtrKeyGenerator> {
    hardware_rust_crypto::random::AesCtrKeyGenerator::from_os_entropy().ok()
}

/// Fill a buffer with random bytes using the thread-local CSPRNG.
/// Returns `Err` if the OS entropy source is unavailable rather than panicking.
#[inline(always)]
pub fn fast_random_bytes(buf: &mut [u8]) -> anyhow::Result<()> {
    #[cfg(feature = "crypto-hardware-rust")]
    use hardware_rust_crypto::random::KeyGenerator as _;
    #[cfg(all(not(feature = "crypto-hardware-rust"), feature = "crypto-ring"))]
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
                #[cfg(all(not(feature = "crypto-hardware-rust"), feature = "crypto-ring"))]
                {
                    use rand::RngCore as _;
                    rng.fill_bytes(buf);
                    Ok(())
                }
                #[cfg(feature = "crypto-hardware-rust")]
                {
                    match rng.fill_bytes(buf) {
                        Ok(()) => Ok(()),
                        Err(hardware_rust_crypto::random::Error::ForkDetected) => {
                            *opt = try_init_rng();
                            match opt.as_mut() {
                                Some(rng) => rng
                                    .fill_bytes(buf)
                                    .map_err(|e| anyhow::anyhow!("fast random failed: {e}")),
                                None => Err(anyhow::anyhow!("fast random initialization failed")),
                            }
                        }
                        Err(e) => {
                            *opt = None;
                            Err(anyhow::anyhow!("fast random failed: {e}"))
                        }
                    }
                }
            }
            #[cfg(all(not(feature = "crypto-hardware-rust"), feature = "crypto-ring"))]
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
            #[cfg(feature = "crypto-hardware-rust")]
            None => Err(anyhow::anyhow!("fast random initialization failed")),
        }
    })
}

impl AeadTrait for AES256GCM {
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        if key.len() != 32 {
            return Err(anyhow::anyhow!("invalid key size"));
        }
        if data.len() > Self::MAX_DATA_SIZE {
            return Err(anyhow::anyhow!("data length exceeds AES GCM limit"));
        }
        let prepared = prepare_key(key).map_err(|_| {
            anyhow::anyhow!(
                "AES-256-GCM encrypt: invalid key (expected 32 bytes, got {})",
                key.len()
            )
        })?;
        encrypt_with_prepared_key(data, &prepared)
    }

    fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        if key.len() != 32 {
            return Err(anyhow::anyhow!("invalid key size"));
        }
        if data.len() < Self::NONCE_SIZE + Self::TAG_SIZE {
            return Err(anyhow::anyhow!("ciphertext too short"));
        }
        let prepared = prepare_key(key).map_err(|_| {
            anyhow::anyhow!(
                "AES-256-GCM decrypt: invalid key (expected 32 bytes, got {})",
                key.len()
            )
        })?;
        decrypt_with_prepared_key(data, &prepared)
    }
}

/// Returns the selected crypto backend name.
pub const fn backend_name() -> &'static str {
    backend::backend_name()
}

/// Returns the selected backend's prepared key-state size in bytes.
pub const fn prepared_key_state_size() -> usize {
    backend::prepared_key_state_size()
}

/// Make reusable AES-256-GCM key state from raw 32-byte key material.
#[inline(always)]
pub fn prepare_key(key: &[u8]) -> Result<PreparedAes256GcmKey, anyhow::Error> {
    backend::prepare_key(key)
}

/// Encrypt using a prepared key (skips key schedule).
/// Nonce safety: a fresh 12-byte random nonce is generated per call from
/// the selected backend's fast CSPRNG seeded from OS entropy.
///
/// **AAD**: this function uses `Aad::empty()` deliberately for cross-
/// language binary compatibility with the Go reference implementation.
/// The Go `appencryption` library does not include any associated
/// authenticated data, so any non-empty AAD here would produce
/// ciphertexts that the Go side cannot decrypt (and vice versa). If
/// future revisions add AAD, both implementations must rev in lockstep
/// and version the envelope format. T-finding "AEAD uses Aad::empty();
/// document intentional cross-language compatibility" in
/// `docs/review-2026-05-05-findings.md`.
#[inline(always)]
pub fn encrypt_with_prepared_key(
    data: &[u8],
    key: &PreparedAes256GcmKey,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut nonce = [0_u8; GCM_NONCE_SIZE];
    fast_random_bytes(&mut nonce)?;
    backend::encrypt_with_prepared_key(data, key, &nonce)
}

/// Decrypt using a prepared key (skips key schedule).
/// The nonce is extracted from the ciphertext (appended during encryption).
#[inline(always)]
pub fn decrypt_with_prepared_key(
    data: &[u8],
    key: &PreparedAes256GcmKey,
) -> Result<Vec<u8>, anyhow::Error> {
    backend::decrypt_with_prepared_key(data, key)
}

/// Backwards-compatible alias for callers that still use the old helper name.
#[inline(always)]
pub fn make_lsk(key: &[u8]) -> Result<PreparedAes256GcmKey, anyhow::Error> {
    prepare_key(key)
}

/// Backwards-compatible alias for callers that still use the old helper name.
#[inline(always)]
pub fn encrypt_with_lsk(data: &[u8], key: &PreparedAes256GcmKey) -> Result<Vec<u8>, anyhow::Error> {
    encrypt_with_prepared_key(data, key)
}

/// Backwards-compatible alias for callers that still use the old helper name.
#[inline(always)]
pub fn decrypt_with_lsk(data: &[u8], key: &PreparedAes256GcmKey) -> Result<Vec<u8>, anyhow::Error> {
    decrypt_with_prepared_key(data, key)
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
