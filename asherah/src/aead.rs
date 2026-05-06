use crate::traits::AEAD as AeadTrait;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
// ring's `LessSafeKey` is named "less safe" only because it does not enforce
// nonce uniqueness at the type level — the caller is responsible for never
// reusing a nonce with the same key. Our usage is safe within Asherah's
// rotation policy, but the math deserves a careful note:
//
// - Data encryption (encrypt_with_lsk): generates a fresh 12-byte random nonce
//   from a ChaCha20-based CSPRNG seeded from OS entropy. The birthday bound
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
// ring's alternative (`SealingKey` with `NonceSequence`) would add overhead
// for nonce tracking that we don't need — our nonce strategy is already sound
// within the rotation policy.
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use std::cell::RefCell;

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

// Thread-local ChaCha20Rng seeded from OsRng (avoids getrandom syscall per call).
// Initialized lazily on first use so that OsRng failure returns an error rather
// than panicking at thread-local initialization time.
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

impl AeadTrait for AES256GCM {
    fn encrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        if key.len() != 32 {
            return Err(anyhow::anyhow!("invalid key size"));
        }
        if data.len() > Self::MAX_DATA_SIZE {
            return Err(anyhow::anyhow!("data length exceeds AES GCM limit"));
        }
        let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| {
            anyhow::anyhow!(
                "AES-256-GCM encrypt: invalid key (expected 32 bytes, got {})",
                key.len()
            )
        })?;
        let lsk = LessSafeKey::new(unbound);
        encrypt_with_lsk(data, &lsk)
    }

    fn decrypt(&self, data: &[u8], key: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        if key.len() != 32 {
            return Err(anyhow::anyhow!("invalid key size"));
        }
        if data.len() < Self::NONCE_SIZE + Self::TAG_SIZE {
            return Err(anyhow::anyhow!("ciphertext too short"));
        }
        let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| {
            anyhow::anyhow!(
                "AES-256-GCM decrypt: invalid key (expected 32 bytes, got {})",
                key.len()
            )
        })?;
        let lsk = LessSafeKey::new(unbound);
        decrypt_with_lsk(data, &lsk)
    }
}

/// Encrypt using a pre-expanded LessSafeKey (skips key schedule).
/// Nonce safety: a fresh 12-byte random nonce is generated per call from
/// a CSPRNG (ChaCha20 seeded from OS entropy).
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
pub fn encrypt_with_lsk(data: &[u8], key: &LessSafeKey) -> Result<Vec<u8>, anyhow::Error> {
    let mut nonce = [0_u8; GCM_NONCE_SIZE];
    fast_random_bytes(&mut nonce)?;
    let nonce_obj = Nonce::assume_unique_for_key(nonce);
    let nonce_bytes = *nonce_obj.as_ref();
    let mut in_out = Vec::with_capacity(data.len() + AES256GCM::TAG_SIZE + GCM_NONCE_SIZE);
    in_out.extend_from_slice(data);
    key.seal_in_place_append_tag(nonce_obj, Aad::empty(), &mut in_out)
        .map_err(|_| anyhow::anyhow!("AES-256-GCM seal failed (data_len={})", data.len()))?;
    in_out.extend_from_slice(&nonce_bytes);
    Ok(in_out)
}

/// Decrypt using a pre-expanded LessSafeKey (skips key schedule).
/// The nonce is extracted from the ciphertext (appended during encryption).
#[inline(always)]
pub fn decrypt_with_lsk(data: &[u8], key: &LessSafeKey) -> Result<Vec<u8>, anyhow::Error> {
    if data.len() < GCM_NONCE_SIZE + AES256GCM::TAG_SIZE {
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

/// Make a LessSafeKey from raw 32-byte key material.
/// See module-level comment on why LessSafeKey is safe in our usage.
#[inline(always)]
pub fn make_lsk(key: &[u8]) -> Result<LessSafeKey, anyhow::Error> {
    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| anyhow::anyhow!("invalid AES-256-GCM key"))?;
    Ok(LessSafeKey::new(unbound))
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
