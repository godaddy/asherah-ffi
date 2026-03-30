use crate::traits::AEAD as AeadTrait;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
// ring's `LessSafeKey` is named "less safe" only because it does not enforce
// nonce uniqueness at the type level — the caller is responsible for never
// reusing a nonce with the same key. Our usage is safe:
//
// - Data encryption (encrypt_with_lsk): generates a fresh 12-byte random nonce
//   from a ChaCha20-based CSPRNG seeded from OS entropy. With 96-bit random
//   nonces, the birthday-bound collision probability is negligible (~2^-32
//   after 2^32 encryptions under the same key).
//
// - Enclave sealing (memguard.rs): uses a monotonic atomic counter, which
//   guarantees uniqueness without randomness.
//
// ring's alternative (`SealingKey` with `NonceSequence`) would add overhead
// for nonce tracking that we don't need — our nonce strategy is already sound.
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

// Thread-local ChaCha20Rng seeded from OsRng (avoids getrandom syscall per call)
thread_local! {
    static FAST_RNG: RefCell<ChaCha20Rng> = RefCell::new({
        use rand::SeedableRng;
        ChaCha20Rng::from_os_rng()
    });
}

/// Use the thread-local fast CSPRNG.
#[inline(always)]
pub fn fast_rng<R>(f: impl FnOnce(&mut ChaCha20Rng) -> R) -> R {
    FAST_RNG.with(|cell| f(&mut cell.borrow_mut()))
}

/// Fill a buffer with random bytes using the thread-local CSPRNG.
#[inline(always)]
pub fn fast_random_bytes(buf: &mut [u8]) {
    fast_rng(|rng| rng.fill_bytes(buf));
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
#[inline(always)]
pub fn encrypt_with_lsk(data: &[u8], key: &LessSafeKey) -> Result<Vec<u8>, anyhow::Error> {
    let mut nonce = [0_u8; GCM_NONCE_SIZE];
    fast_random_bytes(&mut nonce);
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
