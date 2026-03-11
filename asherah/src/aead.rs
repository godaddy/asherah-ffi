use crate::traits::AEAD as AeadTrait;
use rand::TryRngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

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
        let key = LessSafeKey::new(unbound);
        let mut nonce = [0_u8; GCM_NONCE_SIZE];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| anyhow::anyhow!("AES-256-GCM encrypt: nonce generation failed: {e}"))?;
        let nonce_obj = Nonce::assume_unique_for_key(nonce);
        let nonce_bytes = *nonce_obj.as_ref();
        let mut in_out = Vec::with_capacity(data.len() + Self::TAG_SIZE);
        in_out.extend_from_slice(data);
        key.seal_in_place_append_tag(nonce_obj, Aad::empty(), &mut in_out)
            .map_err(|_| anyhow::anyhow!("AES-256-GCM seal failed (data_len={})", data.len()))?;
        in_out.extend_from_slice(&nonce_bytes);
        Ok(in_out)
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
        let key = LessSafeKey::new(unbound);
        let nonce_pos = data.len() - GCM_NONCE_SIZE;
        let (ct_with_tag, nonce_bytes) = data.split_at(nonce_pos);
        if ct_with_tag.len() < Self::TAG_SIZE {
            return Err(anyhow::anyhow!(
                "AES-256-GCM decrypt: ciphertext missing tag (ct_len={})",
                ct_with_tag.len()
            ));
        }
        if ct_with_tag.len() - Self::TAG_SIZE > Self::MAX_DATA_SIZE {
            return Err(anyhow::anyhow!(
                "AES-256-GCM decrypt: ciphertext exceeds limit (ct_len={})",
                ct_with_tag.len()
            ));
        }
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
        Ok(pt.to_vec())
    }
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
