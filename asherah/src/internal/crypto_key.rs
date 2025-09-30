use crate::memguard::LockedBuffer;

#[derive(Debug)]
pub struct CryptoKey {
    created: i64,
    revoked: bool,
    secret: LockedBuffer,
}

impl CryptoKey {
    pub fn new(created: i64, revoked: bool, bytes: Vec<u8>) -> anyhow::Result<Self> {
        let buf =
            LockedBuffer::from_bytes(bytes).map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?;
        Ok(Self {
            created,
            revoked,
            secret: buf,
        })
    }
    pub fn created(&self) -> i64 {
        self.created
    }
    pub fn revoked(&self) -> bool {
        self.revoked
    }
    pub fn with_key_func<R>(&self, f: impl FnOnce(&[u8]) -> R) -> anyhow::Result<R> {
        self.secret
            .with_bytes(|b| f(b))
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
    }
}

pub fn generate_key(created: i64) -> anyhow::Result<CryptoKey> {
    let mut raw = vec![0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    CryptoKey::new(created, false, raw)
}

pub fn is_key_expired(created_s: i64, expire_after_s: i64, now_s: i64) -> bool {
    now_s - created_s >= expire_after_s
}

use rand::RngCore;
