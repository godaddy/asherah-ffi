use crate::memguard::{wipe_bytes, Buffer, Enclave};

#[derive(Debug)]
pub struct CryptoKey {
    created: i64,
    revoked: bool,
    secret: Enclave,
}

impl CryptoKey {
    pub fn new(created: i64, revoked: bool, mut bytes: Vec<u8>) -> anyhow::Result<Self> {
        let mut buf = Buffer::new(bytes.len()).map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?;
        buf.bytes().copy_from_slice(&bytes);
        wipe_bytes(&mut bytes);
        let enclave =
            Enclave::new_from(&mut buf).map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?;
        Ok(Self {
            created,
            revoked,
            secret: enclave,
        })
    }
    pub fn created(&self) -> i64 {
        self.created
    }
    pub fn revoked(&self) -> bool {
        self.revoked
    }
    pub fn with_key_func<R>(&self, f: impl FnOnce(&[u8]) -> R) -> anyhow::Result<R> {
        let buf = self
            .secret
            .open()
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?;
        let result = f(buf.as_slice());
        crate::memguard::pool_release(buf);
        Ok(result)
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
