use std::sync::Arc;

use crate::traits::KeyManagementService;

// A composite KMS that routes Encrypt to a preferred region KMS and Decrypt tries all KMSs until success.
#[derive(Clone)]
pub struct MultiKms {
    preferred: usize,
    backends: Vec<Arc<dyn KeyManagementService>>, // different regions
}

impl MultiKms {
    pub fn new(
        preferred: usize,
        backends: Vec<Arc<dyn KeyManagementService>>,
    ) -> anyhow::Result<Self> {
        if backends.is_empty() {
            return Err(anyhow::anyhow!("no KMS backends provided"));
        }
        let idx = if preferred < backends.len() {
            preferred
        } else {
            0
        };
        Ok(Self {
            preferred: idx,
            backends,
        })
    }
}

impl KeyManagementService for MultiKms {
    fn encrypt_key(&self, ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.backends[self.preferred].encrypt_key(ctx, key_bytes)
    }

    fn decrypt_key(&self, ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        // Try preferred first, then fallbacks
        if let Ok(pt) = self.backends[self.preferred].decrypt_key(ctx, blob) {
            return Ok(pt);
        }
        for (i, kms) in self.backends.iter().enumerate() {
            if i == self.preferred {
                continue;
            }
            if let Ok(pt) = kms.decrypt_key(ctx, blob) {
                return Ok(pt);
            }
        }
        Err(anyhow::anyhow!("all KMS backends failed to decrypt"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct DummyKms(&'static AtomicUsize, usize); // (counter, id)
    impl KeyManagementService for DummyKms {
        fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
            self.0.fetch_add(1, Ordering::Relaxed);
            // prefix id to simulate region
            let mut v = vec![self.1 as u8];
            v.extend_from_slice(key_bytes);
            Ok(v)
        }
        fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
            if blob.first().copied() == Some(self.1 as u8) {
                Ok(blob[1..].to_vec())
            } else {
                Err(anyhow::anyhow!("wrong region"))
            }
        }
    }

    #[test]
    fn multi_kms_pref_encrypts_on_preferred_and_fallbacks_on_decrypt() {
        static C1: AtomicUsize = AtomicUsize::new(0);
        static C2: AtomicUsize = AtomicUsize::new(0);
        let kms1: Arc<dyn KeyManagementService> = Arc::new(DummyKms(&C1, 1));
        let kms2: Arc<dyn KeyManagementService> = Arc::new(DummyKms(&C2, 2));
        let mk = MultiKms::new(0, vec![kms1.clone(), kms2.clone()]).unwrap();
        let pt = b"secret";
        let blob = mk.encrypt_key(&(), pt).unwrap();
        assert_eq!(C1.load(Ordering::Relaxed), 1);
        // Decrypt with a different backend via a new MultiKms pref index 1
        let mk2 = MultiKms::new(1, vec![kms1, kms2]).unwrap();
        let out = mk2.decrypt_key(&(), &blob).unwrap();
        assert_eq!(out, pt);
    }
}
