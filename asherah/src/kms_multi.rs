use std::sync::Arc;

use crate::traits::KeyManagementService;

// A composite KMS that routes Encrypt to a preferred region KMS and Decrypt tries all KMSs until success.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
    fn multi_kms_pref_encrypts_on_preferred_and_fallbacks_on_decrypt() -> anyhow::Result<()> {
        static C1: AtomicUsize = AtomicUsize::new(0);
        static C2: AtomicUsize = AtomicUsize::new(0);
        let kms1: Arc<dyn KeyManagementService> = Arc::new(DummyKms(&C1, 1));
        let kms2: Arc<dyn KeyManagementService> = Arc::new(DummyKms(&C2, 2));
        let mk = MultiKms::new(0, vec![kms1.clone(), kms2.clone()])?;
        let pt = b"secret";
        let blob = mk.encrypt_key(&(), pt)?;
        assert_eq!(C1.load(Ordering::Relaxed), 1);
        // Decrypt with a different backend via a new MultiKms pref index 1
        let mk2 = MultiKms::new(1, vec![kms1, kms2])?;
        let out = mk2.decrypt_key(&(), &blob)?;
        assert_eq!(out, pt);
        Ok(())
    }

    #[test]
    fn multi_kms_empty_backends_fails() {
        let result = MultiKms::new(0, vec![]);
        let err_msg = result.err().expect("should be Err").to_string();
        assert!(
            err_msg.contains("no KMS backends provided"),
            "expected 'no KMS backends provided', got: {err_msg}"
        );
    }

    #[test]
    fn multi_kms_preferred_out_of_bounds_clamps_to_zero() {
        static C3: AtomicUsize = AtomicUsize::new(0);
        let kms1: Arc<dyn KeyManagementService> = Arc::new(DummyKms(&C3, 1));
        let mk = MultiKms::new(999, vec![kms1]).unwrap();
        let blob = mk.encrypt_key(&(), b"data").unwrap();
        // DummyKms with id=1 prefixes 0x01
        assert_eq!(
            blob[0], 1,
            "should use backend at index 0 (region prefix 1)"
        );
    }

    #[test]
    fn multi_kms_all_backends_fail_returns_error() {
        static C4: AtomicUsize = AtomicUsize::new(0);
        static C5: AtomicUsize = AtomicUsize::new(0);
        static C6: AtomicUsize = AtomicUsize::new(0);

        // Encrypt with region id=3
        let encryptor: Arc<dyn KeyManagementService> = Arc::new(DummyKms(&C4, 3));
        let blob = encryptor.encrypt_key(&(), b"secret").unwrap();

        // Build a MultiKms with two backends that use different region ids (1 and 2)
        let kms1: Arc<dyn KeyManagementService> = Arc::new(DummyKms(&C5, 1));
        let kms2: Arc<dyn KeyManagementService> = Arc::new(DummyKms(&C6, 2));
        let mk = MultiKms::new(0, vec![kms1, kms2]).unwrap();

        let result = mk.decrypt_key(&(), &blob);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("all KMS backends failed to decrypt"),
            "expected 'all KMS backends failed to decrypt', got: {err_msg}"
        );
    }
}
