use std::sync::Arc;

use async_trait::async_trait;

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

#[async_trait]
impl KeyManagementService for MultiKms {
    fn encrypt_key(&self, ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        self.backends[self.preferred]
            .encrypt_key(ctx, key_bytes)
            .map_err(|e| {
                log::error!(
                    "MultiKms encrypt_key failed on preferred backend {}: {e:#}",
                    self.preferred
                );
                e
            })
    }

    fn decrypt_key(&self, ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let mut errors: Vec<String> = Vec::new();
        // Try preferred first, then fallbacks
        match self.backends[self.preferred].decrypt_key(ctx, blob) {
            Ok(pt) => return Ok(pt),
            Err(e) => {
                log::warn!(
                    "MultiKms decrypt_key: preferred backend {} failed: {e:#}",
                    self.preferred
                );
                if is_terminal_kms_error(&e) {
                    log::error!(
                        "MultiKms decrypt_key: preferred backend returned a terminal \
                         error ({e:#}); aborting fallback to avoid spurious cross-region \
                         KMS calls"
                    );
                    return Err(anyhow::anyhow!(
                        "preferred KMS backend failed terminally: {e}"
                    ));
                }
                errors.push(format!("backend[{}]: {e}", self.preferred));
            }
        }
        for (i, kms) in self.backends.iter().enumerate() {
            if i == self.preferred {
                continue;
            }
            match kms.decrypt_key(ctx, blob) {
                Ok(pt) => return Ok(pt),
                Err(e) => {
                    log::warn!("MultiKms decrypt_key: backend {i} failed: {e:#}");
                    if is_terminal_kms_error(&e) {
                        log::error!(
                            "MultiKms decrypt_key: backend {i} returned a terminal \
                             error ({e:#}); aborting fallback"
                        );
                        return Err(anyhow::anyhow!("KMS backend {i} failed terminally: {e}"));
                    }
                    errors.push(format!("backend[{i}]: {e}"));
                }
            }
        }
        let detail = errors.join("; ");
        log::error!("MultiKms decrypt_key: all backends failed: {detail}");
        Err(anyhow::anyhow!(
            "all KMS backends failed to decrypt: {detail}"
        ))
    }

    /// Async encrypt on the preferred backend. Overrides the trait default
    /// (which would call the *sync* `encrypt_key` and block a worker /
    /// panic on a current-thread runtime when the backend is AWS KMS) so the
    /// backend's native async path is awaited instead.
    async fn encrypt_key_async(
        &self,
        ctx: &(),
        key_bytes: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        self.backends[self.preferred]
            .encrypt_key_async(ctx, key_bytes)
            .await
            .map_err(|e| {
                log::error!(
                    "MultiKms encrypt_key_async failed on preferred backend {}: {e:#}",
                    self.preferred
                );
                e
            })
    }

    /// Async decrypt mirroring the sync `decrypt_key` fallback policy — try
    /// the preferred backend, then the rest — but awaiting each backend's
    /// native async path. Terminal errors (AccessDenied, InvalidKey, …) abort
    /// the fallback exactly as in the sync path.
    async fn decrypt_key_async(&self, ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let mut errors: Vec<String> = Vec::new();
        match self.backends[self.preferred]
            .decrypt_key_async(ctx, blob)
            .await
        {
            Ok(pt) => return Ok(pt),
            Err(e) => {
                log::warn!(
                    "MultiKms decrypt_key_async: preferred backend {} failed: {e:#}",
                    self.preferred
                );
                if is_terminal_kms_error(&e) {
                    log::error!(
                        "MultiKms decrypt_key_async: preferred backend returned a terminal \
                         error ({e:#}); aborting fallback to avoid spurious cross-region \
                         KMS calls"
                    );
                    return Err(anyhow::anyhow!(
                        "preferred KMS backend failed terminally: {e}"
                    ));
                }
                errors.push(format!("backend[{}]: {e}", self.preferred));
            }
        }
        for (i, kms) in self.backends.iter().enumerate() {
            if i == self.preferred {
                continue;
            }
            match kms.decrypt_key_async(ctx, blob).await {
                Ok(pt) => return Ok(pt),
                Err(e) => {
                    log::warn!("MultiKms decrypt_key_async: backend {i} failed: {e:#}");
                    if is_terminal_kms_error(&e) {
                        log::error!(
                            "MultiKms decrypt_key_async: backend {i} returned a terminal \
                             error ({e:#}); aborting fallback"
                        );
                        return Err(anyhow::anyhow!("KMS backend {i} failed terminally: {e}"));
                    }
                    errors.push(format!("backend[{i}]: {e}"));
                }
            }
        }
        let detail = errors.join("; ");
        log::error!("MultiKms decrypt_key_async: all backends failed: {detail}");
        Err(anyhow::anyhow!(
            "all KMS backends failed to decrypt: {detail}"
        ))
    }
}

/// Heuristic: distinguish errors where retrying another region/backend
/// is pointless (AccessDenied, InvalidKey, NotAuthorized — the caller's
/// identity won't suddenly gain permission in a different region) from
/// errors that warrant a fallback (InvalidCiphertext, Throttling,
/// ServerError, network).
///
/// We can't pattern-match on AWS SDK typed variants because `MultiKms`
/// is generic over `dyn KeyManagementService`. Falls back to substring
/// matching on the error chain — best-effort, errs on the side of
/// continuing the fallback when uncertain (T-finding "blindly retries
/// every backend on any error" in `docs/review-2026-05-05-findings.md`).
fn is_terminal_kms_error(err: &anyhow::Error) -> bool {
    let chain = format!("{err:#}");
    let needles: &[&str] = &[
        "AccessDenied",
        "AccessDeniedException",
        "NotAuthorized",
        "InvalidKey",
        "DisabledException",
        "KMSInvalidKeyUsageException",
    ];
    needles.iter().any(|n| chain.contains(n))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone)]
    struct DummyKms(&'static AtomicUsize, usize); // (counter, id)
    #[async_trait]
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

    #[derive(Clone)]
    struct AwsLikeFallbackKms {
        counter: &'static AtomicUsize,
        id: u8,
        err: &'static str,
    }

    #[async_trait]
    impl KeyManagementService for AwsLikeFallbackKms {
        fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
            self.counter.fetch_add(1, Ordering::Relaxed);
            let mut out = vec![self.id];
            out.extend_from_slice(key_bytes);
            Ok(out)
        }

        fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
            self.counter.fetch_add(1, Ordering::Relaxed);
            if blob.first().copied() == Some(self.id) {
                Ok(blob[1..].to_vec())
            } else {
                Err(anyhow::anyhow!("{}", self.err))
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
    fn multi_kms_fallbacks_after_invalid_ciphertext_exception() -> anyhow::Result<()> {
        static WRONG: AtomicUsize = AtomicUsize::new(0);
        static RIGHT: AtomicUsize = AtomicUsize::new(0);

        let wrong: Arc<dyn KeyManagementService> = Arc::new(AwsLikeFallbackKms {
            counter: &WRONG,
            id: 1,
            err: "InvalidCiphertextException: ciphertext was not encrypted by this key",
        });
        let right: Arc<dyn KeyManagementService> = Arc::new(AwsLikeFallbackKms {
            counter: &RIGHT,
            id: 2,
            err: "wrong region",
        });

        let encrypted = right.encrypt_key(&(), b"region secret")?;
        let multi = MultiKms::new(0, vec![wrong, right])?;
        let out = multi.decrypt_key(&(), &encrypted)?;

        assert_eq!(out, b"region secret");
        assert_eq!(WRONG.load(Ordering::Relaxed), 1);
        assert_eq!(RIGHT.load(Ordering::Relaxed), 2);
        Ok(())
    }

    #[test]
    fn multi_kms_still_aborts_on_access_denied() {
        static DENIED: AtomicUsize = AtomicUsize::new(0);
        static FALLBACK: AtomicUsize = AtomicUsize::new(0);

        let denied: Arc<dyn KeyManagementService> = Arc::new(AwsLikeFallbackKms {
            counter: &DENIED,
            id: 1,
            err: "AccessDeniedException: caller is not authorized",
        });
        let fallback: Arc<dyn KeyManagementService> = Arc::new(AwsLikeFallbackKms {
            counter: &FALLBACK,
            id: 2,
            err: "wrong region",
        });
        let encrypted = fallback.encrypt_key(&(), b"secret").unwrap();
        FALLBACK.store(0, Ordering::Relaxed);

        let multi = MultiKms::new(0, vec![denied, fallback]).unwrap();
        let err = multi.decrypt_key(&(), &encrypted).unwrap_err();

        assert!(format!("{err:#}").contains("terminally"));
        assert_eq!(DENIED.load(Ordering::Relaxed), 1);
        assert_eq!(
            FALLBACK.load(Ordering::Relaxed),
            0,
            "AccessDenied must not fan out to later KMS backends"
        );
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
            err_msg.contains("all KMS backends failed to decrypt:"),
            "expected 'all KMS backends failed to decrypt:', got: {err_msg}"
        );
    }

    // ── async path ────────────────────────────────────────────────────────
    // A backend that counts sync vs async calls separately, so the async tests
    // can assert the `*_async` overrides delegate to the backend's async path
    // (sync_calls stays 0) rather than falling through the trait default to the
    // sync method.
    #[derive(Clone)]
    struct CountingKms {
        sync_calls: &'static AtomicUsize,
        async_calls: &'static AtomicUsize,
        id: u8,
        err: &'static str,
    }

    #[async_trait]
    impl KeyManagementService for CountingKms {
        fn encrypt_key(&self, _ctx: &(), key_bytes: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
            self.sync_calls.fetch_add(1, Ordering::Relaxed);
            let mut v = vec![self.id];
            v.extend_from_slice(key_bytes);
            Ok(v)
        }
        fn decrypt_key(&self, _ctx: &(), blob: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
            self.sync_calls.fetch_add(1, Ordering::Relaxed);
            if blob.first().copied() == Some(self.id) {
                Ok(blob[1..].to_vec())
            } else {
                Err(anyhow::anyhow!("{}", self.err))
            }
        }
        async fn encrypt_key_async(
            &self,
            _ctx: &(),
            key_bytes: &[u8],
        ) -> Result<Vec<u8>, anyhow::Error> {
            self.async_calls.fetch_add(1, Ordering::Relaxed);
            let mut v = vec![self.id];
            v.extend_from_slice(key_bytes);
            Ok(v)
        }
        async fn decrypt_key_async(
            &self,
            _ctx: &(),
            blob: &[u8],
        ) -> Result<Vec<u8>, anyhow::Error> {
            self.async_calls.fetch_add(1, Ordering::Relaxed);
            if blob.first().copied() == Some(self.id) {
                Ok(blob[1..].to_vec())
            } else {
                Err(anyhow::anyhow!("{}", self.err))
            }
        }
    }

    #[tokio::test]
    async fn multi_kms_async_encrypt_uses_preferred_backend_async_path() {
        static SYNC: AtomicUsize = AtomicUsize::new(0);
        static ASYNC: AtomicUsize = AtomicUsize::new(0);
        let backend: Arc<dyn KeyManagementService> = Arc::new(CountingKms {
            sync_calls: &SYNC,
            async_calls: &ASYNC,
            id: 1,
            err: "n/a",
        });
        let mk = MultiKms::new(0, vec![backend]).unwrap();

        let blob = mk.encrypt_key_async(&(), b"secret").await.unwrap();
        assert_eq!(blob[0], 1, "should encrypt on preferred backend");
        assert_eq!(ASYNC.load(Ordering::Relaxed), 1, "async path must be used");
        assert_eq!(
            SYNC.load(Ordering::Relaxed),
            0,
            "sync method must NOT be called on the async path"
        );
    }

    #[tokio::test]
    async fn multi_kms_async_decrypt_fallbacks_on_async_path() {
        static SYNC: AtomicUsize = AtomicUsize::new(0);
        static ASYNC: AtomicUsize = AtomicUsize::new(0);
        // Encrypt under region id=2.
        let right: Arc<dyn KeyManagementService> = Arc::new(CountingKms {
            sync_calls: &SYNC,
            async_calls: &ASYNC,
            id: 2,
            err: "wrong region",
        });
        let blob = right
            .encrypt_key_async(&(), b"region secret")
            .await
            .unwrap();
        ASYNC.store(0, Ordering::Relaxed);

        // Preferred backend (id=1) is wrong → must fall back to id=2.
        let wrong: Arc<dyn KeyManagementService> = Arc::new(CountingKms {
            sync_calls: &SYNC,
            async_calls: &ASYNC,
            id: 1,
            err: "wrong region",
        });
        let mk = MultiKms::new(0, vec![wrong, right]).unwrap();
        let out = mk.decrypt_key_async(&(), &blob).await.unwrap();

        assert_eq!(out, b"region secret");
        assert_eq!(
            ASYNC.load(Ordering::Relaxed),
            2,
            "both backends tried via the async path"
        );
        assert_eq!(
            SYNC.load(Ordering::Relaxed),
            0,
            "sync path must not be used"
        );
    }

    #[tokio::test]
    async fn multi_kms_async_decrypt_aborts_on_terminal_error() {
        static DSYNC: AtomicUsize = AtomicUsize::new(0);
        static DASYNC: AtomicUsize = AtomicUsize::new(0);
        static FSYNC: AtomicUsize = AtomicUsize::new(0);
        static FASYNC: AtomicUsize = AtomicUsize::new(0);
        let denied: Arc<dyn KeyManagementService> = Arc::new(CountingKms {
            sync_calls: &DSYNC,
            async_calls: &DASYNC,
            id: 1,
            err: "AccessDeniedException: caller is not authorized",
        });
        let fallback: Arc<dyn KeyManagementService> = Arc::new(CountingKms {
            sync_calls: &FSYNC,
            async_calls: &FASYNC,
            id: 2,
            err: "wrong region",
        });
        let blob = fallback.encrypt_key_async(&(), b"secret").await.unwrap();
        FASYNC.store(0, Ordering::Relaxed);

        let mk = MultiKms::new(0, vec![denied, fallback]).unwrap();
        let err = mk.decrypt_key_async(&(), &blob).await.unwrap_err();

        assert!(format!("{err:#}").contains("terminally"));
        assert_eq!(DASYNC.load(Ordering::Relaxed), 1, "preferred tried once");
        assert_eq!(
            FASYNC.load(Ordering::Relaxed),
            0,
            "AccessDenied must not fan out to later backends on the async path"
        );
    }
}
