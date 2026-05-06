use std::sync::Arc;

use crate::config::Config;
use crate::session::PublicFactory;
use crate::traits::{KeyManagementService, Metastore, AEAD};

pub fn new_session_factory<
    A: AEAD + Clone,
    K: KeyManagementService + Clone,
    M: Metastore + Clone,
>(
    cfg: Config,
    store: Arc<M>,
    kms: Arc<K>,
    crypto: Arc<A>,
) -> PublicFactory<A, K, M> {
    PublicFactory::new(cfg, store, kms, crypto)
}

/// Options for [`new_session_factory_with_options`]. Mirrors the Go
/// reference's `FactoryOption` pattern.
///
/// `SecretFactory` is a no-op in this Rust port — the page-locked memguard
/// allocator is enabled unconditionally. The variant is retained only for
/// source-level API parity with the Go bindings; passing it has no effect.
/// New code should not match on it.
#[derive(Debug)]
#[allow(clippy::manual_non_exhaustive)]
pub enum FactoryOption {
    /// Enable per-factory metrics collection. Defaults to `true` if no
    /// option is supplied. Disabling skips the per-encrypt
    /// `Instant::now()` and the metrics hook dispatch.
    Metrics(bool),
    /// Reserved for Go-API parity; has no effect in the Rust core. Kept
    /// only so existing call sites that pass `FactoryOption::SecretFactory`
    /// keep compiling.
    #[doc(hidden)]
    SecretFactory,
}

pub fn new_session_factory_with_options<
    A: AEAD + Clone,
    K: KeyManagementService + Clone,
    M: Metastore + Clone,
>(
    cfg: Config,
    store: Arc<M>,
    kms: Arc<K>,
    crypto: Arc<A>,
    opts: &[FactoryOption],
) -> PublicFactory<A, K, M> {
    let mut metrics_enabled = true;
    for opt in opts {
        match opt {
            FactoryOption::Metrics(b) => metrics_enabled = *b,
            FactoryOption::SecretFactory => {}
        }
    }
    PublicFactory::new(cfg, store, kms, crypto).with_metrics(metrics_enabled)
}

pub use new_session_factory as NewSessionFactory;
