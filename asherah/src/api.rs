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

// No-op options to mirror Go's FactoryOption pattern
pub enum FactoryOption {
    Metrics(bool),
    SecretFactory, // not applicable in Rust port (memguard-rs is internal)
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
    _opts: &[FactoryOption],
) -> PublicFactory<A, K, M> {
    let mut metrics_enabled = true;
    for opt in _opts {
        match opt {
            FactoryOption::Metrics(b) => metrics_enabled = *b,
            FactoryOption::SecretFactory => {}
        }
    }
    PublicFactory::new(cfg, store, kms, crypto).with_metrics(metrics_enabled)
}

pub use new_session_factory as NewSessionFactory;
