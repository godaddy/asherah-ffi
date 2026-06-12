//! # Asherah
//!
//! Application-layer envelope encryption with automatic key rotation.
//!
//! This crate provides the core encryption engine, key hierarchy management,
//! metastore adapters (DynamoDB, MySQL, Postgres, SQLite, in-memory), and
//! KMS backends (AWS KMS, static for testing). All secret key material is
//! protected with hardware-enclave memory and zeroized on drop.
//!
//! ## Feature Flags
//!
//! - `sqlite` — SQLite metastore adapter
//! - `mysql` — MySQL metastore adapter
//! - `postgres` — Postgres metastore adapter
//! - `dynamodb` — DynamoDB metastore adapter (async via AWS SDK)

#![allow(unsafe_code)]

pub mod aead;
pub mod api;
pub mod builders;
pub mod cache;
pub mod config;
pub mod config_drift_guard;
pub mod internal;
pub mod kms;
pub mod kms_aws;
pub mod kms_aws_envelope;
pub mod kms_builders;
pub mod kms_multi;
#[cfg(feature = "secrets-manager")]
pub mod kms_secrets_manager;
#[cfg(feature = "vault")]
pub mod kms_vault_transit;
pub mod limits;
pub mod logging;
pub mod metastore;
#[cfg(feature = "dynamodb")]
pub mod metastore_dynamodb;
#[cfg(feature = "mysql")]
pub mod metastore_mysql;
#[cfg(feature = "postgres")]
pub mod metastore_postgres;
pub mod metastore_region;
#[cfg(feature = "sqlite")]
pub mod metastore_sqlite;
pub mod metrics;
pub mod microarchitecture;
// `partition` exposes `DefaultPartition`, an implementation detail
// used by integration tests inside the same workspace. `#[doc(hidden)]`
// keeps it off the public API surface (rustdoc landing page) without
// breaking the tests that import it. T-finding "Most modules pub;
// many implementation-detail should be pub(crate) or #[doc(hidden)]"
// in `docs/review-2026-05-05-findings.md`.
#[doc(hidden)]
pub mod partition;
pub mod policy;
#[cfg(feature = "mysql")]
pub mod pool_mysql;
pub mod process_hardening;
pub mod session;
/// Implementation-detail of `session.rs` — caches `PublicSession`
/// instances by partition. External callers should use the
/// session-cache config knobs on `CryptoPolicy`.
#[doc(hidden)]
pub mod session_cache;
/// Implementation-detail in-memory data store used by integration
/// tests. External callers should use `metastore::InMemoryMetastore`
/// for a metastore-shaped equivalent.
#[doc(hidden)]
pub mod store;
pub mod traits;
pub mod types;
// Crate-private helpers (not re-exported)
mod aws_sdk_load;

pub use api::new_session_factory_with_options as NewSessionFactoryWithOptions;
pub use api::{FactoryOption, NewSessionFactory};
pub use config::Config;
pub use policy::CryptoPolicy;
pub use session::{PublicFactory as SessionFactory, PublicSession as Session};
pub use traits::{KeyManagementService, Metastore, Partition, AEAD};
pub use types::{DataRowRecord, EnvelopeKeyRecord, KeyMeta};

// Optional Encryption trait mirroring Go's interface
pub trait Encryption {
    fn encrypt(&self, data: &[u8]) -> anyhow::Result<DataRowRecord>;
    fn decrypt(&self, drr: DataRowRecord) -> anyhow::Result<Vec<u8>>;
    fn close(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<A, K, M> Encryption for session::PublicSession<A, K, M>
where
    A: AEAD + Clone,
    K: KeyManagementService + Clone,
    M: Metastore + Clone,
{
    fn encrypt(&self, data: &[u8]) -> anyhow::Result<DataRowRecord> {
        session::PublicSession::<A, K, M>::encrypt(self, data)
    }
    fn decrypt(&self, drr: DataRowRecord) -> anyhow::Result<Vec<u8>> {
        session::PublicSession::<A, K, M>::decrypt(self, drr)
    }
    fn close(&self) -> anyhow::Result<()> {
        session::PublicSession::<A, K, M>::close(self)
    }
}

pub trait EncryptionCtx {
    fn encrypt_ctx(&self, ctx: &(), data: &[u8]) -> anyhow::Result<DataRowRecord>;
    fn decrypt_ctx(&self, ctx: &(), drr: DataRowRecord) -> anyhow::Result<Vec<u8>>;
    fn close_ctx(&self, _ctx: &()) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<A, K, M> EncryptionCtx for session::PublicSession<A, K, M>
where
    A: AEAD + Clone,
    K: KeyManagementService + Clone,
    M: Metastore + Clone,
{
    fn encrypt_ctx(&self, ctx: &(), data: &[u8]) -> anyhow::Result<DataRowRecord> {
        session::PublicSession::<A, K, M>::encrypt_ctx(self, ctx, data)
    }
    fn decrypt_ctx(&self, ctx: &(), drr: DataRowRecord) -> anyhow::Result<Vec<u8>> {
        session::PublicSession::<A, K, M>::decrypt_ctx(self, ctx, drr)
    }
}
