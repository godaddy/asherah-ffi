#![allow(unsafe_code)]

pub mod aead;
pub mod api;
pub mod builders;
pub mod cache;
pub mod config;
pub mod internal;
pub mod kms;
pub mod kms_aws;
pub mod kms_aws_envelope;
pub mod kms_builders;
pub mod kms_multi;
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
pub mod partition;
pub mod policy;
pub mod session;
pub mod session_cache;
pub mod store;
pub mod traits;
pub mod types;
// Embedded low-level libs
pub mod memcall;
pub mod memguard;

pub use api::new_session_factory_with_options as NewSessionFactoryWithOptions;
pub use api::{FactoryOption, NewSessionFactory};
pub use config::Config;
pub use policy::CryptoPolicy;
pub use session::{PublicFactory as SessionFactory, PublicSession as Session};
pub use traits::{KeyManagementService, Metastore, Partition, AEAD};
pub use types::{DataRowRecord, EnvelopeKeyRecord, KeyMeta};

// Optional Encryption trait mirroring Go's interface
pub trait Encryption {
    fn encrypt(&self, data: &[u8]) -> anyhow::Result<types::DataRowRecord>;
    fn decrypt(&self, drr: types::DataRowRecord) -> anyhow::Result<Vec<u8>>;
    fn close(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<A, K, M> Encryption for session::PublicSession<A, K, M>
where
    A: traits::AEAD + Clone,
    K: traits::KeyManagementService + Clone,
    M: traits::Metastore + Clone,
{
    fn encrypt(&self, data: &[u8]) -> anyhow::Result<types::DataRowRecord> {
        session::PublicSession::<A, K, M>::encrypt(self, data)
    }
    fn decrypt(&self, drr: types::DataRowRecord) -> anyhow::Result<Vec<u8>> {
        session::PublicSession::<A, K, M>::decrypt(self, drr)
    }
    fn close(&self) -> anyhow::Result<()> {
        session::PublicSession::<A, K, M>::close(self)
    }
}

pub trait EncryptionCtx {
    fn encrypt_ctx(&self, ctx: &(), data: &[u8]) -> anyhow::Result<types::DataRowRecord>;
    fn decrypt_ctx(&self, ctx: &(), drr: types::DataRowRecord) -> anyhow::Result<Vec<u8>>;
    fn close_ctx(&self, _ctx: &()) -> anyhow::Result<()> {
        Ok(())
    }
}

impl<A, K, M> EncryptionCtx for session::PublicSession<A, K, M>
where
    A: traits::AEAD + Clone,
    K: traits::KeyManagementService + Clone,
    M: traits::Metastore + Clone,
{
    fn encrypt_ctx(&self, ctx: &(), data: &[u8]) -> anyhow::Result<types::DataRowRecord> {
        session::PublicSession::<A, K, M>::encrypt_ctx(self, ctx, data)
    }
    fn decrypt_ctx(&self, ctx: &(), drr: types::DataRowRecord) -> anyhow::Result<Vec<u8>> {
        session::PublicSession::<A, K, M>::decrypt_ctx(self, ctx, drr)
    }
}
