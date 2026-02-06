#[cfg(feature = "sqlite")]
use asherah as ael;
#[cfg(feature = "sqlite")]
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(feature = "sqlite"))]
    {
        return Err("Enable with --features sqlite".into());
    }
    #[cfg(feature = "sqlite")]
    {
        // SQLite metastore
        let store = Arc::new(ael::metastore_sqlite::SqliteMetastore::open(":memory:")?);

        let crypto = Arc::new(ael::aead::AES256GCM::new());
        let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![9_u8; 32]).unwrap());
        let cfg = ael::Config::new("svc", "prod");

        let factory =
            ael::api::new_session_factory(cfg, store.clone(), kms.clone(), crypto.clone());
        let session = factory.get_session("p1");

        let drr = session.encrypt(b"db-backed-example")?;
        // Simulate storing drr in DB
        // Re-create factory/session and decrypt
        let factory2 =
            ael::api::new_session_factory(ael::Config::new("svc", "prod"), store, kms, crypto);
        let session2 = factory2.get_session("p1");
        let pt = session2.decrypt(drr)?;
        assert_eq!(pt, b"db-backed-example");
        log::info!("sqlite example OK");
        Ok(())
    }
}
