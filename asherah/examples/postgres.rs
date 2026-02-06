#[cfg(feature = "postgres")]
use asherah as ael;
#[cfg(feature = "postgres")]
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    #[cfg(not(feature = "postgres"))]
    {
        return Err(anyhow::anyhow!("Enable with --features postgres"));
    }
    #[cfg(feature = "postgres")]
    {
        let url = match std::env::var("POSTGRES_URL") {
            Ok(v) => v,
            Err(_) => return Err(anyhow::anyhow!("Set POSTGRES_URL")),
        };
        let store = Arc::new(ael::metastore_postgres::PostgresMetastore::connect(&url)?);
        let crypto = Arc::new(ael::aead::AES256GCM::new());
        let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![2_u8; 32]).unwrap());
        let cfg = ael::Config::new("svc", "prod");
        let factory = ael::api::new_session_factory(cfg, store, kms, crypto);
        let s = factory.get_session("p1");
        let drr = s.encrypt(b"pg-example")?;
        let pt = s.decrypt(drr)?;
        assert_eq!(pt, b"pg-example");
        log::info!("postgres example OK");
        Ok(())
    }
}
