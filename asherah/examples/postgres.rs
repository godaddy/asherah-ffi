#[cfg(feature = "postgres")]
use asherah as ael;
#[cfg(feature = "postgres")]
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    #[cfg(not(feature = "postgres"))]
    {
        eprintln!("Enable with --features postgres");
        return Ok(());
    }
    #[cfg(feature = "postgres")]
    {
        let url = match std::env::var("POSTGRES_URL") {
            Ok(v) => v,
            Err(_) => {
                eprintln!("Set POSTGRES_URL");
                return Ok(());
            }
        };
        let store = Arc::new(ael::metastore_postgres::PostgresMetastore::connect(&url)?);
        let crypto = Arc::new(ael::aead::AES256GCM::new());
        let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![2u8; 32]));
        let cfg = ael::Config::new("svc", "prod");
        let factory = ael::api::new_session_factory(cfg, store, kms, crypto);
        let s = factory.get_session("p1");
        let drr = s.encrypt(b"pg-example")?;
        let pt = s.decrypt(drr)?;
        assert_eq!(pt, b"pg-example");
        println!("postgres example OK");
        Ok(())
    }
}
