#[cfg(feature = "mysql")]
use asherah as ael;
#[cfg(feature = "mysql")]
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    #[cfg(not(feature = "mysql"))]
    {
        eprintln!("Enable with --features mysql");
        return Ok(());
    }
    #[cfg(feature = "mysql")]
    {
        let url = match std::env::var("MYSQL_URL") {
            Ok(v) => v,
            Err(_) => {
                eprintln!("Set MYSQL_URL");
                return Ok(());
            }
        };
        let store = Arc::new(ael::metastore_mysql::MySqlMetastore::connect(&url)?);
        let crypto = Arc::new(ael::aead::AES256GCM::new());
        let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![1u8; 32]));
        let cfg = ael::Config::new("svc", "prod");
        let factory = ael::api::new_session_factory(cfg, store, kms, crypto);
        let s = factory.get_session("p1");
        let drr = s.encrypt(b"mysql-example")?;
        let pt = s.decrypt(drr)?;
        assert_eq!(pt, b"mysql-example");
        println!("mysql example OK");
        Ok(())
    }
}
