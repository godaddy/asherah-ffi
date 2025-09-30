#[cfg(feature = "dynamodb")]
use asherah as ael;
#[cfg(feature = "dynamodb")]
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    #[cfg(not(feature = "dynamodb"))]
    {
        return Err(anyhow::anyhow!("Enable with --features dynamodb"));
    }
    #[cfg(feature = "dynamodb")]
    {
        let table = std::env::var("DDB_TABLE").unwrap_or_else(|_| "ekeys".into());
        let region = std::env::var("AWS_REGION").ok();
        let store = Arc::new(ael::metastore_dynamodb::DynamoDbMetastore::new(
            table, region,
        )?);
        let crypto = Arc::new(ael::aead::AES256GCM::new());
        // StaticKMS for demo (replace with AwsKms for real usage)
        let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![3_u8; 32]));
        let cfg = ael::Config::new("svc", "prod");
        let factory = ael::api::new_session_factory(cfg, store, kms, crypto);
        let s = factory.get_session("p1");
        let drr = s.encrypt(b"ddb-example")?;
        let pt = s.decrypt(drr)?;
        assert_eq!(pt, b"ddb-example");
        log::info!("dynamodb example OK");
        Ok(())
    }
}
