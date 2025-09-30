use std::sync::Arc;

use asherah as ael;

// Example: Use AWS KMS for SK/IK encryption
// Requires env: KMS_KEY_ID (and optionally AWS_REGION/AWS creds)
fn main() -> anyhow::Result<()> {
    let key_id = match std::env::var("KMS_KEY_ID") {
        Ok(v) => v,
        Err(_) => return Err(anyhow::anyhow!("Set KMS_KEY_ID to run this example")),
    };

    let region = std::env::var("AWS_REGION").ok();
    let crypto = Arc::new(ael::aead::AES256GCM::new());

    let kms = Arc::new(ael::kms_aws::AwsKms::new(crypto.clone(), key_id, region)?);
    let metastore = Arc::new(ael::metastore::InMemoryMetastore::new());
    let cfg = ael::Config::new("service", "product");

    let factory = ael::api::new_session_factory(cfg, metastore.clone(), kms, crypto.clone());
    let session = factory.get_session("p1");

    let drr = session.encrypt(b"hello-kms")?;
    let pt = session.decrypt(drr)?;
    assert_eq!(pt, b"hello-kms");
    log::info!("AWS KMS example OK");
    Ok(())
}
