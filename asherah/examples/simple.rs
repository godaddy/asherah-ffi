use std::sync::Arc;

use asherah as ael;

fn main() -> anyhow::Result<()> {
    // Components
    let crypto = Arc::new(ael::aead::AES256GCM::new());
    let metastore = Arc::new(ael::metastore::InMemoryMetastore::new());
    let kms = Arc::new(ael::kms::StaticKMS::new(crypto.clone(), vec![0_u8; 32]).unwrap());
    let cfg = ael::Config::new("service", "product");

    // Factory and session
    let factory =
        ael::api::new_session_factory(cfg, metastore.clone(), kms.clone(), crypto.clone());
    let session = factory.get_session("partition-1");

    // Encrypt
    let drr = session.encrypt(b"hello asherah")?;

    // Decrypt
    let pt = session.decrypt(drr.clone())?;
    assert_eq!(pt, b"hello asherah");

    // Store/Load with in-memory example
    let store = ael::store::InMemoryStore::new();
    let key = session.store(b"payload", &store)?;
    let out = session.load(&key, &store)?;
    assert_eq!(out, b"payload");

    log::info!("OK");
    Ok(())
}
