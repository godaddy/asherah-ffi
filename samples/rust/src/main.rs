use anyhow::Result;
use asherah::DataRowRecord;
use asherah_config::{factory_from_config, ConfigOptions};

fn main() -> Result<()> {
    // -- Production config (uncomment and set env vars) --
    // std::env::set_var("MYSQL_URL", "mysql://user:pass@host/asherah");
    // std::env::set_var("POSTGRES_URL", "postgres://user:pass@host/asherah");
    // let config = ConfigOptions {
    //     service_name: Some("my-service".into()),
    //     product_id: Some("my-product".into()),
    //     metastore: Some("rdbms".into()),        // "rdbms", "dynamodb", or "memory"
    //     connection_string: Some(std::env::var("MYSQL_URL")?),
    //     kms: Some("aws".into()),
    //     region_map: Some([("us-west-2".into(), "arn:aws:kms:...".into())].into()),
    //     preferred_region: Some("us-west-2".into()),
    //     enable_session_caching: Some(true),
    //     ..Default::default()
    // };

    // -- Local dev config (static master key, in-memory metastore) --
    std::env::set_var(
        "STATIC_MASTER_KEY_HEX",
        "2222222222222222222222222222222222222222222222222222222222222222",
    );
    let config = ConfigOptions {
        service_name: Some("sample-service".into()),
        product_id: Some("sample-product".into()),
        metastore: Some("memory".into()),
        kms: Some("static".into()),
        enable_session_caching: Some(true),
        ..Default::default()
    };

    // ── Factory / Session API ──────────────────────────────────────────
    let (factory, _applied) = factory_from_config(&config)?;
    let session = factory.get_session("user-1234");

    let plaintext = b"Hello from Rust!";
    let drr = session.encrypt(plaintext)?;
    let decrypted = session.decrypt(drr.clone())?;
    assert_eq!(decrypted, plaintext);
    println!("Sync roundtrip OK: {}", String::from_utf8(decrypted)?);

    session.close()?;

    // ── JSON interop ───────────────────────────────────────────────────
    // DataRowRecord serializes to the same JSON shape used by all language bindings.
    let session = factory.get_session("user-5678");
    let drr = session.encrypt(b"cross-language payload")?;

    let json = serde_json::to_string(&drr)?;
    println!("DRR JSON: {json}");

    // Any language binding can deserialize this and decrypt with the same keys.
    let drr_from_json: DataRowRecord = serde_json::from_str(&json)?;
    let recovered = session.decrypt(drr_from_json)?;
    assert_eq!(recovered, b"cross-language payload");
    println!("JSON roundtrip OK");

    session.close()?;

    // ── Async API ──────────────────────────────────────────────────────
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let session = factory.get_session("user-async");

        let drr = session.encrypt_async(b"async payload").await?;
        let decrypted = session.decrypt_async(drr).await?;
        assert_eq!(decrypted, b"async payload");
        println!("Async roundtrip OK: {}", String::from_utf8(decrypted)?);

        session.close()?;
        Ok::<(), anyhow::Error>(())
    })?;

    factory.close()?;
    Ok(())
}
