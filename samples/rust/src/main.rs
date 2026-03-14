use anyhow::Result;

fn main() -> Result<()> {
    // A static master key for local development only.
    // In production, use KMS: "aws" with a proper region map.
    std::env::set_var(
        "STATIC_MASTER_KEY_HEX",
        "2222222222222222222222222222222222222222222222222222222222222222",
    );

    let config = asherah_config::ConfigOptions {
        service_name: Some("sample-service".into()),
        product_id: Some("sample-product".into()),
        metastore: Some("memory".into()),
        kms: Some("static".into()),
        enable_session_caching: Some(true),
        ..Default::default()
    };

    let (factory, _applied) = asherah_config::factory_from_config(&config)?;

    let session = factory.get_session("sample-partition");

    // Encrypt
    let plaintext = b"Hello from Rust!";
    let drr = session.encrypt(plaintext)?;
    let drr_json = serde_json::to_string(&drr)?;
    println!("Encrypted: {drr_json}");

    // Decrypt
    let drr_back: asherah::DataRowRecord = serde_json::from_str(&drr_json)?;
    let recovered = session.decrypt(drr_back)?;
    println!("Decrypted: {}", String::from_utf8(recovered)?);

    Ok(())
}
