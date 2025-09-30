use asherah as ael;

fn main() -> anyhow::Result<()> {
    // Build from environment; see README for supported variables
    let factory = ael::builders::factory_from_env()?;
    let session =
        factory.get_session(&std::env::var("PARTITION_ID").unwrap_or_else(|_| "p1".into()));

    let payload = std::env::var("PLAINTEXT").unwrap_or_else(|_| "hello-from-env".into());
    let drr = session.encrypt(payload.as_bytes())?;
    let pt = session.decrypt(drr)?;
    log::info!("{}", String::from_utf8_lossy(&pt));
    Ok(())
}
