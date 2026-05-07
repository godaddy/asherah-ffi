fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(&["proto/appencryption.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/appencryption.proto");
    Ok(())
}
