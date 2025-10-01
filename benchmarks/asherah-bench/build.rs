use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root(manifest_dir: &Path) -> PathBuf {
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn shared_library_extension() -> &'static str {
    if cfg!(target_os = "macos") {
        "dylib"
    } else if cfg!(target_os = "windows") {
        "dll"
    } else {
        "so"
    }
}

fn build_rust_ffi(workspace: &Path) -> anyhow::Result<PathBuf> {
    if env::var_os("ASHERAH_BENCH_SKIP_BUILD").is_none() {
        let status = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .arg("-p")
            .arg("asherah-ffi")
            .current_dir(workspace)
            .env("ASHERAH_BENCH_SKIP_BUILD", "1")
            .status()?;
        if !status.success() {
            anyhow::bail!("failed to build asherah-ffi");
        }
    }
    let lib_name = format!("libasherah_ffi.{}", shared_library_extension());
    Ok(workspace.join("target").join("release").join(lib_name))
}

fn build_go_wrapper(manifest: &Path) -> anyhow::Result<PathBuf> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let lib_path = out_dir.join(format!(
        "libasherah_go_bench.{}",
        shared_library_extension()
    ));

    let go_wrapper = manifest
        .parent()
        .expect("benchmarks dir")
        .join("go-wrapper");
    let mut cmd = Command::new("go");
    cmd.arg("build")
        .arg("-buildmode=c-shared")
        .arg("-o")
        .arg(&lib_path)
        .current_dir(&go_wrapper);
    if env::var_os("GOTOOLCHAIN").is_none() {
        cmd.env("GOTOOLCHAIN", "auto");
    }
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("failed to build Go wrapper");
    }

    // Copy the generated header for reference (optional)
    let header_src = lib_path.with_extension("h");
    if header_src.exists() {
        let header_dst = out_dir.join("asherah_go_wrapper.h");
        let _ = fs::copy(&header_src, header_dst);
    }

    Ok(lib_path)
}

fn main() -> anyhow::Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let workspace = workspace_root(&manifest_dir);

    let rust_lib = build_rust_ffi(&workspace)?;
    let go_lib = build_go_wrapper(&manifest_dir)?;

    println!("cargo:rustc-env=RUST_FFI_LIB_PATH={}", rust_lib.display());
    println!("cargo:rustc-env=GO_FFI_LIB_PATH={}", go_lib.display());

    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("../go-wrapper").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace.join("asherah-ffi").display()
    );

    Ok(())
}
