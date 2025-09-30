fn main() {
    const DEFAULT_NAPI_VERSION: &str = "2.18.4";
    let cli_version = std::env::var("CARGO_CFG_NAPI_RS_CLI_VERSION")
        .or_else(|_| std::env::var("NAPI_RS_CLI_VERSION"))
        .unwrap_or_else(|_| DEFAULT_NAPI_VERSION.to_string());
    std::env::set_var("CARGO_CFG_NAPI_RS_CLI_VERSION", &cli_version);
    std::env::set_var("NAPI_RS_CLI_VERSION", &cli_version);
    println!("cargo:rustc-env=CARGO_CFG_NAPI_RS_CLI_VERSION={cli_version}");

    let build_env = std::env::var("CARGO_CFG_NAPI_RS_BUILD_ENV")
        .or_else(|_| std::env::var("NAPI_RS_BUILD_ENV"))
        .or_else(|_| std::env::var("PROFILE"))
        .unwrap_or_else(|_| "debug".to_string());
    std::env::set_var("CARGO_CFG_NAPI_RS_BUILD_ENV", &build_env);
    std::env::set_var("NAPI_RS_BUILD_ENV", &build_env);
    println!("cargo:rustc-env=CARGO_CFG_NAPI_RS_BUILD_ENV={build_env}");

    if std::env::var("NAPI_TYPE_DEF_TMP_FOLDER").is_err() {
        if let Ok(type_def_file) = std::env::var("TYPE_DEF_TMP_PATH") {
            let folder = std::path::Path::new(&type_def_file)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| type_def_file);
            std::env::set_var("NAPI_TYPE_DEF_TMP_FOLDER", &folder);
            println!("cargo:rustc-env=NAPI_TYPE_DEF_TMP_FOLDER={folder}");
        }
    }

    napi_build::setup();
}
