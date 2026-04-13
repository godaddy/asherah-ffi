//! Guard tests that validate repository configuration files.
//!
//! These catch configuration drift that broke CI in the past:
//! - Invalid .NET SDK version in global.json
//! - Missing UseAppHost in .NET test projects
//! - Java pom.xml depending on unset env vars
//! - Interop scripts not reading STATIC_MASTER_KEY_HEX
//! - Python binding init not importing the native module
//! - Interop test not probing maturin fallback candidates
//! - PyPI E2E test not creating an isolated venv

use std::path::Path;

fn repo_root() -> &'static Path {
    // CARGO_MANIFEST_DIR is asherah/, parent is the repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR must have a parent directory")
}

#[test]
fn test_global_json_valid_sdk_feature_band() {
    let content = std::fs::read_to_string(repo_root().join("global.json"))
        .expect("global.json must exist at repo root");
    let v: serde_json::Value =
        serde_json::from_str(&content).expect("global.json must be valid JSON");
    let version = v["sdk"]["version"]
        .as_str()
        .expect("global.json must have sdk.version string");
    let parts: Vec<u32> = version
        .split('.')
        .map(|s| s.parse().expect("version component must be numeric"))
        .collect();
    assert_eq!(parts.len(), 3, "SDK version must have 3 parts: {version}");
    assert!(
        parts[2] >= 100,
        "SDK version third component must be a feature band (>=100), got {version}"
    );
}

#[test]
fn test_dotnet_test_projects_disable_apphost() {
    let content =
        std::fs::read_to_string(repo_root().join("asherah-dotnet/tests/Directory.Build.props"))
            .expect("asherah-dotnet/tests/Directory.Build.props must exist");
    assert!(
        content.contains("<UseAppHost>false</UseAppHost>"),
        "Test Directory.Build.props must set <UseAppHost>false</UseAppHost>"
    );
}

#[test]
fn test_java_pom_uses_project_basedir() {
    let content = std::fs::read_to_string(repo_root().join("asherah-java/java/pom.xml"))
        .expect("asherah-java/java/pom.xml must exist");
    assert!(
        content.contains("${project.basedir}/../../target/debug"),
        "pom.xml nativeLibraryPath must use ${{project.basedir}}, not ${{env.CARGO_TARGET_DIR}}"
    );
    assert!(
        !content.contains("${env.CARGO_TARGET_DIR}"),
        "pom.xml must not reference ${{env.CARGO_TARGET_DIR}}"
    );
}

#[test]
fn test_interop_scripts_read_static_master_key() {
    let node_script = std::fs::read_to_string(repo_root().join("asherah-node/scripts/interop.js"))
        .expect("asherah-node/scripts/interop.js must exist");
    assert!(
        node_script.contains("STATIC_MASTER_KEY_HEX"),
        "Node interop.js must read STATIC_MASTER_KEY_HEX from env"
    );
    assert!(
        node_script.contains("staticMasterKeyHex"),
        "Node interop.js config must set staticMasterKeyHex field"
    );

    let ruby_script = std::fs::read_to_string(repo_root().join("asherah-ruby/scripts/interop.rb"))
        .expect("asherah-ruby/scripts/interop.rb must exist");
    assert!(
        ruby_script.contains("STATIC_MASTER_KEY_HEX"),
        "Ruby interop.rb must read STATIC_MASTER_KEY_HEX from env"
    );
    assert!(
        ruby_script.contains("StaticMasterKeyHex"),
        "Ruby interop.rb config must set StaticMasterKeyHex field"
    );
}

#[test]
fn test_python_binding_init_imports_native_module() {
    let content = std::fs::read_to_string(repo_root().join("asherah-py/asherah/__init__.py"))
        .expect("asherah-py/asherah/__init__.py must exist");
    assert!(
        content.contains("from asherah._asherah import"),
        "__init__.py must use 'from asherah._asherah import' to avoid namespace shadowing"
    );
}

#[test]
fn test_interop_maturin_fallback_catches_errors() {
    let content = std::fs::read_to_string(repo_root().join("interop/tests/test_py_node_rust.py"))
        .expect("interop/tests/test_py_node_rust.py must exist");
    assert!(
        content.contains("python3 -m maturin"),
        "interop test must probe 'python3 -m maturin'"
    );
    assert!(
        content.contains("\"maturin\""),
        "interop test must fall back to bare 'maturin'"
    );
    assert!(
        content.contains("CalledProcessError"),
        "interop test must catch CalledProcessError during maturin probe"
    );
}

#[test]
fn test_pypi_e2e_creates_venv() {
    let content = std::fs::read_to_string(repo_root().join("scripts/test.sh"))
        .expect("scripts/test.sh must exist");
    assert!(
        content.contains("python3 -m venv"),
        "test.sh PyPI E2E must create a venv"
    );
    assert!(
        content.contains("pip install") && content.contains("asherah"),
        "test.sh PyPI E2E must pip install asherah in the venv"
    );
}
