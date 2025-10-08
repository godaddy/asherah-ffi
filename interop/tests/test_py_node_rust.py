from __future__ import annotations

import base64
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import shlex

import pytest


LOGGER = logging.getLogger("interop")

ROOT = Path(__file__).resolve().parents[2]
NODE_DIR = ROOT / "asherah-node"
PY_DIR = ROOT / "asherah-py"
NODE_SCRIPT = NODE_DIR / "scripts" / "interop.js"
NODE_COMPAT_SCRIPT = ROOT / "interop" / "scripts" / "node_module_runner.js"
RUST_BIN_DEBUG = ROOT / "target" / "debug" / "asherah-interop"
RUST_BIN_RELEASE = ROOT / "target" / "release" / "asherah-interop"
# Also consider explicit CARGO_TARGET_DIR paths (e.g., target/<triple>/...)
_CARGO_TARGET_DIR = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
RUST_TRIPLE_DEBUG = _CARGO_TARGET_DIR / "debug" / "asherah-interop"
RUST_TRIPLE_RELEASE = _CARGO_TARGET_DIR / "release" / "asherah-interop"
RUBY_DIR = ROOT / "asherah-ruby"
RUBY_SCRIPT = RUBY_DIR / "scripts" / "interop.rb"
LEGACY_NODE_DIR = ROOT / "interop" / "legacy-node"

SQLITE_DB: Path | None = None

BASE_ENV = {
    "SERVICE_NAME": "service",
    "PRODUCT_ID": "product",
    "KMS": "static",
    "STATIC_MASTER_KEY_HEX": "22" * 32,
    "Metastore": "rdbms",
    "SESSION_CACHE": "0",
}


def ensure_env(target_env):
    env = os.environ.copy()
    for k, v in BASE_ENV.items():
        env[k] = v
    if SQLITE_DB is not None:
        env["SQLITE_PATH"] = str(SQLITE_DB)
        env["CONNECTION_STRING"] = str(SQLITE_DB)
    ruby_native = env.get("ASHERAH_RUBY_NATIVE")
    if not ruby_native:
        env["ASHERAH_RUBY_NATIVE"] = str(ROOT / "target" / "debug")
    env.update(target_env)
    return env


@pytest.fixture(scope="session", autouse=True)
def build_artifacts():
    env = ensure_env({})

    global SQLITE_DB
    db_path = ROOT / "target" / "interop_metastore.sqlite"
    if db_path.exists():
        db_path.unlink()
    SQLITE_DB = db_path
    env["SQLITE_PATH"] = str(db_path)
    env["CONNECTION_STRING"] = str(db_path)

    # Build Node addon via napi
    npm_env = env.copy()
    tmp_types = Path(tempfile.gettempdir()) / "napi-types"
    tmp_types.mkdir(parents=True, exist_ok=True)
    npm_env["NAPI_TYPE_DEF_TMP_FOLDER"] = str(tmp_types)
    npm_env["CARGO_TARGET_DIR"] = str(ROOT / "target")
    LOGGER.info("building asherah-node addon via napi")
    subprocess.run(["npm", "install"], cwd=NODE_DIR, env=npm_env, check=True)
    subprocess.run(["npm", "run", "build"], cwd=NODE_DIR, env=npm_env, check=True)

    # Build and install Python wheel
    if shutil.which("python3") is None:
        pytest.skip("python3 interpreter required")

    maturin_cmd = env.get("MATURIN_BIN", "python3 -m maturin")
    maturin_args = shlex.split(maturin_cmd)
    try:
        subprocess.run(
            maturin_args + ["--version"],
            cwd=ROOT,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        pytest.skip("maturin is required for Python interop tests")

    LOGGER.info("building Python wheel with maturin")
    subprocess.run(
        maturin_args
        + [
            "build",
            "--profile",
            "dev",
            "--manifest-path",
            str(PY_DIR / "Cargo.toml"),
        ],
        cwd=ROOT,
        env=env,
        check=True,
    )
    target_dir = Path(env.get("CARGO_TARGET_DIR", ROOT / "target"))
    wheel_dir = target_dir / "wheels"
    wheels = sorted(wheel_dir.glob("asherah_py-*.whl"))
    if not wheels:
        raise RuntimeError("maturin did not produce a wheel")
    wheel_path = wheels[-1]
    LOGGER.info("installing freshly built Python wheel")
    subprocess.run(
        [
            "python3",
            "-m",
            "pip",
            "install",
            "--force-reinstall",
            "--no-deps",
            str(wheel_path),
        ],
        cwd=ROOT,
        env=env,
        check=True,
    )

    LOGGER.info("building asherah-ffi for Ruby tests")
    subprocess.run(
        [
            "cargo",
            "build",
            "-p",
            "asherah-ffi",
        ],
        cwd=ROOT,
        env=env,
        check=True,
    )

    # Build Rust interop binary (debug is fine for tests)
    LOGGER.info("building asherah-interop Rust CLI")
    subprocess.run(
        [
            "cargo",
            "build",
            "--bin",
            "asherah-interop",
            "--manifest-path",
            str(ROOT / "asherah" / "Cargo.toml"),
            "--features",
            "sqlite",
        ],
        cwd=ROOT,
        env=env,
        check=True,
    )

    LOGGER.info("installing legacy npm package asherah@3.0.12")
    subprocess.run(["npm", "install"], cwd=LEGACY_NODE_DIR, env=env, check=True)

    return wheel_path


def node_cli(action: str, partition: str, payload: bytes) -> bytes:
    payload_b64 = base64.b64encode(payload).decode()
    env = ensure_env({})
    LOGGER.info("node addon %s partition=%s payload=%d bytes", action, partition, len(payload))
    result = subprocess.run(
        ["node", str(NODE_SCRIPT), action, partition, payload_b64],
        cwd=NODE_DIR,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return base64.b64decode(result.stdout.strip())


def rust_cli(action: str, partition: str, payload: bytes) -> bytes:
    payload_b64 = base64.b64encode(payload).decode()
    env = ensure_env({})
    # Prefer plain target/debug, then target/<triple>/debug, then releases.
    if RUST_BIN_DEBUG.exists():
        bin_path = RUST_BIN_DEBUG
    elif RUST_TRIPLE_DEBUG.exists():
        bin_path = RUST_TRIPLE_DEBUG
    elif RUST_BIN_RELEASE.exists():
        bin_path = RUST_BIN_RELEASE
    else:
        bin_path = RUST_TRIPLE_RELEASE
    LOGGER.info("rust cli %s partition=%s payload=%d bytes", action, partition, len(payload))
    result = subprocess.run(
        [str(bin_path), action, partition, payload_b64],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return base64.b64decode(result.stdout.strip())


def ruby_cli(action: str, partition: str, payload: bytes) -> bytes:
    payload_b64 = base64.b64encode(payload).decode()
    env = ensure_env({})
    LOGGER.info("ruby %s partition=%s payload=%d bytes", action, partition, len(payload))
    result = subprocess.run(
        ["ruby", str(RUBY_SCRIPT), action, partition, payload_b64],
        cwd=RUBY_DIR,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return base64.b64decode(result.stdout.strip())


def node_module_cli(flavour: str, action: str, partition: str, payload: bytes) -> bytes:
    payload_b64 = base64.b64encode(payload).decode()
    env = ensure_env({"Metastore": "memory"})
    env.pop("CONNECTION_STRING", None)
    env.pop("SQLITE_PATH", None)
    cwd = LEGACY_NODE_DIR if flavour == "legacy" else NODE_DIR
    LOGGER.info(
        "node %s %s partition=%s payload=%d bytes",
        flavour,
        action,
        partition,
        len(payload),
    )
    result = subprocess.run(
        ["node", str(NODE_COMPAT_SCRIPT), flavour, action, partition, payload_b64],
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return base64.b64decode(result.stdout.strip())


def python_encrypt(partition: str, data: bytes) -> str:
    import asherah_py as asherah

    for k, v in BASE_ENV.items():
        os.environ[k] = v
    if SQLITE_DB is not None:
        os.environ["SQLITE_PATH"] = str(SQLITE_DB)
        os.environ["CONNECTION_STRING"] = str(SQLITE_DB)

    factory = asherah.SessionFactory()
    session = factory.get_session(partition)
    try:
        LOGGER.info("python encrypt partition=%s payload=%d bytes", partition, len(data))
        return session.encrypt_bytes(data)
    finally:
        factory.close()


def python_decrypt(partition: str, drr_json: str) -> bytes:
    import asherah_py as asherah

    for k, v in BASE_ENV.items():
        os.environ[k] = v
    if SQLITE_DB is not None:
        os.environ["SQLITE_PATH"] = str(SQLITE_DB)
        os.environ["CONNECTION_STRING"] = str(SQLITE_DB)

    factory = asherah.SessionFactory()
    session = factory.get_session(partition)
    try:
        LOGGER.info("python decrypt partition=%s", partition)
        return session.decrypt_bytes(drr_json)
    finally:
        factory.close()


def test_cross_language_round_trip(build_artifacts):
    partition = "partition"
    plaintext = b"cross-language secret"

    # Python -> Node/Rust
    LOGGER.info("=== Python encrypt -> Node + Rust decrypt ===")
    py_json = python_encrypt(partition, plaintext)
    assert node_cli("decrypt", partition, py_json.encode()) == plaintext
    assert rust_cli("decrypt", partition, py_json.encode()) == plaintext
    assert ruby_cli("decrypt", partition, py_json.encode()) == plaintext

    # Node -> Python/Rust
    LOGGER.info("=== Node encrypt -> Python + Rust decrypt ===")
    node_json = node_cli("encrypt", partition, plaintext)
    assert python_decrypt(partition, node_json.decode()) == plaintext
    assert rust_cli("decrypt", partition, node_json) == plaintext
    assert ruby_cli("decrypt", partition, node_json) == plaintext

    # Rust -> Python/Node
    LOGGER.info("=== Rust encrypt -> Python + Node decrypt ===")
    rust_json = rust_cli("encrypt", partition, plaintext)
    assert python_decrypt(partition, rust_json.decode()) == plaintext
    assert node_cli("decrypt", partition, rust_json) == plaintext
    assert ruby_cli("decrypt", partition, rust_json) == plaintext

    # Ruby -> Python/Node/Rust
    LOGGER.info("=== Ruby encrypt -> Python + Node + Rust decrypt ===")
    ruby_json = ruby_cli("encrypt", partition, plaintext)
    assert python_decrypt(partition, ruby_json.decode()) == plaintext
    assert node_cli("decrypt", partition, ruby_json) == plaintext
    assert rust_cli("decrypt", partition, ruby_json) == plaintext


def test_node_legacy_compatibility(build_artifacts):
    partition = "compat"
    payload = b"legacy compatibility payload"

    recovered_legacy = node_module_cli("legacy", "roundtrip", partition, payload)
    assert recovered_legacy == payload
