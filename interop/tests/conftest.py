"""Shared interop test setup. The session-scoped autouse fixture below
builds the language-binding artifacts (Node addon, Python wheel, Rust
CLI, Ruby native lib, legacy npm fixture) and a shared SQLite metastore
file so every test in this directory can rely on them being ready.

Centralizing this in conftest.py (rather than in any single test file)
ensures the fixture runs before tests in *any* test module, including
tests that don't import from test_py_node_rust.
"""
from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest


LOGGER = logging.getLogger("interop")

ROOT = Path(__file__).resolve().parents[2]
NODE_DIR = ROOT / "asherah-node"
PY_DIR = ROOT / "asherah-py"
RUBY_DIR = ROOT / "asherah-ruby"
LEGACY_NODE_DIR = ROOT / "interop" / "legacy-node"

BASE_ENV = {
    "SERVICE_NAME": "service",
    "PRODUCT_ID": "product",
    "KMS": "static",
    "STATIC_MASTER_KEY_HEX": "22" * 32,
    "Metastore": "sqlite",
    "SESSION_CACHE": "0",
}

SQLITE_DB: Path | None = None


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

    maturin_cmd = env.get("MATURIN_BIN", "")
    if not maturin_cmd:
        for candidate in ("python3 -m maturin", "maturin"):
            try:
                subprocess.run(
                    shlex.split(candidate) + ["--version"],
                    cwd=ROOT,
                    env=env,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                maturin_cmd = candidate
                break
            except (FileNotFoundError, subprocess.CalledProcessError):
                continue
        if not maturin_cmd:
            pytest.skip("maturin is required for Python interop tests")
    else:
        try:
            subprocess.run(
                shlex.split(maturin_cmd) + ["--version"],
                cwd=ROOT,
                env=env,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            pytest.skip(f"maturin not available via MATURIN_BIN={maturin_cmd}")
    maturin_args = shlex.split(maturin_cmd)

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
    wheels = sorted(wheel_dir.glob("asherah*.whl"))
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
        ["cargo", "build", "-p", "asherah-ffi"],
        cwd=ROOT,
        env=env,
        check=True,
    )

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
