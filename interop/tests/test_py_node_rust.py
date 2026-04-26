from __future__ import annotations

import base64
import logging
import os
import subprocess
from pathlib import Path

import pytest

# build_artifacts (autouse, session-scoped) lives in conftest.py and is
# applied to every test in this directory automatically. Helpers we still
# define locally below.
from conftest import (  # noqa: F401  (build_artifacts re-exported for explicit use)
    ROOT,
    NODE_DIR,
    LEGACY_NODE_DIR,
    ensure_env,
)

LOGGER = logging.getLogger("interop")

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

# Prefer Homebrew Ruby over macOS system Ruby (2.6, missing gems)
_HOMEBREW_RUBY = Path("/opt/homebrew/opt/ruby/bin/ruby")
RUBY_CMD = str(_HOMEBREW_RUBY) if _HOMEBREW_RUBY.exists() else "ruby"


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
    # Ensure Homebrew Ruby's gem path is on PATH (system Ruby 2.6 lacks gems)
    if _HOMEBREW_RUBY.exists():
        ruby_paths = "/opt/homebrew/opt/ruby/bin:/opt/homebrew/lib/ruby/gems/4.0.0/bin"
        env["PATH"] = ruby_paths + ":" + env.get("PATH", "")
    LOGGER.info("ruby %s partition=%s payload=%d bytes", action, partition, len(payload))
    result = subprocess.run(
        [RUBY_CMD, str(RUBY_SCRIPT), action, partition, payload_b64],
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
    import asherah

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
    import asherah

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


def test_cross_language_unicode(build_artifacts):
    """Unicode payloads must survive encrypt in one language and decrypt in another."""
    partition = "unicode-interop"
    payloads = [
        "你好世界こんにちは세계".encode(),
        "🦀🔐🎉💾🌍".encode(),
        "Hello 世界 مرحبا Привет 🌍".encode(),
        "e\u0301 n\u0303 a\u0308".encode(),
        "\U0001F468\u200D\U0001F469\u200D\U0001F467\u200D\U0001F466".encode(),
    ]

    for payload in payloads:
        # Python encrypt -> Node + Rust + Ruby decrypt
        py_json = python_encrypt(partition, payload)
        assert node_cli("decrypt", partition, py_json.encode()) == payload, (
            f"Node failed to decrypt Python-encrypted unicode: {payload!r}"
        )
        assert rust_cli("decrypt", partition, py_json.encode()) == payload, (
            f"Rust failed to decrypt Python-encrypted unicode: {payload!r}"
        )
        assert ruby_cli("decrypt", partition, py_json.encode()) == payload, (
            f"Ruby failed to decrypt Python-encrypted unicode: {payload!r}"
        )

        # Node encrypt -> Python + Rust + Ruby decrypt
        node_json = node_cli("encrypt", partition, payload)
        assert python_decrypt(partition, node_json.decode()) == payload
        assert rust_cli("decrypt", partition, node_json) == payload
        assert ruby_cli("decrypt", partition, node_json) == payload


def test_cross_language_binary(build_artifacts):
    """Binary payloads with all 256 byte values must survive cross-language roundtrip."""
    partition = "binary-interop"
    payload = bytes(range(256))

    # Python encrypt -> Node + Rust + Ruby decrypt
    py_json = python_encrypt(partition, payload)
    assert node_cli("decrypt", partition, py_json.encode()) == payload
    assert rust_cli("decrypt", partition, py_json.encode()) == payload
    assert ruby_cli("decrypt", partition, py_json.encode()) == payload

    # Node encrypt -> Python + Rust + Ruby decrypt
    node_json = node_cli("encrypt", partition, payload)
    assert python_decrypt(partition, node_json.decode()) == payload
    assert rust_cli("decrypt", partition, node_json) == payload
    assert ruby_cli("decrypt", partition, node_json) == payload

    # Rust encrypt -> Python + Node + Ruby decrypt
    rust_json = rust_cli("encrypt", partition, payload)
    assert python_decrypt(partition, rust_json.decode()) == payload
    assert node_cli("decrypt", partition, rust_json) == payload
    assert ruby_cli("decrypt", partition, rust_json) == payload


def test_cross_language_empty(build_artifacts):
    """Empty payloads must survive cross-language roundtrip."""
    partition = "empty-interop"
    payload = b""

    py_json = python_encrypt(partition, payload)
    assert node_cli("decrypt", partition, py_json.encode()) == payload
    assert rust_cli("decrypt", partition, py_json.encode()) == payload
    assert ruby_cli("decrypt", partition, py_json.encode()) == payload


def test_node_legacy_compatibility(build_artifacts):
    partition = "compat"
    payload = b"legacy compatibility payload"

    recovered_legacy = node_module_cli("legacy", "roundtrip", partition, payload)
    assert recovered_legacy == payload


def test_node_legacy_empty_payload_roundtrip(build_artifacts):
    """The canonical asherah-node (Go cobhan core) must accept empty
    plaintext on encrypt and round-trip it back to empty on decrypt.

    This proves behavioral parity with our impl: empty plaintext is a
    valid cryptographic operation in both implementations. (Cross-impl
    decrypt requires a shared metastore so the IK is visible to both
    addons; canonical asherah-cobhan only supports MySQL/Postgres for
    rdbms metastore, not SQLite, so this test runs the canonical
    addon's own roundtrip rather than crossing the impl boundary.)"""
    partition = "legacy-empty"
    payload = b""

    # Encrypt + decrypt within the canonical addon, in one subprocess.
    recovered = node_module_cli("legacy", "roundtrip", partition, payload)
    assert recovered == payload, (
        "canonical asherah-node must round-trip empty plaintext to empty"
    )


def test_node_legacy_decrypt_empty_input_rejected(build_artifacts):
    """The canonical asherah-node must reject an empty-byte ciphertext
    rather than silently returning empty plaintext — same contract as
    our impl."""
    try:
        node_module_cli("legacy", "decrypt", "legacy-empty-decrypt", b"")
        assert False, "canonical decrypt of empty bytes should have errored"
    except subprocess.CalledProcessError:
        pass  # expected: canonical errors on invalid/empty input
