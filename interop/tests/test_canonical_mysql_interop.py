"""MySQL-backed cross-impl interop with canonical asherah.

Both the canonical asherah-node 3.0.12 (which wraps the canonical Go cobhan
core) and our Rust addon are configured to use a shared MySQL metastore so
the IK is visible to both. Then we test bidirectional encrypt/decrypt
including empty plaintext.

These tests skip if Docker or MySQL is unavailable.
"""
from __future__ import annotations

import base64
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "interop" / "scripts" / "mysql_bidirectional.js"
NODE_DIR = ROOT / "asherah-node"
LEGACY_NODE_DIR = ROOT / "interop" / "legacy-node"
LABEL = "asherah-interop-mysql"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False


def _wait_port(host: str, port: int, timeout: float = 60.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False


def _start_mysql() -> tuple[str, str, str]:
    """Find an existing labelled MySQL container, or start one. Returns
    (container_id, mysql_url, mysql_dsn)."""
    # Try labelled, running benchmark MySQL containers first
    for label in [LABEL, "asherah-benchmark-mysql"]:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"label={label}", "--format", "{{.ID}} {{.Ports}}"],
            check=True, capture_output=True, text=True,
        )
        if result.stdout.strip():
            cid, ports = result.stdout.strip().split(maxsplit=1)
            # parse "0.0.0.0:55107->3306/tcp, ..." or "127.0.0.1:55107->3306/tcp"
            for chunk in ports.split(","):
                chunk = chunk.strip()
                if "->3306/tcp" in chunk:
                    host_port = chunk.split("->")[0].split(":")[-1]
                    url = f"mysql://root@127.0.0.1:{host_port}/test"
                    dsn = f"root@tcp(127.0.0.1:{host_port})/test"
                    return cid, url, dsn

    # Start a fresh one
    cid = subprocess.run(
        [
            "docker", "run", "-d", "--rm",
            "--label", LABEL,
            "-e", "MYSQL_DATABASE=test",
            "-e", "MYSQL_ALLOW_EMPTY_PASSWORD=yes",
            "-p", "127.0.0.1::3306",
            "mysql:8.1",
        ],
        check=True, capture_output=True, text=True,
    ).stdout.strip()

    # Get the mapped port
    port_line = subprocess.run(
        ["docker", "port", cid, "3306/tcp"],
        check=True, capture_output=True, text=True,
    ).stdout.strip().splitlines()[0]
    host_port = port_line.split(":")[-1]

    if not _wait_port("127.0.0.1", int(host_port), timeout=120):
        raise RuntimeError(f"MySQL didn't start on port {host_port}")

    # Wait for readiness via mysqladmin ping
    end = time.time() + 90
    while time.time() < end:
        r = subprocess.run(
            ["docker", "exec", cid, "mysqladmin", "-h", "127.0.0.1", "-u", "root", "ping", "--silent"],
            capture_output=True,
        )
        if r.returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("mysqladmin ping never succeeded")

    url = f"mysql://root@127.0.0.1:{host_port}/test"
    dsn = f"root@tcp(127.0.0.1:{host_port})/test"
    return cid, url, dsn


@pytest.fixture(scope="module")
def mysql_metastore():
    if not _docker_available():
        pytest.skip("docker required")
    cid, url, dsn = _start_mysql()

    # Ensure the encryption_key table exists (canonical asherah-cobhan creates
    # it automatically, but our addon expects it to be present).
    create_table_sql = (
        "CREATE TABLE IF NOT EXISTS encryption_key ("
        "id VARCHAR(255) NOT NULL, "
        "created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, "
        "key_record JSON NOT NULL, "
        "PRIMARY KEY(id, created), "
        "INDEX(created)"
        ") ENGINE=InnoDB"
    )
    subprocess.run(
        ["docker", "exec", cid, "mysql", "-h", "127.0.0.1", "-u", "root", "test",
         "-e", create_table_sql],
        check=True, capture_output=True,
    )
    yield {"url": url, "dsn": dsn, "container": cid}


def _bidirectional(encrypter: str, decrypter: str, partition: str, payload: bytes,
                   mysql_metastore) -> bytes:
    env = {
        **os.environ,
        "MYSQL_URL": mysql_metastore["url"],
        "MYSQL_DSN": mysql_metastore["dsn"],
        "SERVICE_NAME": "mysql-interop-svc",
        "PRODUCT_ID": "mysql-interop-prod",
    }
    payload_b64 = base64.b64encode(payload).decode()
    result = subprocess.run(
        ["node", str(SCRIPT), encrypter, decrypter, partition, payload_b64],
        check=True, capture_output=True, text=True, env=env,
    )
    return base64.b64decode(result.stdout.strip()) if result.stdout.strip() else b""


def test_canonical_to_ours_nonempty(mysql_metastore):
    """Canonical Go cobhan core encrypts → our Rust addon decrypts."""
    payload = b"canonical-go-to-ours"
    recovered = _bidirectional("legacy", "new", "x-legacy-new-1", payload, mysql_metastore)
    assert recovered == payload


def test_ours_to_canonical_nonempty(mysql_metastore):
    """Our Rust addon encrypts → canonical Go cobhan core decrypts."""
    payload = b"ours-to-canonical-go"
    recovered = _bidirectional("new", "legacy", "x-new-legacy-1", payload, mysql_metastore)
    assert recovered == payload


def test_canonical_to_ours_empty(mysql_metastore):
    """Empty plaintext: canonical encrypts → ours decrypts → empty."""
    recovered = _bidirectional("legacy", "new", "x-legacy-new-empty", b"", mysql_metastore)
    assert recovered == b""


def test_ours_to_canonical_empty(mysql_metastore):
    """Empty plaintext: ours encrypts → canonical decrypts → empty."""
    recovered = _bidirectional("new", "legacy", "x-new-legacy-empty", b"", mysql_metastore)
    assert recovered == b""


def test_canonical_to_ours_unicode(mysql_metastore):
    """Cross-impl unicode payload — verifies UTF-8 wire compatibility."""
    payload = "Hello 世界 🦀".encode()
    recovered = _bidirectional("legacy", "new", "x-unicode", payload, mysql_metastore)
    assert recovered == payload


def test_ours_to_canonical_unicode(mysql_metastore):
    payload = "🔐🌍 Привет".encode()
    recovered = _bidirectional("new", "legacy", "x-unicode-rev", payload, mysql_metastore)
    assert recovered == payload


def test_canonical_to_ours_binary(mysql_metastore):
    """Cross-impl binary payload — all 256 byte values."""
    payload = bytes(range(256))
    recovered = _bidirectional("legacy", "new", "x-binary", payload, mysql_metastore)
    assert recovered == payload


def test_ours_to_canonical_binary(mysql_metastore):
    payload = bytes(range(256))
    recovered = _bidirectional("new", "legacy", "x-binary-rev", payload, mysql_metastore)
    assert recovered == payload
