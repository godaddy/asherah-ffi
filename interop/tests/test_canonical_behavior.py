"""Verify the *actual* behavior of the canonical Asherah implementations
on null/empty inputs. No inference — every assertion is anchored to a
real subprocess that runs against the published canonical artifact.

Probes:
  - canonical Go (github.com/godaddy/asherah/go/appencryption)
  - canonical asherah-csharp (GoDaddy.Asherah.AppEncryption NuGet)
  - canonical asherah-java (com.godaddy:asherah Maven)

These tests document the canonical contract so any divergence in our
implementation is caught immediately.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
CANONICAL_GO = ROOT / "interop" / "canonical-go"
CANONICAL_CSHARP = ROOT / "interop" / "canonical-csharp"
CANONICAL_JAVA = ROOT / "interop" / "canonical-java"


# ── Canonical Go ───────────────────────────────────────────────────────


def _run_canonical_go() -> dict[str, str]:
    """Run the Go probe and parse `name: result` lines into a dict."""
    if shutil.which("go") is None:
        pytest.skip("go toolchain required")
    result = subprocess.run(
        ["go", "run", "."],
        cwd=CANONICAL_GO,
        check=True,
        capture_output=True,
        text=True,
    )
    out = {}
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        out[name.strip()] = value.strip()
    return out


def test_canonical_go_empty_partition_rejected():
    r = _run_canonical_go()
    assert r["GetSession_empty_partition"] == "ERROR: partition id cannot be empty"


def test_canonical_go_nil_plaintext_accepted():
    r = _run_canonical_go()
    # Canonical Go accepts nil []byte as empty plaintext and produces a
    # 28-byte AES-GCM ciphertext (12-byte nonce + 16-byte tag, 0-byte ct).
    assert r["Encrypt_nil_data"] == "accepted: ciphertext_data_len=28"


def test_canonical_go_empty_plaintext_accepted():
    r = _run_canonical_go()
    assert r["Encrypt_empty_data"] == "accepted: ciphertext_data_len=28"


def test_canonical_go_empty_roundtrip():
    r = _run_canonical_go()
    # Canonical decrypts empty plaintext back to len=0 (the recovered slice
    # is nil, which in Go is interchangeable with []byte{} of length 0).
    assert r["Roundtrip_empty"] == "recovered_len=0 nil=true"


def test_canonical_go_empty_drr_rejected():
    r = _run_canonical_go()
    assert r["Decrypt_empty_drr"] == "ERROR: datarow key record cannot be empty"


def test_canonical_go_decrypt_with_empty_parent_rejected():
    r = _run_canonical_go()
    assert r["Decrypt_nil_data_in_drr"] == "ERROR: parent key cannot be empty"


# ── Canonical asherah-csharp ───────────────────────────────────────────


def _run_canonical_csharp() -> dict[str, str]:
    if shutil.which("dotnet") is None:
        pytest.skip("dotnet SDK required")
    result = subprocess.run(
        ["dotnet", "run", "--no-build", "--configuration", "Release"],
        cwd=CANONICAL_CSHARP,
        check=True,
        capture_output=True,
        text=True,
    )
    out = {}
    for line in result.stdout.splitlines():
        if ":" not in line or line.startswith("WARNING"):
            continue
        name, _, value = line.partition(":")
        out[name.strip()] = value.strip()
    return out


@pytest.fixture(scope="module")
def csharp_built():
    if shutil.which("dotnet") is None:
        pytest.skip("dotnet SDK required")
    subprocess.run(
        ["dotnet", "build", "--configuration", "Release", "--nologo", "--verbosity", "quiet"],
        cwd=CANONICAL_CSHARP,
        check=True,
    )


def test_canonical_csharp_null_partition_accepted(csharp_built):
    """Canonical asherah-csharp does NOT validate null partition id at
    GetSession time — it accepts it silently. (Different from canonical Go.)"""
    r = _run_canonical_csharp()
    assert r["GetSessionBytes_null_partition"] == "accepted"


def test_canonical_csharp_null_partition_writes_broken_key_to_metastore(csharp_built):
    """**SECURITY-RELEVANT:** canonical asherah-csharp accepts a null
    partition ID, encrypts successfully, and stores an IK in the metastore
    with KeyId='_IK__service_product' — the partition slot is empty
    because string concatenation with null in C# yields empty. This means
    callers passing null write real keys to the database under a degenerate
    ID. Any other caller with the same service/product who also passes null
    (or "") will read/write the same key, conflating partitions."""
    r = _run_canonical_csharp()
    line = r["Encrypt_with_null_partition_session"]
    assert line.startswith("accepted: drr=")
    assert '"KeyId":"_IK__service_product"' in line, (
        f"expected canonical C# to write IK with KeyId=_IK__service_product, got: {line}"
    )


def test_canonical_csharp_empty_partition_accepted(csharp_built):
    """Canonical asherah-csharp does NOT validate empty partition id."""
    r = _run_canonical_csharp()
    assert r["GetSessionBytes_empty_partition"] == "accepted"


def test_canonical_csharp_empty_partition_collides_with_null(csharp_built):
    """**SECURITY-RELEVANT:** canonical asherah-csharp produces the SAME
    KeyId for both null and empty partition — they collide in the
    metastore and share keys."""
    r = _run_canonical_csharp()
    null_line = r["Encrypt_with_null_partition_session"]
    empty_line = r["Encrypt_with_empty_partition_session"]
    # Extract the KeyId from each
    import re
    null_kid = re.search(r'"KeyId":"([^"]+)"', null_line).group(1)
    empty_kid = re.search(r'"KeyId":"([^"]+)"', empty_line).group(1)
    assert null_kid == empty_kid == "_IK__service_product", (
        f"canonical C#: null KeyId={null_kid!r} empty KeyId={empty_kid!r}"
    )


def test_canonical_csharp_null_plaintext_rejected(csharp_built):
    """Canonical asherah-csharp wraps a null plaintext NRE in AppEncryptionException."""
    r = _run_canonical_csharp()
    assert r["Encrypt_null_bytes"].startswith("ERROR: AppEncryptionException:")
    assert "NullReferenceException" in r["Encrypt_null_bytes"]


def test_canonical_csharp_empty_plaintext_accepted(csharp_built):
    """Canonical asherah-csharp accepts empty byte[] and produces a DRR JSON ~241 bytes."""
    r = _run_canonical_csharp()
    assert r["Encrypt_empty_bytes"].startswith("accepted: ct_len=")
    ct_len = int(r["Encrypt_empty_bytes"].split("=")[1])
    assert ct_len > 100, f"expected non-trivial ciphertext, got len={ct_len}"


def test_canonical_csharp_empty_roundtrip(csharp_built):
    """Canonical asherah-csharp round-trips empty plaintext to len=0
    (recovered array is non-null in C#, unlike canonical Go's nil)."""
    r = _run_canonical_csharp()
    assert r["Roundtrip_empty_bytes"] == "recovered_len=0 null=False"


def test_canonical_csharp_decrypt_null_rejected(csharp_built):
    r = _run_canonical_csharp()
    assert r["Decrypt_null"].startswith("ERROR: ArgumentNullException:")
    assert "buffer" in r["Decrypt_null"]


def test_canonical_csharp_decrypt_empty_rejected(csharp_built):
    """Canonical asherah-csharp rejects empty ciphertext as invalid JSON."""
    r = _run_canonical_csharp()
    assert r["Decrypt_empty_bytes"].startswith("ERROR: JsonReaderException:")


# ── Canonical asherah-java ─────────────────────────────────────────────


def _run_canonical_java() -> dict[str, str]:
    if shutil.which("java") is None or shutil.which("mvn") is None:
        pytest.skip("java + mvn required")
    jar = CANONICAL_JAVA / "target" / "canonical-java-probe-1.0.0.jar"
    if not jar.exists():
        pytest.skip(f"build canonical Java probe first: mvn -f {CANONICAL_JAVA}/pom.xml package")
    result = subprocess.run(
        ["java", "-jar", str(jar)],
        cwd=CANONICAL_JAVA,
        check=True,
        capture_output=True,
        text=True,
    )
    out = {}
    for line in result.stdout.splitlines():
        if ":" not in line or line.startswith("WARNING") or line.startswith("SLF4J") or line.startswith("["):
            continue
        name, _, value = line.partition(":")
        out[name.strip()] = value.strip()
    return out


def _java_major_version():
    """Return JDK major version (e.g. 17, 11) by parsing `java -version`."""
    try:
        out = subprocess.run(
            ["java", "-version"], capture_output=True, text=True, check=True
        ).stderr
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    import re
    m = re.search(r'version "(\d+)', out)
    if not m:
        return None
    return int(m.group(1))


@pytest.fixture(scope="module")
def java_built():
    if shutil.which("mvn") is None:
        pytest.skip("mvn required")
    # canonical com.godaddy.asherah:appencryption@0.4.0 is compiled with
    # JDK 17 (class file 61.0); skip cleanly on older JDKs rather than
    # producing a confusing "wrong class file version" build error.
    major = _java_major_version()
    if major is None or major < 17:
        pytest.skip(f"JDK 17+ required for canonical 0.4.0 probe (found {major})")
    subprocess.run(
        ["mvn", "-B", "-q", "package", "-DskipTests"],
        cwd=CANONICAL_JAVA,
        check=True,
    )


def test_canonical_java_null_partition_accepted(java_built):
    """Canonical asherah-java does NOT validate null partition id at
    getSession time — it accepts it silently. (Different from canonical Go.)"""
    r = _run_canonical_java()
    assert r["getSessionBytes_null_partition"] == "accepted"


def test_canonical_java_null_partition_writes_literal_null_to_metastore(java_built):
    """**SECURITY-RELEVANT:** canonical asherah-java accepts a null
    partition ID, encrypts successfully, and stores an IK in the metastore
    with KeyId='_IK_null_service_product' — Java's String.format / concat
    converts null to the literal string "null". Any caller passing the
    actual string "null" as a partition will collide with this."""
    r = _run_canonical_java()
    line = r["encrypt_with_null_partition_session"]
    assert line.startswith("accepted: drr=")
    assert '"KeyId":"_IK_null_service_product"' in line, (
        f"expected canonical Java to write IK with KeyId=_IK_null_service_product, got: {line}"
    )


def test_canonical_java_empty_partition_writes_broken_key_to_metastore(java_built):
    """Canonical asherah-java with empty partition writes IK
    KeyId='_IK__service_product' to the metastore (different from null,
    which writes '_IK_null_...')."""
    r = _run_canonical_java()
    line = r["encrypt_with_empty_partition_session"]
    assert line.startswith("accepted: drr=")
    assert '"KeyId":"_IK__service_product"' in line


def test_canonical_java_empty_partition_accepted(java_built):
    r = _run_canonical_java()
    assert r["getSessionBytes_empty_partition"] == "accepted"


def test_canonical_java_null_plaintext_rejected(java_built):
    """Canonical asherah-java wraps null plaintext NPE in AppEncryptionException."""
    r = _run_canonical_java()
    assert r["encrypt_null_bytes"].startswith("ERROR: AppEncryptionException:")
    assert "NullPointerException" in r["encrypt_null_bytes"]


def test_canonical_java_empty_plaintext_accepted(java_built):
    r = _run_canonical_java()
    assert r["encrypt_empty_bytes"].startswith("accepted: ct_len=")
    ct_len = int(r["encrypt_empty_bytes"].split("=")[1])
    assert ct_len > 100


def test_canonical_java_empty_roundtrip(java_built):
    """Canonical asherah-java round-trips empty plaintext to len=0
    (recovered array is non-null, like asherah-csharp, unlike Go)."""
    r = _run_canonical_java()
    assert r["roundtrip_empty_bytes"] == "recovered_len=0 null=false"


def test_canonical_java_decrypt_null_rejected(java_built):
    r = _run_canonical_java()
    assert r["decrypt_null"].startswith("ERROR: NullPointerException:")


def test_canonical_java_decrypt_empty_rejected(java_built):
    """Canonical asherah-java rejects empty ciphertext as invalid JSON."""
    r = _run_canonical_java()
    assert r["decrypt_empty_bytes"].startswith("ERROR: JSONException:")
