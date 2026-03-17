import os

import pytest


def _configure_env():
    os.environ.setdefault("SERVICE_NAME", "svc")
    os.environ.setdefault("PRODUCT_ID", "prod")
    os.environ.setdefault("KMS", "static")
    os.environ.setdefault("STATIC_MASTER_KEY_HEX", "22" * 32)


def test_encrypt_decrypt_roundtrip():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()
    session = factory.get_session("pytest")

    payload = b"test payload"
    ciphertext = session.encrypt_bytes(payload)
    assert isinstance(ciphertext, str)

    recovered = session.decrypt_bytes(ciphertext)
    assert recovered == payload

    factory.close()


def test_text_helpers():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    session = asherah.SessionFactory().get_session("pytest-text")

    text = "hello world"
    ciphertext = session.encrypt_text(text)
    assert isinstance(ciphertext, str)

    recovered = session.decrypt_text(ciphertext)
    assert recovered == text


def test_module_level_setup_flow():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    config = {
        "ServiceName": "svc",
        "ProductID": "prod",
        "Metastore": "memory",
        "KMS": "static",
        "EnableSessionCaching": True,
        "Verbose": False,
    }

    asherah.setup(config)
    assert asherah.get_setup_status() is True

    payload = b"setup api payload"
    ciphertext = asherah.encrypt_bytes("pytest-setup", payload)
    assert isinstance(ciphertext, str)

    recovered = asherah.decrypt_bytes("pytest-setup", ciphertext)
    assert recovered == payload

    plaintext = "text api"
    text_ct = asherah.encrypt_string("pytest-setup", plaintext)
    assert isinstance(text_ct, str)
    assert asherah.decrypt_string("pytest-setup", text_ct) == plaintext

    asherah.shutdown()
    assert asherah.get_setup_status() is False


def test_module_level_setup_can_repeat():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    config = {
        "ServiceName": "svc",
        "ProductID": "prod",
        "Metastore": "memory",
        "KMS": "static",
    }

    asherah.setup(config)
    asherah.shutdown()

    asherah.setup(config)
    try:
        ciphertext = asherah.encrypt_bytes("repeat", b"python-cycle")
        recovered = asherah.decrypt_bytes("repeat", ciphertext)
        assert recovered == b"python-cycle"
    finally:
        asherah.shutdown()

    assert asherah.get_setup_status() is False


def test_setenv_helper():
    pytest.importorskip("asherah")
    import asherah

    env_payload = {"FOO": "BAR", "REMOVE_ME": None}
    asherah.setenv(env_payload)
    assert os.environ["FOO"] == "BAR"
    assert "REMOVE_ME" not in os.environ


# ============================================================================
# FFI Boundary Tests
# ============================================================================


def _setup_module_api():
    """Setup using module-level API for boundary tests."""
    import asherah

    _configure_env()
    config = {
        "ServiceName": "ffi-test",
        "ProductID": "prod",
        "Metastore": "memory",
        "KMS": "static",
        "EnableSessionCaching": False,
    }
    asherah.setup(config)
    return asherah


def test_unicode_cjk():
    asherah = _setup_module_api()
    try:
        text = "你好世界こんにちは세계"
        ct = asherah.encrypt_string("py-unicode", text)
        assert asherah.decrypt_string("py-unicode", ct) == text
    finally:
        asherah.shutdown()


def test_unicode_emoji():
    asherah = _setup_module_api()
    try:
        text = "🦀🔐🎉💾🌍"
        ct = asherah.encrypt_string("py-unicode", text)
        assert asherah.decrypt_string("py-unicode", ct) == text
    finally:
        asherah.shutdown()


def test_unicode_mixed_scripts():
    asherah = _setup_module_api()
    try:
        text = "Hello 世界 مرحبا Привет 🌍"
        ct = asherah.encrypt_string("py-unicode", text)
        assert asherah.decrypt_string("py-unicode", ct) == text
    finally:
        asherah.shutdown()


def test_unicode_combining_characters():
    asherah = _setup_module_api()
    try:
        text = "e\u0301 n\u0303 a\u0308"
        ct = asherah.encrypt_string("py-unicode", text)
        assert asherah.decrypt_string("py-unicode", ct) == text
    finally:
        asherah.shutdown()


def test_unicode_zwj_sequence():
    asherah = _setup_module_api()
    try:
        text = "\U0001F468\u200D\U0001F469\u200D\U0001F467\u200D\U0001F466"
        ct = asherah.encrypt_string("py-unicode", text)
        assert asherah.decrypt_string("py-unicode", ct) == text
    finally:
        asherah.shutdown()


def test_binary_all_byte_values():
    asherah = _setup_module_api()
    try:
        payload = bytes(range(256))
        ct = asherah.encrypt_bytes("py-binary", payload)
        recovered = asherah.decrypt_bytes("py-binary", ct)
        assert recovered == payload
    finally:
        asherah.shutdown()


def test_empty_payload():
    asherah = _setup_module_api()
    try:
        ct = asherah.encrypt_bytes("py-empty", b"")
        recovered = asherah.decrypt_bytes("py-empty", ct)
        assert recovered == b""
    finally:
        asherah.shutdown()


def test_large_payload_1mb():
    asherah = _setup_module_api()
    try:
        payload = bytes(i % 256 for i in range(1024 * 1024))
        ct = asherah.encrypt_bytes("py-large", payload)
        recovered = asherah.decrypt_bytes("py-large", ct)
        assert len(recovered) == len(payload)
        assert recovered == payload
    finally:
        asherah.shutdown()


def test_decrypt_invalid_json():
    asherah = _setup_module_api()
    try:
        with pytest.raises(Exception):
            asherah.decrypt_bytes("py-error", "not valid json")
    finally:
        asherah.shutdown()


def test_decrypt_wrong_partition():
    asherah = _setup_module_api()
    try:
        ct = asherah.encrypt_bytes("partition-a", b"secret")
        with pytest.raises(Exception):
            asherah.decrypt_bytes("partition-b", ct)
    finally:
        asherah.shutdown()
