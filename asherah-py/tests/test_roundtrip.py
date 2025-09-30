import os

import pytest


def _configure_env():
    os.environ.setdefault("SERVICE_NAME", "svc")
    os.environ.setdefault("PRODUCT_ID", "prod")
    os.environ.setdefault("KMS", "static")
    os.environ.setdefault("STATIC_MASTER_KEY_HEX", "22" * 32)


def test_encrypt_decrypt_roundtrip():
    pytest.importorskip("asherah_py")
    import asherah_py as asherah

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
    pytest.importorskip("asherah_py")
    import asherah_py as asherah

    _configure_env()
    session = asherah.SessionFactory().get_session("pytest-text")

    text = "hello world"
    ciphertext = session.encrypt_text(text)
    assert isinstance(ciphertext, str)

    recovered = session.decrypt_text(ciphertext)
    assert recovered == text


def test_module_level_setup_flow():
    pytest.importorskip("asherah_py")
    import asherah_py as asherah

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
    pytest.importorskip("asherah_py")
    import asherah_py as asherah

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
    pytest.importorskip("asherah_py")
    import asherah_py as asherah

    env_payload = {"FOO": "BAR", "REMOVE_ME": None}
    asherah.setenv(env_payload)
    assert os.environ["FOO"] == "BAR"
    assert "REMOVE_ME" not in os.environ
