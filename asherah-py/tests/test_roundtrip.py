import os
import threading

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


# ============================================================================
# Factory / Session API Tests
# ============================================================================


def test_factory_multiple_sessions():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()
    try:
        session_a = factory.get_session("partition-alpha")
        session_b = factory.get_session("partition-beta")

        ct_a = session_a.encrypt_bytes(b"alpha secret")
        ct_b = session_b.encrypt_bytes(b"beta secret")

        # Each session can decrypt its own data
        assert session_a.decrypt_bytes(ct_a) == b"alpha secret"
        assert session_b.decrypt_bytes(ct_b) == b"beta secret"

        # Cross-partition decrypt must fail
        with pytest.raises(Exception):
            session_a.decrypt_bytes(ct_b)
        with pytest.raises(Exception):
            session_b.decrypt_bytes(ct_a)
    finally:
        factory.close()


def test_factory_context_manager():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    with asherah.SessionFactory() as factory:
        session = factory.get_session("ctx-mgr")
        payload = b"context manager payload"
        ct = session.encrypt_bytes(payload)
        recovered = session.decrypt_bytes(ct)
        assert recovered == payload


def test_session_encrypt_string_via_factory():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()
    try:
        session = factory.get_session("factory-text")
        text = "factory string roundtrip"
        ct = session.encrypt_text(text)
        assert isinstance(ct, str)
        recovered = session.decrypt_text(ct)
        assert recovered == text
    finally:
        factory.close()


def test_concurrent_encrypt_decrypt():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()
    errors = []

    def worker(thread_id):
        try:
            session = factory.get_session(f"thread-{thread_id}")
            payload = f"thread-{thread_id}-data".encode()
            ct = session.encrypt_bytes(payload)
            recovered = session.decrypt_bytes(ct)
            assert recovered == payload, (
                f"thread {thread_id}: expected {payload!r}, got {recovered!r}"
            )
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    factory.close()
    assert errors == [], f"threads raised errors: {errors}"


def test_config_missing_required_fields():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    config = {
        # ServiceName intentionally omitted
        "ProductID": "prod",
        "Metastore": "memory",
        "KMS": "static",
    }
    with pytest.raises(Exception):
        asherah.setup(config)


def test_multiple_partitions_global_api():
    asherah = _setup_module_api()
    try:
        ct_a = asherah.encrypt_bytes("global-part-a", b"data for a")
        ct_b = asherah.encrypt_bytes("global-part-b", b"data for b")

        # Same partition decrypts fine
        assert asherah.decrypt_bytes("global-part-a", ct_a) == b"data for a"
        assert asherah.decrypt_bytes("global-part-b", ct_b) == b"data for b"

        # Cross-partition must fail
        with pytest.raises(Exception):
            asherah.decrypt_bytes("global-part-b", ct_a)
        with pytest.raises(Exception):
            asherah.decrypt_bytes("global-part-a", ct_b)
    finally:
        asherah.shutdown()
