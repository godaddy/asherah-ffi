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


# ── Null / None / empty input contract ─────────────────────────────────
#
# Contract:
#   - None for str/bytes parameter is a programming error → TypeError
#     (raised by PyO3 type conversion before reaching native code).
#   - empty str / empty bytes is a valid encrypt that round-trips back
#     to empty.
#   - decrypting empty input is invalid JSON and must raise.


def test_module_encrypt_none_partition_raises():
    asherah = _setup_module_api()
    try:
        with pytest.raises(TypeError):
            asherah.encrypt_bytes(None, b"x")
    finally:
        asherah.shutdown()


def test_module_encrypt_none_data_raises():
    asherah = _setup_module_api()
    try:
        with pytest.raises(TypeError):
            asherah.encrypt_bytes("p", None)
    finally:
        asherah.shutdown()


def test_module_encrypt_string_none_text_raises():
    asherah = _setup_module_api()
    try:
        with pytest.raises(TypeError):
            asherah.encrypt_string("p", None)
    finally:
        asherah.shutdown()


def test_module_decrypt_none_raises():
    asherah = _setup_module_api()
    try:
        with pytest.raises(TypeError):
            asherah.decrypt_bytes("p", None)
        with pytest.raises(TypeError):
            asherah.decrypt_string("p", None)
    finally:
        asherah.shutdown()


def test_module_empty_string_round_trip():
    asherah = _setup_module_api()
    try:
        ct = asherah.encrypt_string("py-empty-str", "")
        assert isinstance(ct, str) and len(ct) > 0
        assert asherah.decrypt_string("py-empty-str", ct) == ""
    finally:
        asherah.shutdown()


def test_module_decrypt_empty_string_raises():
    asherah = _setup_module_api()
    try:
        with pytest.raises(Exception):
            asherah.decrypt_string("py-empty-decrypt", "")
        with pytest.raises(Exception):
            asherah.decrypt_bytes("py-empty-decrypt", "")
    finally:
        asherah.shutdown()


def test_session_none_args_raise():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()
    try:
        session = factory.get_session("py-session-null")
        with pytest.raises(TypeError):
            session.encrypt_bytes(None)
        with pytest.raises(TypeError):
            session.encrypt_text(None)
        with pytest.raises(TypeError):
            session.decrypt_bytes(None)
        with pytest.raises(TypeError):
            session.decrypt_text(None)
    finally:
        factory.close()


def test_session_empty_string_round_trip():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()
    try:
        session = factory.get_session("py-empty-session-str")
        ct = session.encrypt_text("")
        assert isinstance(ct, str) and len(ct) > 0
        assert session.decrypt_text(ct) == ""
    finally:
        factory.close()


def test_session_decrypt_empty_string_raises():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()
    try:
        session = factory.get_session("py-empty-decrypt-sess")
        with pytest.raises(Exception):
            session.decrypt_text("")
        with pytest.raises(Exception):
            session.decrypt_bytes("")
    finally:
        factory.close()


@pytest.mark.asyncio
async def test_async_none_args_raise():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()
    try:
        session = factory.get_session("py-async-null")
        with pytest.raises(TypeError):
            await session.encrypt_bytes_async(None)
        with pytest.raises(TypeError):
            await session.decrypt_bytes_async(None)
    finally:
        factory.close()


@pytest.mark.asyncio
async def test_async_empty_string_round_trip():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()
    try:
        session = factory.get_session("py-async-empty-str")
        ct = await session.encrypt_bytes_async(b"")
        assert isinstance(ct, str) and len(ct) > 0
        recovered = await session.decrypt_bytes_async(ct)
        assert recovered == b""
    finally:
        factory.close()


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


# ── Async tests (Session-level, native tokio coroutines) ───────────


@pytest.mark.asyncio
async def test_async_encrypt_decrypt_roundtrip():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()
    session = factory.get_session("async-roundtrip")

    payload = b"async test payload"
    ciphertext = await session.encrypt_bytes_async(payload)
    assert isinstance(ciphertext, str)

    recovered = await session.decrypt_bytes_async(ciphertext)
    assert recovered == payload

    factory.close()


@pytest.mark.asyncio
async def test_async_empty_payload():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()
    session = factory.get_session("async-empty")

    ciphertext = await session.encrypt_bytes_async(b"")
    recovered = await session.decrypt_bytes_async(ciphertext)
    assert recovered == b""

    factory.close()


@pytest.mark.asyncio
async def test_async_concurrent():
    pytest.importorskip("asherah")
    import asyncio
    import asherah

    _configure_env()
    factory = asherah.SessionFactory()

    async def worker(i):
        session = factory.get_session(f"async-concurrent-{i}")
        payload = f"async-data-{i}".encode()
        ct = await session.encrypt_bytes_async(payload)
        recovered = await session.decrypt_bytes_async(ct)
        assert recovered == payload

    await asyncio.gather(*[worker(i) for i in range(10)])
    factory.close()
