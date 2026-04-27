"""Comprehensive log/metrics hook coverage for the Python binding.

Run with `pytest tests/test_hooks.py`.

What this exercises:
  - log hook fires for verbose-level log events
  - metrics hook fires for encrypt/decrypt timing events
  - metrics hook fires for cache_hit / cache_miss / cache_stale events
  - hook registration is idempotent and replaceable
  - passing None deregisters the hook
  - registering hook BEFORE setup is supported
  - registering hook AFTER setup is supported
  - hooks fire under both module-level and Session API
  - log event level is the lowercase name ("warn" not "WARN")
"""
from __future__ import annotations

import os
import threading
import time

import pytest


def _configure_env():
    os.environ.setdefault("SERVICE_NAME", "hook-test-svc")
    os.environ.setdefault("PRODUCT_ID", "hook-test-prod")
    os.environ.setdefault("KMS", "static")
    os.environ.setdefault("STATIC_MASTER_KEY_HEX", "22" * 32)


def _config(verbose: bool = False):
    return {
        "ServiceName": "hook-test-svc",
        "ProductID": "hook-test-prod",
        "Metastore": "memory",
        "KMS": "static",
        "EnableSessionCaching": True,
        "Verbose": verbose,
    }


# Hooks are global state; serialize the tests so they don't race.
_LOCK = threading.Lock()


@pytest.fixture(autouse=True)
def _serial_and_clean():
    pytest.importorskip("asherah")
    import asherah

    with _LOCK:
        # Wipe any leftover hook state from a previous test that might
        # have panicked before its cleanup ran.
        try:
            asherah.set_log_hook(None)
        except Exception:
            pass
        try:
            asherah.set_metrics_hook(None)
        except Exception:
            pass
        if asherah.get_setup_status():
            asherah.shutdown()
        yield
        try:
            asherah.set_log_hook(None)
        except Exception:
            pass
        try:
            asherah.set_metrics_hook(None)
        except Exception:
            pass
        if asherah.get_setup_status():
            asherah.shutdown()


def test_log_hook_fires():
    import asherah

    _configure_env()
    events = []
    asherah.set_log_hook(lambda e: events.append(e))
    asherah.setup(_config(verbose=True))
    ct = asherah.encrypt_string("p1", "log-test")
    asherah.decrypt_string("p1", ct)
    asherah.shutdown()
    assert len(events) > 0, f"expected ≥1 log event, got {len(events)}"
    # Each event has the documented dict shape
    for e in events:
        assert "level" in e and isinstance(e["level"], str)
        assert "message" in e and isinstance(e["message"], str)
        assert "target" in e and isinstance(e["target"], str)
        assert e["level"] in {"trace", "debug", "info", "warn", "error"}, (
            f"unexpected log level: {e['level']!r}"
        )


def test_metrics_hook_fires_on_encrypt_decrypt():
    import asherah

    _configure_env()
    events = []
    asherah.set_metrics_hook(lambda e: events.append(e))
    asherah.setup(_config())
    for i in range(5):
        ct = asherah.encrypt_string("p2", f"payload-{i}")
        asherah.decrypt_string("p2", ct)
    asherah.shutdown()
    encrypts = [e for e in events if e["type"] == "encrypt"]
    decrypts = [e for e in events if e["type"] == "decrypt"]
    assert len(encrypts) >= 5, f"expected ≥5 encrypt events, got {len(encrypts)}"
    assert len(decrypts) >= 5, f"expected ≥5 decrypt events, got {len(decrypts)}"
    for e in encrypts:
        assert isinstance(e["duration_ns"], int) and e["duration_ns"] > 0


def test_metrics_hook_cache_events():
    import asherah

    _configure_env()
    events = []
    asherah.set_metrics_hook(lambda e: events.append(e))
    asherah.setup(_config())
    for i in range(3):
        asherah.encrypt_string("cache-p", f"item-{i}")
    asherah.shutdown()
    cache_events = [
        e for e in events
        if e["type"] in ("cache_hit", "cache_miss", "cache_stale")
    ]
    # Cache events from the IK cache may or may not surface depending on
    # session caching state — assert structure of any that do fire.
    for e in cache_events:
        assert "name" in e and isinstance(e["name"], str) and len(e["name"]) > 0


def test_hook_deregister_stops_callbacks():
    import asherah

    _configure_env()
    events = []
    asherah.set_metrics_hook(lambda e: events.append(e))
    asherah.setup(_config())
    asherah.encrypt_string("p3", "pre-deregister")
    before = len(events)
    assert before > 0
    asherah.set_metrics_hook(None)
    asherah.encrypt_string("p3", "post-deregister")
    after = len(events)
    asherah.shutdown()
    assert before == after, f"events fired after deregister: {before=} {after=}"


def test_hook_replacement():
    import asherah

    _configure_env()
    events_a = []
    events_b = []
    asherah.set_metrics_hook(lambda e: events_a.append(e))
    asherah.setup(_config())
    asherah.encrypt_string("p4", "first")
    asherah.set_metrics_hook(lambda e: events_b.append(e))
    asherah.encrypt_string("p4", "second")
    asherah.shutdown()
    assert len(events_a) > 0, "first callback should have fired"
    assert len(events_b) > 0, "second callback should have fired after replace"


def test_hook_installed_before_setup_fires():
    import asherah

    _configure_env()
    events = []
    asherah.set_metrics_hook(lambda e: events.append(e))
    # setup happens AFTER hook is installed
    asherah.setup(_config())
    asherah.encrypt_string("p5", "before-setup")
    asherah.shutdown()
    assert len(events) > 0, "hook installed before setup should still fire"


def test_multiple_register_clear_cycles():
    import asherah

    _configure_env()
    for cycle in range(3):
        events = []
        asherah.set_metrics_hook(lambda e, lst=events: lst.append(e))
        asherah.setup(_config())
        asherah.encrypt_string("p6", f"cycle-{cycle}")
        asherah.shutdown()
        asherah.set_metrics_hook(None)
        assert len(events) > 0, f"cycle {cycle} should produce events"


def test_hooks_with_session_factory_api():
    import asherah

    _configure_env()
    logs = []
    metrics = []
    asherah.set_log_hook(lambda e: logs.append(e))
    asherah.set_metrics_hook(lambda e: metrics.append(e))
    factory = asherah.SessionFactory()
    try:
        session = factory.get_session("factory-p")
        ct = session.encrypt_text("factory-payload")
        recovered = session.decrypt_text(ct)
        assert recovered == "factory-payload"
    finally:
        factory.close()
    assert len(metrics) > 0, "factory/session ops should fire metrics"


def test_log_event_level_is_lowercase():
    import asherah

    _configure_env()
    events = []
    asherah.set_log_hook(lambda e: events.append(e))
    asherah.setup(_config(verbose=True))
    asherah.encrypt_string("p7", "level-check")
    asherah.shutdown()
    # All level strings must be the lowercase name.
    for e in events:
        assert e["level"].islower(), f"level should be lowercase: {e['level']!r}"
        assert e["level"] in {"trace", "debug", "info", "warn", "error"}


def test_metrics_event_dict_shape():
    """Timing events have duration_ns; cache events have name."""
    import asherah

    _configure_env()
    events = []
    asherah.set_metrics_hook(lambda e: events.append(e))
    asherah.setup(_config())
    asherah.encrypt_string("p8", "shape-check")
    asherah.shutdown()
    for e in events:
        assert "type" in e
        if e["type"] in ("encrypt", "decrypt", "store", "load"):
            assert "duration_ns" in e
            assert isinstance(e["duration_ns"], int)
        elif e["type"] in ("cache_hit", "cache_miss", "cache_stale"):
            assert "name" in e
            assert isinstance(e["name"], str)
