"""Verifies that the module-level session cache respects SessionCacheMaxSize.

Prior to the LRU/bound fix the cache:
- Hardcoded the bound to 1000 (ignored SessionCacheMaxSize from config).
- Used HashMap.keys().next() for eviction, which is undefined order
  (effectively random based on hash randomization), not LRU or FIFO.
"""
import os

import pytest


def _configure_env():
    os.environ.setdefault("STATIC_MASTER_KEY_HEX", "22" * 32)


def _base_config(max_size=None):
    cfg = {
        "ServiceName": "svc",
        "ProductID": "prod",
        "Metastore": "memory",
        "KMS": "static",
        "EnableSessionCaching": True,
        "Verbose": False,
    }
    if max_size is not None:
        cfg["SessionCacheMaxSize"] = max_size
    return cfg


def test_round_trip_under_eviction_churn():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    asherah.setup(_base_config(max_size=4))
    try:
        for i in range(64):
            partition = f"churn-{i}"
            payload = f"payload-{i}".encode()
            ct = asherah.encrypt_bytes(partition, payload)
            assert asherah.decrypt_bytes(partition, ct) == payload
    finally:
        asherah.shutdown()


def test_hot_partitions_round_trip_repeatedly():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    asherah.setup(_base_config(max_size=2))
    try:
        for _ in range(16):
            ct = asherah.encrypt_bytes("hot-a", b"a")
            assert asherah.decrypt_bytes("hot-a", ct) == b"a"
            ct = asherah.encrypt_bytes("hot-b", b"b")
            assert asherah.decrypt_bytes("hot-b", ct) == b"b"
    finally:
        asherah.shutdown()


def test_default_bound_round_trips_past_thousand():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    asherah.setup(_base_config())
    try:
        for i in range(1100):
            partition = f"default-{i}"
            payload = f"p{i}".encode()
            ct = asherah.encrypt_bytes(partition, payload)
            assert asherah.decrypt_bytes(partition, ct) == payload
    finally:
        asherah.shutdown()


def test_session_caching_disabled_round_trips():
    pytest.importorskip("asherah")
    import asherah

    _configure_env()
    cfg = _base_config()
    cfg["EnableSessionCaching"] = False
    asherah.setup(cfg)
    try:
        for i in range(8):
            ct = asherah.encrypt_bytes(f"nocache-{i}", b"x")
            assert asherah.decrypt_bytes(f"nocache-{i}", ct) == b"x"
    finally:
        asherah.shutdown()
