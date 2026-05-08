"""Rotation, revocation, and sync↔async interop tests for the
asherah-py binding.

The Rust core has comprehensive rotation/revocation coverage in
asherah/tests/. The Python binding had **zero** rotation tests —
test_roundtrip.py only checks happy-path encrypt/decrypt. Without
these tests, an FFI marshalling bug or a Python-specific
config-mapping regression that breaks key rotation slips through.

Tests are kept hermetic: ``Metastore: 'memory'`` + ``KMS:
'test-debug-static'`` produces a hermetic factory that doesn't need
Docker or any network.
"""

import asyncio
import json
import time

import pytest


def _setup_short_expiry(suffix):
    """Use a unique service/product per test to avoid sharing the
    process-global metastore / SK cache across tests within one
    setup/shutdown cycle."""
    pytest.importorskip("asherah")
    import asherah

    config = {
        "ServiceName": f"rot-{suffix}-svc",
        "ProductID": f"rot-{suffix}-prod",
        "Metastore": "memory",
        "KMS": "test-debug-static",
        "ExpireAfter": 1,
        "CheckInterval": 1,
        "EnableSessionCaching": False,
    }
    asherah.setup(config)
    return asherah


def _ik_created(drr_json):
    """Pull ``Key.ParentKeyMeta.Created`` out of a DRR JSON string. The
    Rust core uses Pascal-cased JSON field names for cross-language
    compatibility with the Go reference."""
    drr = json.loads(drr_json)
    assert "Key" in drr and "ParentKeyMeta" in drr["Key"], f"DRR missing Key.ParentKeyMeta: {drr_json}"
    return drr["Key"]["ParentKeyMeta"]["Created"]


# ──────────── Sync rotation ────────────


def test_sync_rotation_across_expiry():
    asherah = _setup_short_expiry("sync")
    try:
        drr1 = asherah.encrypt_bytes("p1", b"before")
        ik1 = _ik_created(drr1)

        # Sleep past expire/precision boundary. With the asherah-config
        # precision clamp + enforce_minimums clamp, expire=1 forces
        # precision=1, so a 1.5-second sleep crosses two precision
        # buckets. 3-second sleep is conservative for slow CI runners.
        time.sleep(3)

        drr2 = asherah.encrypt_bytes("p1", b"after")
        ik2 = _ik_created(drr2)

        assert ik2 > ik1, f"expected IK rotation across expiry: ik2={ik2} should be > ik1={ik1}"
        assert asherah.decrypt_bytes("p1", drr1) == b"before"
        assert asherah.decrypt_bytes("p1", drr2) == b"after"
    finally:
        asherah.shutdown()


# ──────────── Async rotation ────────────


def test_async_rotation_across_expiry():
    asherah = _setup_short_expiry("async")

    async def run():
        drr1 = await asherah.encrypt_bytes_async("p1", b"before-async")
        ik1 = _ik_created(drr1)

        await asyncio.sleep(3)

        drr2 = await asherah.encrypt_bytes_async("p1", b"after-async")
        ik2 = _ik_created(drr2)

        assert ik2 > ik1, f"async path must rotate IK across expiry: ik2={ik2} should be > ik1={ik1}"
        assert (await asherah.decrypt_bytes_async("p1", drr1)) == b"before-async"
        assert (await asherah.decrypt_bytes_async("p1", drr2)) == b"after-async"

    try:
        asyncio.run(run())
    finally:
        asherah.shutdown()


# ──────────── Sync↔async interop after rotation ────────────


def test_sync_async_interop_after_rotation():
    asherah = _setup_short_expiry("interop")

    async def encrypt_async(partition, payload):
        return await asherah.encrypt_bytes_async(partition, payload)

    async def decrypt_async(partition, drr):
        return await asherah.decrypt_bytes_async(partition, drr)

    try:
        loop = asyncio.new_event_loop()
        try:
            drr_sync_pre = asherah.encrypt_bytes("p1", b"sync-pre")
            drr_async_pre = loop.run_until_complete(encrypt_async("p1", b"async-pre"))

            time.sleep(3)

            drr_sync_post = asherah.encrypt_bytes("p1", b"sync-post")
            drr_async_post = loop.run_until_complete(encrypt_async("p1", b"async-post"))

            # Confirm rotation actually happened.
            pre_max = max(_ik_created(drr_sync_pre), _ik_created(drr_async_pre))
            post_min = min(_ik_created(drr_sync_post), _ik_created(drr_async_post))
            assert post_min > pre_max, f"interop path must rotate: postMin={post_min} should be > preMax={pre_max}"

            # 8 round-trips: every encrypt × every decrypt.
            cases = [
                (drr_sync_pre, b"sync-pre"),
                (drr_async_pre, b"async-pre"),
                (drr_sync_post, b"sync-post"),
                (drr_async_post, b"async-post"),
            ]
            for drr, expected in cases:
                assert asherah.decrypt_bytes("p1", drr) == expected, f"sync decrypt of {expected!r}"
                assert loop.run_until_complete(decrypt_async("p1", drr)) == expected, f"async decrypt of {expected!r}"
        finally:
            loop.close()
    finally:
        asherah.shutdown()


# ──────────── Multiple rotation cycles ────────────


def test_multiple_rotation_cycles():
    asherah = _setup_short_expiry("multi")

    async def run():
        history = []
        for i in range(3):
            payload = f"cycle-{i}".encode()
            drr = await asherah.encrypt_bytes_async("p1", payload)
            history.append((drr, payload, _ik_created(drr)))
            await asyncio.sleep(3)

        # Each cycle's IK must be strictly newer than the previous.
        for i in range(1, len(history)):
            assert history[i][2] > history[i - 1][2], (
                f"cycle {i}: ik={history[i][2]} should be > prev ik={history[i - 1][2]}"
            )

        # Every historical DRR still decrypts.
        for drr, payload, _ in history:
            assert (await asherah.decrypt_bytes_async("p1", drr)) == payload

    try:
        asyncio.run(run())
    finally:
        asherah.shutdown()
