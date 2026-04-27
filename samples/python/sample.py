import os
import asyncio
import asherah

# Testing only — use rdbms/dynamodb + aws in production.
os.environ["STATIC_MASTER_KEY_HEX"] = "22" * 32

config = {
    "ServiceName": "sample-service",
    "ProductID": "sample-product",
    "Metastore": "memory",  # testing only — use rdbms/dynamodb in production
    "KMS": "static",        # testing only — use aws in production
    "EnableSessionCaching": True,
    # "Verbose": True,      # uncomment to see info-level log events via the log hook
}

# ── 1. Static / module-level API (legacy compatibility) ──────────────
# Mirrors the canonical godaddy/asherah-python API. Easiest path for
# existing callers, single global instance.

asherah.setup(config)
try:
    ct_str = asherah.encrypt_string("user-123", "Hello from Python!")
    print("[static] encrypted:", ct_str[:60] + "...")
    print("[static] decrypted:", asherah.decrypt_string("user-123", ct_str))

    ct_bytes = asherah.encrypt_bytes("user-123", bytes([0xDE, 0xAD, 0xBE, 0xEF]))
    print("[static] binary roundtrip:",
          asherah.decrypt_bytes("user-123", ct_bytes).hex())
finally:
    asherah.shutdown()

# ── 2. Factory / Session API (recommended for applications) ──────────
# Explicit lifecycle, multi-tenant isolation, no hidden singleton.

os.environ.update(
    SERVICE_NAME="sample-service",
    PRODUCT_ID="sample-product",
    METASTORE="memory",
    KMS="static",
)

with asherah.SessionFactory() as factory:
    with factory.get_session("tenant-a") as session:
        ct_a = session.encrypt_text("secret for tenant A")
        print("[session] tenant-a:", session.decrypt_text(ct_a))

    with factory.get_session("tenant-b") as session_b:
        ct_b = session_b.encrypt_text("secret for tenant B")
        print("[session] tenant-b:", session_b.decrypt_text(ct_b))

        # Different partition → cryptographic isolation; tenant-b cannot
        # decrypt tenant-a's ciphertext.
        try:
            session_b.decrypt_text(ct_a)
            print("[session] WARNING: cross-tenant decrypt unexpectedly succeeded")
        except Exception as e:
            print("[session] cross-tenant decrypt correctly rejected:", str(e)[:60])

# ── 3. Async API (for asyncio applications) ──────────────────────────

async def async_example():
    await asherah.setup_async(config)
    try:
        ct = await asherah.encrypt_string_async("user-456", "async payload")
        print("[async] encrypted:", ct[:60] + "...")
        print("[async] decrypted:", await asherah.decrypt_string_async("user-456", ct))
    finally:
        await asherah.shutdown_async()


asyncio.run(async_example())

# ── 4. Log hook (observability) ──────────────────────────────────────
# Receives every log event from the Rust core. Use with verbose=True to
# see info/debug-level setup messages, or always-on for warn/error.

log_events = []
def on_log(event):
    # event = {"level": "trace"|"debug"|"info"|"warn"|"error",
    #          "message": str, "target": str}
    if event["level"] in ("warn", "error"):
        print(f"[log] {event['level']}: {event['message']}")
    log_events.append(event)

asherah.set_log_hook(on_log)
asherah.setup({**config, "Verbose": True})
asherah.encrypt_string("user-789", "with-log-hook")
asherah.shutdown()
print(f"[log] received {len(log_events)} log events total")
asherah.set_log_hook(None)

# ── 5. Metrics hook (observability) ──────────────────────────────────
# Receives encrypt/decrypt timings plus key cache hit/miss/stale counters.

metrics = {"encrypt": 0, "decrypt": 0, "store": 0, "load": 0,
           "cache_hit": 0, "cache_miss": 0, "cache_stale": 0}

def on_metric(event):
    metrics[event["type"]] = metrics.get(event["type"], 0) + 1

asherah.set_metrics_hook(on_metric)
asherah.setup(config)
for i in range(5):
    ct = asherah.encrypt_string("metrics-test", f"payload-{i}")
    asherah.decrypt_string("metrics-test", ct)
asherah.shutdown()
print("[metrics]", metrics)
asherah.set_metrics_hook(None)

# ── 6. Production config (commented out) ─────────────────────────────
#
# asherah.setup({
#     "ServiceName": "payments-api",
#     "ProductID": "acme-corp",
#     "Metastore": "rdbms",
#     "ConnectionString": "mysql://user:pass@host:3306/asherah",
#     "SQLMetastoreDBType": "mysql",
#     "KMS": "aws",
#     "RegionMap": {"us-west-2": "arn:aws:kms:us-west-2:000:key/abc"},
#     "PreferredRegion": "us-west-2",
#     "EnableSessionCaching": True,
#     "SessionCacheMaxSize": 1000,
# })
