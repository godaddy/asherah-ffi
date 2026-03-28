import os
import asyncio
import asherah

# Testing only — use rdbms/dynamodb + aws in production
os.environ["STATIC_MASTER_KEY_HEX"] = "22" * 32

config = {
    "ServiceName": "sample-service",
    "ProductID": "sample-product",
    "Metastore": "memory",  # testing only — use rdbms/dynamodb in production
    "KMS": "static",        # testing only — use aws in production
    "EnableSessionCaching": True,
}

# ── 1. Static API (simplest, for scripts/CLIs) ─────────────────────

asherah.setup(config)
try:
    # String encrypt/decrypt
    ciphertext = asherah.encrypt_string("user-123", "Hello from Python!")
    print("[static] encrypted:", ciphertext[:60] + "...")
    plaintext = asherah.decrypt_string("user-123", ciphertext)
    print("[static] decrypted:", plaintext)

    # Bytes encrypt/decrypt
    binary_ct = asherah.encrypt_bytes("user-123", bytes([0xDE, 0xAD, 0xBE, 0xEF]))
    binary_pt = asherah.decrypt_bytes("user-123", binary_ct)
    print("[static] binary roundtrip:", binary_pt.hex())
finally:
    asherah.shutdown()

# ── 2. Session/Factory API (recommended for applications) ──────────

os.environ.update(
    SERVICE_NAME="sample-service",
    PRODUCT_ID="sample-product",
    METASTORE="memory",
    KMS="static",
)

with asherah.SessionFactory() as factory:
    with factory.get_session("tenant-a") as session:
        ct = session.encrypt_text("secret for tenant A")
        print("[session] tenant-a encrypted:", ct[:60] + "...")
        print("[session] tenant-a decrypted:", session.decrypt_text(ct))

    with factory.get_session("tenant-b") as session:
        ct = session.encrypt_text("secret for tenant B")
        print("[session] tenant-b decrypted:", session.decrypt_text(ct))

# ── 3. Async API (for event-loop applications) ─────────────────────

async def async_example():
    await asherah.setup_async(config)
    try:
        ct = await asherah.encrypt_string_async("user-456", "async payload")
        print("[async] encrypted:", ct[:60] + "...")
        pt = await asherah.decrypt_string_async("user-456", ct)
        print("[async] decrypted:", pt)
    finally:
        await asherah.shutdown_async()

asyncio.run(async_example())

# ── 4. Production config example (commented out) ───────────────────
#
# asherah.setup({
#     "ServiceName": "payments-api",
#     "ProductID": "acme-corp",
#     "Metastore": "rdbms",
#     "ConnectionString": "mysql://user:pass@host:3306/asherah",
#     "KMS": "aws",
#     "RegionMap": {"us-west-2": "arn:aws:kms:us-west-2:000:key/abc"},
#     "PreferredRegion": "us-west-2",
#     "EnableSessionCaching": True,
#     "SessionCacheMaxSize": 1000,
# })
