"""End-to-end test for the asherah PyPI package."""
import os
import sys

def main():
    # Set required env vars for static/memory config
    os.environ["SERVICE_NAME"] = "test-service"
    os.environ["PRODUCT_ID"] = "test-product"
    os.environ["KMS"] = "static"
    os.environ["STATIC_MASTER_KEY_HEX"] = "22" * 32
    os.environ["Metastore"] = "memory"

    import asherah_py as asherah

    print(f"asherah_py module: {asherah}")
    print(f"Python: {sys.version}")
    print(f"Platform: {sys.platform}")

    # Test 1: Basic encrypt/decrypt roundtrip
    print("\n--- Test 1: Basic roundtrip ---")
    factory = asherah.SessionFactory()
    session = factory.get_session("test-partition")

    plaintext = b"hello from PyPI package test"
    encrypted = session.encrypt_bytes(plaintext)
    print(f"Encrypted: {encrypted[:80]}...")

    decrypted = session.decrypt_bytes(encrypted)
    assert decrypted == plaintext, f"Decryption mismatch: {decrypted!r} != {plaintext!r}"
    print(f"Decrypted: {decrypted}")
    print("PASS")

    # Test 2: Unicode payload
    print("\n--- Test 2: Unicode payload ---")
    unicode_text = "你好世界 🔐 Hello мир".encode("utf-8")
    enc2 = session.encrypt_bytes(unicode_text)
    dec2 = session.decrypt_bytes(enc2)
    assert dec2 == unicode_text, f"Unicode mismatch: {dec2!r} != {unicode_text!r}"
    print(f"Decrypted: {dec2.decode('utf-8')}")
    print("PASS")

    # Test 3: Binary payload (all 256 byte values)
    print("\n--- Test 3: Binary payload ---")
    binary_data = bytes(range(256))
    enc3 = session.encrypt_bytes(binary_data)
    dec3 = session.decrypt_bytes(enc3)
    assert dec3 == binary_data, "Binary roundtrip failed"
    print(f"Binary roundtrip: {len(dec3)} bytes")
    print("PASS")

    # Test 4: Empty payload
    print("\n--- Test 4: Empty payload ---")
    enc4 = session.encrypt_bytes(b"")
    dec4 = session.decrypt_bytes(enc4)
    assert dec4 == b"", f"Empty roundtrip failed: {dec4!r}"
    print("PASS")

    # Test 5: Multiple partitions
    print("\n--- Test 5: Multiple partitions ---")
    session2 = factory.get_session("other-partition")
    enc5 = session2.encrypt_bytes(b"partition test")
    dec5 = session2.decrypt_bytes(enc5)
    assert dec5 == b"partition test"
    print("PASS")

    # Test 6: Large payload
    print("\n--- Test 6: Large payload (1MB) ---")
    large = b"A" * (1024 * 1024)
    enc6 = session.encrypt_bytes(large)
    dec6 = session.decrypt_bytes(enc6)
    assert dec6 == large, "Large payload roundtrip failed"
    print(f"Large roundtrip: {len(dec6)} bytes")
    print("PASS")

    factory.close()
    print("\n=== All tests passed ===")


if __name__ == "__main__":
    main()
