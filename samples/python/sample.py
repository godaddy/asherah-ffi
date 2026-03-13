import os

# A static master key for local development only.
# In production, use KMS: "aws" with a proper region map.
os.environ["STATIC_MASTER_KEY_HEX"] = "22" * 32

import asherah_py as asherah

asherah.setup({
    "ServiceName": "sample-service",
    "ProductID": "sample-product",
    "Metastore": "memory",
    "KMS": "static",
    "EnableSessionCaching": True,
})

# Encrypt
ciphertext = asherah.encrypt_string("sample-partition", "Hello from Python!")
print("Encrypted:", ciphertext[:80] + "...")

# Decrypt
recovered = asherah.decrypt_string("sample-partition", ciphertext)
print("Decrypted:", recovered)

asherah.shutdown()
