import asherah from "asherah";

// A static master key for local development only.
// In production, use KMS: "aws" with a proper region map.
process.env.STATIC_MASTER_KEY_HEX = "22".repeat(32);

asherah.setup({
  serviceName: "sample-service",
  productId: "sample-product",
  metastore: "memory",
  kms: "static",
  enableSessionCaching: true,
});

// Encrypt
const ciphertext = asherah.encryptString("sample-partition", "Hello from Node.js!");
console.log("Encrypted:", ciphertext.slice(0, 80) + "...");

// Decrypt
const recovered = asherah.decryptString("sample-partition", ciphertext);
console.log("Decrypted:", recovered);

asherah.shutdown();
