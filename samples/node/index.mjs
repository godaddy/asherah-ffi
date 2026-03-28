import asherah from "asherah";
const { SessionFactory } = asherah;

// Testing only — use rdbms/dynamodb + aws in production
process.env.STATIC_MASTER_KEY_HEX = "22".repeat(32);

const config = {
  serviceName: "sample-service",
  productId: "sample-product",
  metastore: "memory", // testing only — use rdbms/dynamodb + aws in production
  kms: "static",       // testing only — use aws in production
  enableSessionCaching: true,
};

// ── 1. Static API (simplest, for scripts/CLIs) ─────────────────────

asherah.setup(config);

// String encrypt/decrypt
const ciphertext = asherah.encryptString("user-123", "Hello from Node.js!");
console.log("[static] encrypted:", ciphertext.slice(0, 60) + "...");
const plaintext = asherah.decryptString("user-123", ciphertext);
console.log("[static] decrypted:", plaintext);

// Buffer (bytes) encrypt/decrypt
const binaryCt = asherah.encrypt("user-123", Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]));
const binaryPt = asherah.decrypt("user-123", binaryCt);
console.log("[static] binary roundtrip:", Buffer.from(binaryPt).toString("hex"));

asherah.shutdown();

// ── 2. Session/Factory API (recommended for applications) ──────────

const factory = new SessionFactory(config);

const session1 = factory.getSession("tenant-a");
const ct1 = session1.encryptString("secret for tenant A");
console.log("[session] tenant-a encrypted:", ct1.slice(0, 60) + "...");
console.log("[session] tenant-a decrypted:", session1.decryptString(ct1));

// Partition isolation: tenant-b cannot decrypt tenant-a's data
const session2 = factory.getSession("tenant-b");
const ct2 = session2.encryptString("secret for tenant B");
console.log("[session] tenant-b decrypted:", session2.decryptString(ct2));

session1.close();
session2.close();
factory.close();

// ── 3. Async API (for event-loop applications) ─────────────────────

await asherah.setupAsync(config);

const asyncCt = await asherah.encryptStringAsync("user-456", "async payload");
console.log("[async] encrypted:", asyncCt.slice(0, 60) + "...");
const asyncPt = await asherah.decryptStringAsync("user-456", asyncCt);
console.log("[async] decrypted:", asyncPt);

await asherah.shutdownAsync();

// ── 4. Production config example (commented out) ───────────────────
//
// asherah.setup({
//   serviceName: "payments-api",
//   productId: "acme-corp",
//   metastore: "rdbms",
//   connectionString: "mysql://user:pass@host:3306/asherah",
//   kms: "aws",
//   regionMap: { "us-west-2": "arn:aws:kms:us-west-2:000:key/abc" },
//   preferredRegion: "us-west-2",
//   enableSessionCaching: true,
//   sessionCacheMaxSize: 1000,
// });
