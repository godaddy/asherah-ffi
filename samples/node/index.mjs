import asherah from "asherah";
const { SessionFactory } = asherah;

// Testing only — use rdbms/dynamodb + aws in production.
process.env.STATIC_MASTER_KEY_HEX = "22".repeat(32);

const config = {
  serviceName: "sample-service",
  productId: "sample-product",
  metastore: "memory",  // testing only — use rdbms/dynamodb in production
  kms: "static",        // testing only — use aws in production
  enableSessionCaching: true,
  // verbose: true,     // uncomment to see info-level log events via the log hook
};

// ── 1. Static / module-level API (legacy compatibility) ──────────────
// Mirrors the canonical godaddy/asherah-node API. Easiest path for
// existing callers, single global instance.

asherah.setup(config);

const staticStringCt = asherah.encryptString("user-123", "Hello from Node.js!");
console.log("[static] encrypted:", staticStringCt.slice(0, 60) + "...");
console.log("[static] decrypted:", asherah.decryptString("user-123", staticStringCt));

const staticBinaryCt = asherah.encrypt("user-123", Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]));
console.log("[static] binary roundtrip:",
  Buffer.from(asherah.decrypt("user-123", staticBinaryCt)).toString("hex"));

asherah.shutdown();

// ── 2. Factory / Session API (recommended for applications) ──────────
// Explicit lifecycle, multi-tenant isolation, no hidden singleton.

const factory = new SessionFactory(config);

const sessionA = factory.getSession("tenant-a");
const ctA = sessionA.encryptString("secret for tenant A");
console.log("[session] tenant-a:", sessionA.decryptString(ctA));

// Different partition → cryptographic isolation: tenant B's session
// cannot decrypt tenant A's ciphertext.
const sessionB = factory.getSession("tenant-b");
const ctB = sessionB.encryptString("secret for tenant B");
console.log("[session] tenant-b:", sessionB.decryptString(ctB));
try {
  sessionB.decryptString(ctA);
  console.log("[session] WARNING: cross-tenant decrypt unexpectedly succeeded");
} catch (e) {
  console.log("[session] cross-tenant decrypt correctly rejected:", e.message.slice(0, 60));
}

sessionA.close();
sessionB.close();
factory.close();

// ── 3. Async API (non-blocking for event loop) ───────────────────────

await asherah.setupAsync(config);

const asyncCt = await asherah.encryptStringAsync("user-456", "async payload");
console.log("[async] encrypted:", asyncCt.slice(0, 60) + "...");
console.log("[async] decrypted:", await asherah.decryptStringAsync("user-456", asyncCt));

await asherah.shutdownAsync();

// ── 4. Log hook (observability) ──────────────────────────────────────
// Receives every log event from the Rust core. Use with `verbose: true`
// to see info/debug-level setup messages, or always-on to capture warn/
// error events.

const logEvents = [];
asherah.setLogHook((event) => {
  // event = { level: 'trace'|'debug'|'info'|'warn'|'error', message, target }
  if (event.level === "warn" || event.level === "error") {
    console.log(`[log] ${event.level}: ${event.message}`);
  }
  logEvents.push(event);
});

asherah.setup({ ...config, verbose: true });
asherah.encryptString("user-789", "with-log-hook");
asherah.shutdown();
// Give the threadsafe-function callbacks a tick to flush.
await new Promise((r) => setTimeout(r, 50));
console.log(`[log] received ${logEvents.length} log events total`);
asherah.setLogHook(null);

// ── 5. Metrics hook (observability) ──────────────────────────────────
// Receives encrypt/decrypt timing events plus key-cache hit/miss/stale.

const metrics = { encrypt: 0, decrypt: 0, store: 0, load: 0,
                  cacheHit: 0, cacheMiss: 0, cacheStale: 0 };
asherah.setMetricsHook((event) => {
  switch (event.type) {
    case "encrypt":     metrics.encrypt++;   break;
    case "decrypt":     metrics.decrypt++;   break;
    case "store":       metrics.store++;     break;
    case "load":        metrics.load++;      break;
    case "cache_hit":   metrics.cacheHit++;  break;
    case "cache_miss":  metrics.cacheMiss++; break;
    case "cache_stale": metrics.cacheStale++; break;
  }
});

asherah.setup(config);
for (let i = 0; i < 5; i++) {
  const ct = asherah.encryptString("metrics-test", `payload-${i}`);
  asherah.decryptString("metrics-test", ct);
}
asherah.shutdown();
await new Promise((r) => setTimeout(r, 50));
console.log("[metrics]", JSON.stringify(metrics));
asherah.setMetricsHook(null);

// ── 6. Production config (commented out) ─────────────────────────────
//
// asherah.setup({
//   serviceName: "payments-api",
//   productId: "acme-corp",
//   metastore: "rdbms",
//   connectionString: "mysql://user:pass@host:3306/asherah",
//   sqlMetastoreDbType: "mysql",
//   kms: "aws",
//   regionMap: { "us-west-2": "arn:aws:kms:us-west-2:000:key/abc" },
//   preferredRegion: "us-west-2",
//   enableSessionCaching: true,
//   sessionCacheMaxSize: 1000,
// });
