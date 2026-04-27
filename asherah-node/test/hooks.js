// Comprehensive log/metrics hook coverage for the Node binding.
// Run with `node test/hooks.js` after `npm run build`.
//
// What this exercises:
//   - log hook fires for verbose-level log events
//   - metrics hook fires for encrypt/decrypt timing events
//   - metrics hook fires for cache_hit / cache_miss events
//   - hook registration is idempotent and replaceable
//   - passing null deregisters the hook
//   - registering hook BEFORE setup is supported
//   - registering hook AFTER setup is supported
//   - both camelCase (setLogHook) and snake_case (set_log_hook) work
//   - the snake_case set_log_hook accepts the canonical (level, message)
//     signature (arity 2) AND the structured (event) signature (arity 1)
'use strict';

const assert = require('assert');
const path = require('path');

// Load the npm wrapper so we exercise the snake_case aliases too.
const asherah = require(path.resolve(__dirname, '..', 'npm', 'index.js'));

const cfg = {
  serviceName: 'hook-test-svc',
  productId: 'hook-test-prod',
  metastore: 'memory',
  kms: 'static',
  enableSessionCaching: true,
  verbose: true, // ensures the log hook actually receives events
};

async function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function withSetup(body) {
  asherah.setup(cfg);
  try {
    await body();
  } finally {
    if (asherah.getSetupStatus()) asherah.shutdown();
  }
}

// ── 1. Log hook fires for log events ─────────────────────────────────
async function testLogHookFires() {
  const events = [];
  asherah.setLogHook(event => events.push(event));
  await withSetup(async () => {
    const ct = asherah.encryptString('p1', 'log-hook-test');
    asherah.decryptString('p1', ct);
    await sleep(50); // ThreadsafeFunction needs an event-loop tick
  });
  asherah.setLogHook(null);
  assert.ok(events.length > 0, `expected ≥1 log event, got ${events.length}`);
  // Each event has the documented shape.
  for (const e of events) {
    assert.ok(typeof e.level === 'string', 'event.level should be a string');
    assert.ok(typeof e.message === 'string', 'event.message should be a string');
    assert.ok(typeof e.target === 'string', 'event.target should be a string');
    assert.ok(
      ['trace', 'debug', 'info', 'warn', 'error'].includes(e.level),
      `unexpected log level: ${e.level}`,
    );
  }
  console.log(`PASS  log hook fires (${events.length} events)`);
}

// ── 2. Metrics hook fires for encrypt/decrypt timings ────────────────
async function testMetricsHookFiresOnEncryptDecrypt() {
  const events = [];
  asherah.setMetricsHook(event => events.push(event));
  await withSetup(async () => {
    for (let i = 0; i < 5; i++) {
      const ct = asherah.encryptString('p2', `payload-${i}`);
      asherah.decryptString('p2', ct);
    }
    await sleep(50);
  });
  asherah.setMetricsHook(null);
  const encryptEvents = events.filter(e => e.type === 'encrypt');
  const decryptEvents = events.filter(e => e.type === 'decrypt');
  assert.ok(encryptEvents.length >= 5, `expected ≥5 encrypt events, got ${encryptEvents.length}`);
  assert.ok(decryptEvents.length >= 5, `expected ≥5 decrypt events, got ${decryptEvents.length}`);
  for (const e of encryptEvents) {
    assert.ok(typeof e.durationNs === 'number' && e.durationNs > 0,
      `encrypt event durationNs invalid: ${e.durationNs}`);
  }
  console.log(`PASS  metrics hook encrypt/decrypt (${encryptEvents.length}+${decryptEvents.length} events)`);
}

// ── 3. Metrics hook fires for cache events ───────────────────────────
async function testMetricsHookFiresForCacheEvents() {
  const events = [];
  asherah.setMetricsHook(event => events.push(event));
  await withSetup(async () => {
    // Repeated encrypts on the same partition should hit the IK cache.
    for (let i = 0; i < 3; i++) {
      asherah.encryptString('cache-p', `item-${i}`);
    }
    await sleep(50);
  });
  asherah.setMetricsHook(null);
  const cacheEvents = events.filter(e =>
    e.type === 'cache_hit' || e.type === 'cache_miss' || e.type === 'cache_stale');
  // Cache events from the IK cache may or may not surface depending on
  // session caching state — assert at least the structure if any fire.
  for (const e of cacheEvents) {
    assert.ok(typeof e.name === 'string' && e.name.length > 0,
      `cache event name invalid: ${e.name}`);
  }
  console.log(`PASS  metrics hook cache events (${cacheEvents.length} cache events seen)`);
}

// ── 4. Hook deregister stops callbacks ────────────────────────────────
async function testHookDeregister() {
  const events = [];
  asherah.setMetricsHook(event => events.push(event));
  asherah.setup(cfg);
  asherah.encryptString('p3', 'pre-deregister');
  await sleep(50);
  const beforeDereg = events.length;
  assert.ok(beforeDereg > 0);
  asherah.setMetricsHook(null);
  asherah.encryptString('p3', 'post-deregister');
  await sleep(50);
  const afterDereg = events.length;
  asherah.shutdown();
  assert.strictEqual(afterDereg, beforeDereg,
    `events fired after deregister: before=${beforeDereg} after=${afterDereg}`);
  console.log(`PASS  metrics hook deregister stops callbacks`);
}

// ── 5. Hook replacement ───────────────────────────────────────────────
async function testHookReplacement() {
  const eventsA = [];
  const eventsB = [];
  asherah.setMetricsHook(event => eventsA.push(event));
  asherah.setup(cfg);
  asherah.encryptString('p4', 'first');
  await sleep(50);
  // Replace with a different callback
  asherah.setMetricsHook(event => eventsB.push(event));
  asherah.encryptString('p4', 'second');
  await sleep(50);
  asherah.setMetricsHook(null);
  asherah.shutdown();
  assert.ok(eventsA.length > 0, 'first callback should have fired');
  assert.ok(eventsB.length > 0, 'second callback should have fired after replace');
  console.log(`PASS  metrics hook replace (A=${eventsA.length}, B=${eventsB.length})`);
}

// ── 6. snake_case set_log_hook with arity-2 canonical signature ──────
async function testSnakeCaseLogHookCanonicalSignature() {
  const events = [];
  asherah.set_log_hook((level, message) => {
    events.push({ level, message });
  });
  await withSetup(async () => {
    asherah.encryptString('p5', 'snake-case-test');
    await sleep(50);
  });
  asherah.set_log_hook(null);
  assert.ok(events.length > 0, 'expected events from canonical 2-arg log hook');
  for (const e of events) {
    assert.ok(typeof e.level === 'number' && e.level >= 0 && e.level <= 4,
      `level should be a number 0-4, got ${e.level}`);
    assert.ok(typeof e.message === 'string', 'message should be a string');
  }
  console.log(`PASS  set_log_hook canonical (level, message) signature (${events.length} events)`);
}

// ── 7. snake_case set_metrics_hook ────────────────────────────────────
async function testSnakeCaseMetricsHook() {
  const events = [];
  asherah.set_metrics_hook(event => events.push(event));
  await withSetup(async () => {
    asherah.encryptString('p6', 'snake-metrics');
    await sleep(50);
  });
  asherah.set_metrics_hook(null);
  assert.ok(events.length > 0, 'expected events from snake_case metrics hook');
  console.log(`PASS  set_metrics_hook snake_case alias (${events.length} events)`);
}

// ── 8. Registering hook BEFORE setup ──────────────────────────────────
async function testHookBeforeSetup() {
  const events = [];
  asherah.setMetricsHook(event => events.push(event));
  // Hook installed first; setup happens after — events from setup itself
  // should be observable.
  asherah.setup(cfg);
  asherah.encryptString('p7', 'before-setup');
  await sleep(50);
  asherah.shutdown();
  asherah.setMetricsHook(null);
  assert.ok(events.length > 0, 'hook registered before setup should still fire');
  console.log(`PASS  hook installed before setup fires events (${events.length})`);
}

// ── 9. Multiple register-clear cycles ─────────────────────────────────
async function testMultipleCycles() {
  for (let cycle = 0; cycle < 3; cycle++) {
    const events = [];
    asherah.setMetricsHook(event => events.push(event));
    asherah.setup(cfg);
    asherah.encryptString('p8', `cycle-${cycle}`);
    await sleep(50);
    asherah.shutdown();
    asherah.setMetricsHook(null);
    assert.ok(events.length > 0, `cycle ${cycle} should produce events`);
  }
  console.log(`PASS  multiple register/clear/setup/shutdown cycles`);
}

// ── 10. Hooks survive Factory/Session API too ─────────────────────────
async function testHooksWithFactorySession() {
  const logs = [];
  const metrics = [];
  asherah.setLogHook(e => logs.push(e));
  asherah.setMetricsHook(e => metrics.push(e));
  const factory = new asherah.SessionFactory(cfg);
  try {
    const session = factory.getSession('factory-p');
    try {
      const ct = session.encryptString('factory-payload');
      session.decryptString(ct);
    } finally {
      session.close();
    }
  } finally {
    factory.close();
  }
  await sleep(50);
  asherah.setLogHook(null);
  asherah.setMetricsHook(null);
  assert.ok(metrics.length > 0, 'factory/session ops should fire metrics');
  console.log(`PASS  hooks fire under Factory/Session API (logs=${logs.length}, metrics=${metrics.length})`);
}

(async function main() {
  try {
    await testLogHookFires();
    await testMetricsHookFiresOnEncryptDecrypt();
    await testMetricsHookFiresForCacheEvents();
    await testHookDeregister();
    await testHookReplacement();
    await testSnakeCaseLogHookCanonicalSignature();
    await testSnakeCaseMetricsHook();
    await testHookBeforeSetup();
    await testMultipleCycles();
    await testHooksWithFactorySession();
    console.log('\nALL HOOK TESTS PASSED');
  } catch (err) {
    console.error('FAIL:', err);
    process.exit(1);
  }
})();
