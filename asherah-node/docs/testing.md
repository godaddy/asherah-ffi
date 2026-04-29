# Testing your application code

Strategies for unit and integration tests of code that uses Asherah.
None of these require AWS or a database — Asherah ships with an
in-memory metastore and a static master-key mode for tests.

## In-memory + static-KMS test fixture (Jest)

```javascript
// __tests__/fixtures/asherah.js
import { SessionFactory } from "asherah";

export function buildTestFactory() {
  process.env.STATIC_MASTER_KEY_HEX = "22".repeat(32);
  return new SessionFactory({
    serviceName: "test-svc",
    productId: "test-prod",
    metastore: "memory",        // no DB, no AWS
    kms: "static",
    enableSessionCaching: true,
  });
}
```

```javascript
// __tests__/repository.test.js
import { buildTestFactory } from "./fixtures/asherah";
import { CardRepository } from "../src/repository";

describe("CardRepository", () => {
  let factory;
  beforeAll(() => { factory = buildTestFactory(); });
  afterAll(() => factory.close());

  it("round-trips through Asherah", () => {
    const session = factory.getSession("tenant-A");
    try {
      const ct = session.encryptString("4242 4242 4242 4242");
      expect(session.decryptString(ct)).toBe("4242 4242 4242 4242");
    } finally {
      session.close();
    }
  });
});
```

Hooks are process-global — tests that exercise them must run serially.
Jest:

```javascript
describe.serial("hooks", () => { /* ... */ });
// or use --runInBand on the CLI when the whole suite includes hook tests.
```

Vitest equivalent:

```javascript
describe.sequential("hooks", () => { /* ... */ });
```

## Mocking your wrapper, not Asherah

The cleanest pattern: build a thin wrapper around `SessionFactory` in
your application code, and mock the wrapper in tests. Mocking native
methods directly is brittle — they're addressed via `require`'d
native bindings that don't compose with Jest's module mocking
cleanly.

```javascript
// src/protector.js
import { SessionFactory } from "asherah";

export class Protector {
  constructor(factory) { this.factory = factory; }

  async protect(partitionId, plaintext) {
    const session = this.factory.getSession(partitionId);
    try {
      return await session.encryptStringAsync(plaintext);
    } finally {
      session.close();
    }
  }
}
```

```javascript
// __tests__/orderService.test.js
import { jest } from "@jest/globals";
import { OrderService } from "../src/orderService";

it("calls Protector.protect with order partition", async () => {
  const protector = { protect: jest.fn().mockResolvedValue("ct-token") };
  const orders = new OrderService({ protector });

  await orders.create({ partitionId: "merchant-7", payload: "card data" });

  expect(protector.protect).toHaveBeenCalledWith("merchant-7", "card data");
});
```

The integration test (the one that actually calls Asherah) uses the
real factory from `buildTestFactory()`; unit tests of consumers mock
`Protector` directly.

## Asserting envelope shape

`session.encryptString(...)` returns a `DataRowRecord` JSON envelope.
For tests asserting on the wire shape (interop with non-Node services):

```javascript
it("envelope has expected shape", () => {
  const session = factory.getSession("partition-1");
  try {
    const json = session.encryptString("hello");
    const env = JSON.parse(json);
    expect(env).toHaveProperty("Key.ParentKeyMeta");
    expect(env).toHaveProperty("Data");
    expect(env).toHaveProperty("Created");
  } finally {
    session.close();
  }
});
```

## Testing empty-input handling

Empty ciphertext is rejected at the C# / native boundary. Tests that
verify your wrapper handles this gracefully:

```javascript
it("rejects empty ciphertext with informative message", () => {
  const session = factory.getSession("p");
  try {
    expect(() => session.decryptString("")).toThrow(/empty|expected value/i);
  } finally {
    session.close();
  }
});
```

## Testing with the SQL metastore (Testcontainers)

For integration tests against MySQL or Postgres, use Testcontainers to
start a containerized database:

```javascript
import { GenericContainer } from "testcontainers";
import { SessionFactory } from "asherah";

let container, factory;

beforeAll(async () => {
  container = await new GenericContainer("mysql:8.0")
    .withEnvironment({ MYSQL_ROOT_PASSWORD: "test", MYSQL_DATABASE: "asherah" })
    .withExposedPorts(3306)
    .start();

  process.env.STATIC_MASTER_KEY_HEX = "22".repeat(32);
  factory = new SessionFactory({
    serviceName: "test-svc",
    productId: "test-prod",
    metastore: "rdbms",
    connectionString:
      `mysql://root:test@${container.getHost()}:${container.getMappedPort(3306)}/asherah`,
    sqlMetastoreDbType: "mysql",
    kms: "static",
  });
});

afterAll(async () => {
  factory.close();
  await container.stop();
});
```

Asherah's RDBMS metastore creates the schema automatically on first
use; no migration step required.

## Determinism caveats

- **AES-GCM nonces are random per encrypt call.** The ciphertext is
  non-deterministic — `encryptString("x")` produces a different
  envelope on every call. Don't compare ciphertext bytes; round-trip
  through `decryptString` and compare plaintexts.
- **Session caching.** `factory.getSession("p")` returns a cached
  session by default. Tests asserting per-call behaviour (e.g. a
  metastore call count) should disable caching with
  `enableSessionCaching: false`.
- **Hooks are process-global.** A test registering a log hook will
  see records from other tests in the same process if they aren't
  serialized. Use `--runInBand` (Jest) or `describe.sequential`
  (Vitest) and clear hooks in `afterEach`.

## Native binary resolution in tests

The npm package ships native binaries via optional dependencies.
Tests run against your project's `node_modules/asherah/` and pick the
right binary by RID automatically. If a test fails with "module not
found" or "wrong architecture":

- Check `node -e "console.log(process.platform, process.arch)"` to
  confirm what your tests are running on.
- For Alpine/musl: ensure your CI image actually has musl libc;
  `npm install` on a glibc image will pull the glibc binary which
  fails at runtime on Alpine.
- For repo development against a local `cargo build`: set
  `ASHERAH_NODE_NATIVE` (if your project supports it) or
  `npm install ../asherah-ffi/asherah-node` to use the local binary.
