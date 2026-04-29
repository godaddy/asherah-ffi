# Framework integration

How to wire Asherah into common Node.js web frameworks and runtimes.
The patterns are similar across frameworks: **call `setup()` (or
construct the `SessionFactory`) at startup, hook observability to your
existing logger/metrics, and call `shutdown()` (or `factory.close()`)
on graceful shutdown.**

For DI-style scenarios (NestJS), inject the factory and resolve
sessions per request. For middleware-style frameworks (Express,
Fastify, Koa), attach the factory to the app/context.

## Express

```javascript
import express from "express";
import asherah, { SessionFactory } from "asherah";

const app = express();
app.use(express.json());

const factory = new SessionFactory({
  serviceName: process.env.SERVICE_NAME,
  productId: process.env.PRODUCT_ID,
  metastore: "dynamodb",
  dynamoDbTableName: "AsherahKeys",
  dynamoDbRegion: "us-east-1",
  kms: "aws",
  regionMap: JSON.parse(process.env.ASHERAH_REGION_MAP),
  preferredRegion: "us-east-1",
});

asherah.setLogHook((level, target, message) => {
  // Forward to your structured logger (pino, winston, bunyan, …).
  req.log?.info?.({ asherah: { level, target } }, message);
});

app.post("/users/:id/secret", async (req, res, next) => {
  try {
    const session = factory.getSession(req.params.id);
    try {
      const ciphertext = await session.encryptStringAsync(req.body.secret);
      res.json({ token: ciphertext });
    } finally {
      session.close();
    }
  } catch (err) {
    next(err);
  }
});

const server = app.listen(3000);

// Graceful shutdown: drain in-flight requests, then close the factory.
process.on("SIGTERM", () => {
  server.close(() => {
    factory.close();
  });
});
```

> Session caching is on by default — `factory.getSession("u")` returns
> a cached session if one exists for that partition. The
> `try { ... } finally { session.close(); }` pattern returns the
> session to the cache; it's not actually destroyed until the cache
> evicts it.

## Fastify

```javascript
import Fastify from "fastify";
import asherah, { SessionFactory } from "asherah";

const fastify = Fastify({ logger: true });

const factory = new SessionFactory(yourConfig);

// Bridge Asherah log records into Fastify's pino logger.
asherah.setLogHook((level, target, message) => {
  const fn = level === "error" ? "error"
           : level === "warn"  ? "warn"
           : level === "info"  ? "info"
           : "debug";
  fastify.log[fn]({ target }, message);
});

fastify.decorate("asherah", factory);

fastify.post("/protect", async (req, reply) => {
  const session = req.server.asherah.getSession(req.body.tenantId);
  try {
    return { token: await session.encryptStringAsync(req.body.payload) };
  } finally {
    session.close();
  }
});

fastify.addHook("onClose", async () => factory.close());

await fastify.listen({ port: 3000 });
```

## NestJS

```typescript
import { Module, Inject, Injectable, OnModuleDestroy } from "@nestjs/common";
import asherah, { SessionFactory } from "asherah";

const ASHERAH_FACTORY = Symbol("ASHERAH_FACTORY");

@Module({
  providers: [
    {
      provide: ASHERAH_FACTORY,
      useFactory: () => {
        const factory = new SessionFactory({
          serviceName: process.env.SERVICE_NAME,
          productId: process.env.PRODUCT_ID,
          metastore: "dynamodb",
          // ...
        });
        return factory;
      },
    },
    EnvelopeService,
  ],
  exports: [EnvelopeService],
})
export class AsherahModule implements OnModuleDestroy {
  constructor(@Inject(ASHERAH_FACTORY) private factory: SessionFactory) {}

  onModuleDestroy() {
    this.factory.close();
  }
}

@Injectable()
export class EnvelopeService {
  constructor(@Inject(ASHERAH_FACTORY) private factory: SessionFactory) {}

  async protect(partitionId: string, plaintext: string): Promise<string> {
    const session = this.factory.getSession(partitionId);
    try {
      return await session.encryptStringAsync(plaintext);
    } finally {
      session.close();
    }
  }

  async unprotect(partitionId: string, ciphertext: string): Promise<string> {
    const session = this.factory.getSession(partitionId);
    try {
      return await session.decryptStringAsync(ciphertext);
    } finally {
      session.close();
    }
  }
}
```

For DI scenarios where every request resolves a session for a known
partition (e.g. tenant from JWT), wrap the session in a request-scoped
provider:

```typescript
{
  provide: "ASHERAH_SESSION",
  scope: Scope.REQUEST,
  useFactory: (factory: SessionFactory, req: Request) => {
    const tenantId = req.user?.tenantId;
    if (!tenantId) throw new UnauthorizedException();
    return factory.getSession(tenantId);
  },
  inject: [ASHERAH_FACTORY, REQUEST],
}
```

The default session cache means the request-scoped provider doesn't
allocate a new session per request — same session instance is returned
for the same `tenantId` across requests until LRU-evicted.

## Koa

```javascript
import Koa from "koa";
import bodyParser from "koa-bodyparser";
import { SessionFactory } from "asherah";

const app = new Koa();
const factory = new SessionFactory(yourConfig);

app.context.asherah = factory;

app.use(bodyParser());

app.use(async (ctx, next) => {
  if (ctx.path === "/protect" && ctx.method === "POST") {
    const session = ctx.asherah.getSession(ctx.request.body.tenantId);
    try {
      ctx.body = { token: await session.encryptStringAsync(ctx.request.body.payload) };
    } finally {
      session.close();
    }
    return;
  }
  await next();
});

const server = app.listen(3000);

// Graceful shutdown.
process.on("SIGTERM", () => {
  server.close(() => factory.close());
});
```

## AWS Lambda

Lambda's execution model freezes between invocations. Build the
factory **outside** the handler so it survives container reuse:

```javascript
import { SessionFactory } from "asherah";

// Module-level: built once per cold start, reused across invocations.
const factory = new SessionFactory({
  serviceName: process.env.SERVICE_NAME,
  productId: process.env.PRODUCT_ID,
  metastore: "dynamodb",
  dynamoDbTableName: process.env.ASHERAH_TABLE,
  dynamoDbRegion: process.env.AWS_REGION,
  kms: "aws",
  regionMap: JSON.parse(process.env.ASHERAH_REGION_MAP),
  preferredRegion: process.env.AWS_REGION,
});

export const handler = async (event, context) => {
  const session = factory.getSession(event.tenantId);
  try {
    return {
      statusCode: 200,
      body: JSON.stringify({
        token: await session.encryptStringAsync(event.payload),
      }),
    };
  } finally {
    session.close();
  }
};
```

The factory's session cache survives across warm invocations — first
invocation per tenant pays the IK fetch, subsequent ones hit the cache.
For a Lambda handling many tenants, set
`sessionCacheMaxSize` higher than the default 1000 if you can fit it
in memory budget.

Lambda doesn't reliably run shutdown hooks on container freeze; the
factory's resources are released when the Node.js process exits. No
explicit cleanup is required.

## Worker / queue-consumer patterns

For background workers (BullMQ, Bee-Queue, Agenda, custom poller):

```javascript
import { SessionFactory } from "asherah";

const factory = new SessionFactory(yourConfig);

worker.on("completed", () => { /* metrics */ });
worker.on("failed", (job, err) => { /* alert */ });

worker.process(async (job) => {
  const session = factory.getSession(job.data.tenantId);
  try {
    return { token: await session.encryptStringAsync(job.data.payload) };
  } finally {
    session.close();
  }
});

// On shutdown:
process.on("SIGTERM", async () => {
  await worker.close();
  factory.close();
});
```

## Pino / Winston / Bunyan log integration

The static log hook delivers `(level, target, message)` triples. Map
those into your structured logger:

```javascript
import pino from "pino";
import asherah from "asherah";

const log = pino();

asherah.setLogHook((level, target, message) => {
  log[level === "warn" ? "warn" : level === "error" ? "error" : "info"](
    { target }, message);
});
```

The level strings match `pino` and `winston` levels directly
(`trace`/`debug`/`info`/`warn`/`error`). For `bunyan`, map
`"info"` → `info`, `"warn"` → `warn`, etc.

## OpenTelemetry / Prometheus metrics

```javascript
import asherah from "asherah";
import { metrics } from "@opentelemetry/api";

const meter = metrics.getMeter("asherah");
const encryptHist = meter.createHistogram("asherah.encrypt.duration", { unit: "ms" });
const decryptHist = meter.createHistogram("asherah.decrypt.duration", { unit: "ms" });
const cacheHits   = meter.createCounter("asherah.cache.hits");

asherah.setMetricsHook((eventType, durationNs, name) => {
  switch (eventType) {
    case "encrypt": encryptHist.record(durationNs / 1e6); break;
    case "decrypt": decryptHist.record(durationNs / 1e6); break;
    case "cache_hit": cacheHits.add(1, { cache: name }); break;
    // store/load/cache_miss/cache_stale similarly
  }
});
```
