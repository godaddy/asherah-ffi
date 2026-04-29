# Framework integration

How to wire Asherah into common Python web frameworks and runtimes.
The pattern is consistent: **build a `SessionFactory` at startup, use
session context-managers per operation, close the factory on graceful
shutdown.**

## FastAPI

FastAPI's lifespan context is the right place for factory setup:

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException
import asherah

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    factory = asherah.SessionFactory.from_config({
        "ServiceName": "payments",
        "ProductID": "checkout",
        "Metastore": "dynamodb",
        "DynamoDBTableName": "AsherahKeys",
        "DynamoDBRegion": "us-east-1",
        "KMS": "aws",
        "RegionMap": json.loads(os.environ["ASHERAH_REGION_MAP"]),
        "PreferredRegion": "us-east-1",
    })

    # Hook Asherah's log records into your structured logger.
    asherah.set_log_hook(forward_log)
    asherah.set_metrics_hook(forward_metric)

    app.state.asherah = factory
    try:
        yield
    finally:
        factory.close()
        asherah.set_log_hook(None)
        asherah.set_metrics_hook(None)

app = FastAPI(lifespan=lifespan)

def get_session(tenant_id: str = Header(alias="X-Tenant-Id")):
    """Per-request dependency that resolves a session for the tenant."""
    factory: asherah.SessionFactory = app.state.asherah
    session = factory.get_session(tenant_id)
    try:
        yield session
    finally:
        session.close()

@app.post("/protect")
async def protect(payload: dict, session = Depends(get_session)):
    return {"token": await session.encrypt_text_async(payload["plaintext"])}

@app.post("/unprotect")
async def unprotect(payload: dict, session = Depends(get_session)):
    return {"plaintext": await session.decrypt_text_async(payload["token"])}
```

The `Depends(get_session)` pattern returns a session *from the
factory's cache* — same instance for the same tenant across requests,
LRU-evicted by the factory's session cache. The
`yield`/`finally`/`close()` returns it to the cache cleanly.

## Flask

```python
from flask import Flask, request, g, jsonify
import asherah

app = Flask(__name__)

def get_factory():
    if "asherah_factory" not in app.config:
        app.config["asherah_factory"] = asherah.SessionFactory.from_config({
            "ServiceName": "my-service",
            "ProductID": "my-product",
            # ... rest of config ...
        })
    return app.config["asherah_factory"]

@app.before_request
def attach_session():
    factory = get_factory()
    g.session = factory.get_session(request.headers["X-Tenant-Id"])

@app.teardown_request
def release_session(exc):
    if hasattr(g, "session"):
        g.session.close()

@app.post("/protect")
def protect():
    return jsonify(token=g.session.encrypt_text(request.json["plaintext"]))

# Graceful shutdown — Flask doesn't have a teardown_app hook, register
# atexit instead:
import atexit
atexit.register(lambda: app.config.get("asherah_factory") and app.config["asherah_factory"].close())
```

## Django

For Django, add a startup hook in your AppConfig and use
request-scoped middleware to attach the session:

```python
# myapp/apps.py
from django.apps import AppConfig
import asherah

class MyAppConfig(AppConfig):
    name = "myapp"
    factory: asherah.SessionFactory | None = None

    def ready(self):
        from django.conf import settings
        MyAppConfig.factory = asherah.SessionFactory.from_config(settings.ASHERAH_CONFIG)
        asherah.set_log_hook(forward_to_django_log)
```

```python
# myapp/middleware.py
from django.utils.deprecation import MiddlewareMixin
from .apps import MyAppConfig

class AsherahSessionMiddleware(MiddlewareMixin):
    def process_request(self, request):
        tenant_id = request.headers.get("X-Tenant-Id")
        if tenant_id:
            request.asherah_session = MyAppConfig.factory.get_session(tenant_id)

    def process_response(self, request, response):
        if hasattr(request, "asherah_session"):
            request.asherah_session.close()
        return response
```

Add `'myapp.middleware.AsherahSessionMiddleware'` to `MIDDLEWARE` in
settings, then in views: `request.asherah_session.encrypt_text(...)`.

## AWS Lambda

Build the factory at module level so it survives container reuse:

```python
import os, json, asherah

# Module-level: built once per cold start, reused across warm invocations.
_factory = asherah.SessionFactory.from_config({
    "ServiceName": os.environ["SERVICE_NAME"],
    "ProductID": os.environ["PRODUCT_ID"],
    "Metastore": "dynamodb",
    "DynamoDBTableName": os.environ["ASHERAH_TABLE"],
    "DynamoDBRegion": os.environ["AWS_REGION"],
    "KMS": "aws",
    "RegionMap": json.loads(os.environ["ASHERAH_REGION_MAP"]),
    "PreferredRegion": os.environ["AWS_REGION"],
})

def lambda_handler(event, context):
    with _factory.get_session(event["tenantId"]) as session:
        return {
            "statusCode": 200,
            "body": json.dumps({"token": session.encrypt_text(event["payload"])}),
        }
```

Lambda doesn't reliably run shutdown hooks on container freeze — the
factory's resources are released when the Python process exits. No
explicit cleanup required.

## Celery worker

```python
# celery_app.py
from celery import Celery
from celery.signals import worker_init, worker_shutdown
import asherah

app = Celery("worker", broker="redis://localhost")
_factory = None

@worker_init.connect
def init_asherah(sender, **kwargs):
    global _factory
    _factory = asherah.SessionFactory.from_config(your_config)
    asherah.set_log_hook(forward_log)

@worker_shutdown.connect
def close_asherah(sender, **kwargs):
    global _factory
    if _factory:
        _factory.close()

@app.task
def protect_payload(tenant_id: str, plaintext: str) -> str:
    with _factory.get_session(tenant_id) as session:
        return session.encrypt_text(plaintext)
```

Use the sync `encrypt_text` (not the async variant) inside Celery
tasks — Celery worker pools are typically threaded or process-based,
not asyncio.

## Logging integration (stdlib `logging`)

```python
import logging
import asherah

log = logging.getLogger("asherah")

LEVELS = {"trace": logging.DEBUG, "debug": logging.DEBUG,
          "info": logging.INFO, "warn": logging.WARNING, "error": logging.ERROR}

def forward_log(event):
    log.log(LEVELS.get(event["level"], logging.INFO),
            "%s: %s", event["target"], event["message"])

asherah.set_log_hook(forward_log)
```

## OpenTelemetry / Prometheus metrics

```python
from opentelemetry import metrics
import asherah

meter = metrics.get_meter("asherah")
encrypt_hist = meter.create_histogram("asherah.encrypt.duration", unit="ms")
decrypt_hist = meter.create_histogram("asherah.decrypt.duration", unit="ms")
cache_hit = meter.create_counter("asherah.cache.hits")
cache_miss = meter.create_counter("asherah.cache.misses")

def forward_metric(event):
    t = event["type"]
    if t == "encrypt":  encrypt_hist.record(event["duration_ns"] / 1e6)
    elif t == "decrypt": decrypt_hist.record(event["duration_ns"] / 1e6)
    elif t == "cache_hit":  cache_hit.add(1, {"cache": event.get("name") or ""})
    elif t == "cache_miss": cache_miss.add(1, {"cache": event.get("name") or ""})
    # store/load/cache_stale similarly

asherah.set_metrics_hook(forward_metric)
```

For Prometheus's `prometheus_client`, the integration is the same
shape — create instruments at module level, increment in the hook
callback.
