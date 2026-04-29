# AWS production setup

End-to-end walkthrough for a production deployment using **AWS KMS**
for the master key and **DynamoDB** for the metastore.

## Prerequisites

1. An AWS account with permission to create KMS keys, DynamoDB tables,
   and IAM policies.
2. A way to deliver AWS credentials to your Python process — IAM role
   for ECS/EKS/EC2, AWS SSO profile (`aws sso login`) for development,
   or environment variables (`AWS_ACCESS_KEY_ID` /
   `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`) for CI. **Asherah
   does not load credentials itself** — the AWS SDK for Rust (running
   in the native core) reads from the standard credential chain.
   `boto3` config is not consulted.

## Step 1: create KMS keys

One symmetric KMS key per region. The key encrypts Asherah's
per-product *system keys* — Asherah does not pass user data to KMS.

```bash
aws kms create-key \
    --region us-east-1 \
    --description "Asherah system-key encryption" \
    --tags TagKey=Application,TagValue=asherah \
    --query 'KeyMetadata.{Arn:Arn,KeyId:KeyId}'
```

Repeat for each region in `RegionMap`. Record the ARNs.

## Step 2: create the DynamoDB metastore table

Schema is fixed: partition key `Id` (string), sort key `Created`
(number).

```bash
aws dynamodb create-table \
    --region us-east-1 \
    --table-name AsherahKeys \
    --attribute-definitions \
        AttributeName=Id,AttributeType=S \
        AttributeName=Created,AttributeType=N \
    --key-schema \
        AttributeName=Id,KeyType=HASH \
        AttributeName=Created,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --tags Key=Application,Value=asherah
```

For multi-region, enable [DynamoDB global
tables](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GlobalTables.html).

## Step 3: IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AsherahKms",
      "Effect": "Allow",
      "Action": ["kms:Encrypt", "kms:Decrypt"],
      "Resource": [
        "arn:aws:kms:us-east-1:111111111111:key/abc-123",
        "arn:aws:kms:us-west-2:111111111111:key/def-456"
      ]
    },
    {
      "Sid": "AsherahMetastore",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem"],
      "Resource": "arn:aws:dynamodb:us-east-1:111111111111:table/AsherahKeys"
    }
  ]
}
```

Attach to the IAM role/user the application runs as. Asherah doesn't
use `kms:GenerateDataKey`.

## Step 4: configure Asherah

```python
import json, os, asherah

config = {
    "ServiceName": "payments",                   # your service identifier
    "ProductID": "checkout",                      # your product identifier within the service
    "Metastore": "dynamodb",
    "DynamoDBTableName": "AsherahKeys",
    "DynamoDBRegion": "us-east-1",
    "KMS": "aws",
    "RegionMap": {
        "us-east-1": "arn:aws:kms:us-east-1:111111111111:key/abc-123",
        "us-west-2": "arn:aws:kms:us-west-2:111111111111:key/def-456",
    },
    "PreferredRegion": "us-east-1",              # KMS key for new envelope keys
    "EnableSessionCaching": True,
    "ExpireAfter": 90 * 24 * 60 * 60,            # IK rotation cadence (seconds)
    "CheckInterval": 60 * 60,                     # revoke-check interval (seconds)
}

factory = asherah.SessionFactory.from_config(config)
```

`ServiceName` and `ProductID` form the prefix for generated
intermediate-key IDs. Pick stable identifiers — changing them later
makes existing envelope keys un-decryptable.

## Step 5: hook observability

```python
import logging
import asherah
from opentelemetry import metrics

log = logging.getLogger("asherah")
LEVELS = {"trace": logging.DEBUG, "debug": logging.DEBUG,
          "info": logging.INFO, "warn": logging.WARNING, "error": logging.ERROR}

def on_log(event):
    log.log(LEVELS.get(event["level"], logging.INFO),
            "%s: %s", event["target"], event["message"])

asherah.set_log_hook(on_log)

meter = metrics.get_meter("asherah")
encrypt_hist = meter.create_histogram("asherah.encrypt.duration", unit="ms")
decrypt_hist = meter.create_histogram("asherah.decrypt.duration", unit="ms")
cache_hit = meter.create_counter("asherah.cache.hits")

def on_metric(event):
    t = event["type"]
    if t == "encrypt":      encrypt_hist.record(event["duration_ns"] / 1e6)
    elif t == "decrypt":    decrypt_hist.record(event["duration_ns"] / 1e6)
    elif t == "cache_hit":  cache_hit.add(1, {"cache": event.get("name") or ""})

asherah.set_metrics_hook(on_metric)
```

## Step 6: smoke-test verification

The first encrypt produces:
- A row in `AsherahKeys` with `Id="_SK_payments"`.
- A row in `AsherahKeys` with `Id="_IK_<partition>_payments_checkout"`.
- A log event at `info` level reporting IK creation.

Subsequent encrypts in the same partition reuse the cached IK — no
metastore round-trip — until expiry.

## Region routing details

| Setting | What it controls |
|---|---|
| `DynamoDBRegion` | Endpoint region for DynamoDB (`dynamodb.<region>.amazonaws.com`). |
| `DynamoDBSigningRegion` | SigV4 signing region. Defaults to endpoint region. |
| `PreferredRegion` | Which entry of `RegionMap` AWS KMS uses to encrypt *new* envelope keys. Existing envelope keys from any region in the map are still decryptable. |

In a single-region deployment all three are equal. In multi-region
active/passive, all three on the active side are the active region;
the passive side switches `DynamoDBRegion` to its region but may keep
`PreferredRegion` on the active KMS key until promotion.

## Common production pitfalls

- **`EnableRegionSuffix: True`** is required when using DynamoDB
  global tables and a multi-region `RegionMap` — otherwise IK IDs
  collide across regions. The suffix disambiguates
  (`_IK_..._us-east-1`).
- **Setting `STATIC_MASTER_KEY_HEX` in production.** It's accepted but
  it's the static-KMS test mode. Production must use `KMS: "aws"`.
- **IAM role missing `kms:Encrypt`.** Encrypt is needed only for
  system-key creation (rare). First IK rotation surfaces the missing
  permission if your app started with the SK already cached.
- **Native binary not loading on Alpine / musl.** pip's manylinux/musllinux
  wheel discovery should pick `linux-musl-x86_64` /
  `linux-musl-aarch64` automatically. If you see "no module named
  asherah._native" after install, rerun
  `pip install --force-reinstall --no-cache-dir asherah`.
- **Lambda cold-start cost.** Build the factory at module level (not
  inside the handler) so warm invocations don't repay setup cost.
- **`asyncio.run` per request.** Don't construct the factory inside an
  `asyncio.run()` block called per request — `asyncio.run` creates and
  destroys a new event loop, and the factory holds tokio resources
  that don't reattach cleanly.
